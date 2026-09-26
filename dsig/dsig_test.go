package dsig_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xml/xdmbuild"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

func newKey(t *testing.T, signer crypto.Signer) xmlsec.KeyProvider {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<32, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return xmlsec.KeyProvider{Signer: signer, Certificate: cert}
}

var rsaKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

func parse(t *testing.T, b []byte) *xdm.Node {
	t.Helper()
	tree, err := xmlsec.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return tree.Root
}

func findSignature(doc *xdm.Node) *xdm.Node {
	var sig *xdm.Node
	xmltree.Walk(doc, func(e *xdm.Node) {
		if sig == nil && e.IsElement(xmlsec.NSDSig, "Signature") {
			sig = e
		}
	})
	return sig
}

func serialize(t *testing.T, doc *xdm.Node) []byte {
	t.Helper()
	b, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --- WS-Security detached signature ----------------------------------------

const envelope = `<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="urn:example:eb">` +
	`<S:Header><eb:Messaging><eb:MessageId>m1</eb:MessageId></eb:Messaging></S:Header>` +
	`<S:Body><p:Payload xmlns:p="urn:example:p">hello</p:Payload></S:Body></S:Envelope>`

var excC14N = []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}

var as4Allow = dsig.VerifyOptions{
	AllowedSignatureAlgorithms:        []string{xmlsec.SigRSASHA256},
	AllowedDigestAlgorithms:           []string{xmlsec.DigestSHA256},
	AllowedCanonicalizationAlgorithms: []string{string(c14n.Exclusive10)},
}

func attachments(t *testing.T, body string) xmlsec.AttachmentSet {
	t.Helper()
	s, err := xmlsec.NewAttachmentSet(&xmlsec.Attachment{ID: "att-1@example.com", Body: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// signAS4 returns a signed envelope and the wsu:Ids of Messaging and Body.
func signAS4(t *testing.T, key xmlsec.KeyProvider) (signed []byte, msgID, bodyID string) {
	t.Helper()
	doc := parse(t, []byte(envelope))
	env := xmltree.DocumentElement(doc)
	msg, body := env.ChildElements()[0].ChildElements()[0], env.ChildElements()[1]

	var err error
	if msgID, err = wss.AssignID(doc, msg); err != nil {
		t.Fatal(err)
	}
	if bodyID, err = wss.AssignID(doc, body); err != nil {
		t.Fatal(err)
	}
	hdr, err := wss.NewHeader(doc, xmlsec.NSSOAP12, "", true)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := hdr.AddBinarySecurityToken(key.Certificate, nil, xmlsec.BSTValueTypeX509v3)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := dsig.Sign(doc, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{
			{URI: "#" + msgID, Transforms: excC14N, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "#" + bodyID, Transforms: excC14N, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "cid:att-1@example.com", DigestAlgorithm: xmlsec.DigestSHA256,
				Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformAttachmentContentSignature}}},
		},
		KeyInfo:         dsig.KeyInfoSecurityTokenReference,
		SecurityTokenID: tok,
		Attachments:     attachments(t, "payload"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := hdr.Append(sig); err != nil {
		t.Fatal(err)
	}
	return serialize(t, doc), msgID, bodyID
}

func verifyAS4(t *testing.T, signed []byte, att string) (*dsig.Coverage, error) {
	t.Helper()
	doc := parse(t, signed)
	opts := as4Allow
	opts.Attachments = attachments(t, att)
	return dsig.Verify(doc, findSignature(doc), opts)
}

func TestConformance_AP_05_AS4SignatureAlgorithms(t *testing.T) {
	signed, _, _ := signAS4(t, newKey(t, rsaKey))
	if _, err := verifyAS4(t, signed, "payload"); err != nil {
		t.Fatal(err)
	}
	for _, alg := range []string{string(c14n.Exclusive10), xmlsec.SigRSASHA256, xmlsec.DigestSHA256} {
		if !strings.Contains(string(signed), `Algorithm="`+alg+`"`) {
			t.Errorf("signature does not name %s", alg)
		}
	}
}

func TestConformance_AP_08_BinarySecurityToken(t *testing.T) {
	key := newKey(t, rsaKey)
	signed, _, _ := signAS4(t, key)
	cov, err := verifyAS4(t, signed, "payload")
	if err != nil {
		t.Fatal(err)
	}
	if cov.KeyInfoForm != dsig.KeyInfoSecurityTokenReference || !cov.Certificate.Equal(key.Certificate) {
		t.Fatalf("key info form %d, certificate match %v", cov.KeyInfoForm, cov.Certificate.Equal(key.Certificate))
	}
}

func TestConformance_AP_09_SwAAttachmentSigning(t *testing.T) {
	signed, _, _ := signAS4(t, newKey(t, rsaKey))
	if _, err := verifyAS4(t, signed, "payloaD"); !errors.Is(err, xmlsec.ErrDigestMismatch) {
		t.Fatalf("modified attachment: got %v", err)
	}
}

func TestConformance_AP_10_SignatureCoverage(t *testing.T) {
	signed, msgID, bodyID := signAS4(t, newKey(t, rsaKey))
	cov, err := verifyAS4(t, signed, "payload")
	if err != nil {
		t.Fatal(err)
	}
	if !cov.Covers(msgID, bodyID) || !cov.CoversAttachments("att-1@example.com") || cov.WholeDocumentSigned {
		t.Fatalf("coverage %+v", cov)
	}
	if len(cov.References) != 3 || !strings.HasPrefix(string(cov.References[0].Raw), "<ds:Reference") {
		t.Fatalf("references %+v", cov.References)
	}

	// Wrapping: move the signed Body into the header and put an unsigned
	// one in its place. The signature still verifies, over the relocated
	// original; Coverage is what exposes it.
	wrapped := strings.Replace(string(signed), "<S:Body", "<S:Body><p:Payload xmlns:p=\"urn:example:p\">evil</p:Payload></S:Body><S:Wrapper><S:Body", 1)
	wrapped = strings.Replace(wrapped, "</S:Body></S:Envelope>", "</S:Body></S:Wrapper></S:Envelope>", 1)
	doc := parse(t, []byte(wrapped))
	opts := as4Allow
	opts.Attachments = attachments(t, "payload")
	cov, err = dsig.Verify(doc, findSignature(doc), opts)
	if err != nil {
		t.Fatal(err)
	}
	realBody := xmltree.DocumentElement(doc).ChildElements()[1]
	if cov.SignedElements[1] == realBody {
		t.Fatal("coverage claims the unsigned body is signed")
	}
}

func TestVerifyNegative(t *testing.T) {
	signed, _, bodyID := signAS4(t, newKey(t, rsaKey))
	s := string(signed)
	cases := []struct {
		name string
		doc  string
		opts func(*dsig.VerifyOptions)
		want error
	}{
		{"modified element", strings.Replace(s, ">hello<", ">HELLO<", 1), nil, xmlsec.ErrDigestMismatch},
		{"duplicate wsu:Id", strings.Replace(s, "</eb:Messaging>",
			`</eb:Messaging><x wsu:Id="`+bodyID+`" xmlns:wsu="`+xmlsec.NSWSU+`"/>`, 1), nil, xmlsec.ErrAmbiguousID},
		{"algorithm outside allow-list", s, func(o *dsig.VerifyOptions) {
			o.AllowedDigestAlgorithms = []string{xmlsec.DigestSHA512}
		}, xmlsec.ErrAlgorithmNotAllowed},
		{"truncated signature value", truncateSignatureValue(s), nil, xmlsec.ErrSignatureInvalid},
		{"reference limit", s, func(o *dsig.VerifyOptions) { o.MaxReferences = 2 }, xmlsec.ErrLimitExceeded},
		{"wrong certificate", s, func(o *dsig.VerifyOptions) {
			k, _ := rsa.GenerateKey(rand.Reader, 2048)
			o.Certificate = newKey(t, k).Certificate
		}, xmlsec.ErrSignatureInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse(t, []byte(c.doc))
			opts := as4Allow
			opts.Attachments = attachments(t, "payload")
			if c.opts != nil {
				c.opts(&opts)
			}
			if _, err := dsig.Verify(doc, findSignature(doc), opts); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func truncateSignatureValue(s string) string {
	i := strings.Index(s, "</ds:SignatureValue>")
	return s[:i-8] + s[i:]
}

// --- Enveloped signature -----------------------------------------------------

const metadata = `<smp:SignedServiceMetadata xmlns:smp="urn:example:smp" xmlns:unused="urn:example:unused">` +
	`<smp:ServiceMetadata><smp:Endpoint>https://example.com/</smp:Endpoint></smp:ServiceMetadata>` +
	`<!-- comment --></smp:SignedServiceMetadata>`

func signEnveloped(t *testing.T, key xmlsec.KeyProvider, sigAlg, digestAlg string) []byte {
	t.Helper()
	doc := parse(t, []byte(metadata))
	signed, err := dsig.SignEnveloped(doc, key, dsig.SignOptions{
		SignatureAlgorithm:        sigAlg,
		CanonicalizationAlgorithm: string(c14n.Inclusive10),
		References: []dsig.Reference{{
			URI:             "",
			DigestAlgorithm: digestAlg,
			Transforms: []dsig.TransformSpec{
				{Algorithm: xmlsec.TransformEnvelopedSignature},
				{Algorithm: string(c14n.Inclusive10)},
			},
		}},
		KeyInfo: dsig.KeyInfoX509Data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if findSignature(doc) != nil {
		t.Fatal("SignEnveloped modified its input")
	}
	return signed
}

func TestConformance_S_03_SMPEnvelopedSignature(t *testing.T) {
	signed := signEnveloped(t, newKey(t, rsaKey), xmlsec.SigRSASHA256, xmlsec.DigestSHA256)
	doc := parse(t, signed)
	sig := findSignature(doc)
	if sig.Parent != xmltree.DocumentElement(doc) || sig != xmltree.DocumentElement(doc).ChildElements()[1] {
		t.Fatal("signature is not the last child element of the document element")
	}
	cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{
		AllowedCanonicalizationAlgorithms: []string{string(c14n.Inclusive10)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cov.WholeDocumentSigned {
		t.Fatal("whole document not reported as signed")
	}
	if _, err := dsig.Verify(parse(t, []byte(strings.Replace(string(signed), "example.com", "evil.com", 1))), nil, dsig.VerifyOptions{}); err == nil {
		t.Fatal("nil signature accepted")
	}
	tampered := parse(t, []byte(strings.Replace(string(signed), "example.com", "evil.com", 1)))
	if _, err := dsig.Verify(tampered, findSignature(tampered), dsig.VerifyOptions{}); !errors.Is(err, xmlsec.ErrDigestMismatch) {
		t.Fatalf("tampered: got %v", err)
	}
}

func TestConformance_S_04_KeyInfoX509Data(t *testing.T) {
	key := newKey(t, rsaKey)
	doc := parse(t, signEnveloped(t, key, xmlsec.SigRSASHA256, xmlsec.DigestSHA256))
	cov, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if cov.KeyInfoForm != dsig.KeyInfoX509Data || !cov.Certificate.Equal(key.Certificate) {
		t.Fatalf("form %d", cov.KeyInfoForm)
	}
}

// SignedInfo must be canonicalized over the live tree. Under inclusive
// canonicalization the in-scope xmlns:unused makes a detached copy
// canonicalize differently, so extracting it first would break verification.
func TestSignedInfoCanonicalizedInPlace(t *testing.T) {
	doc := parse(t, signEnveloped(t, newKey(t, rsaKey), xmlsec.SigRSASHA256, xmlsec.DigestSHA256))
	si := findSignature(doc).ChildElements()[0]
	opts := c14n.Options{Algorithm: c14n.Inclusive10}
	live, err := c14n.Bytes(si, opts)
	if err != nil {
		t.Fatal(err)
	}
	detached, err := c14n.Bytes(xdmbuild.DeepCopy(si), opts)
	if err != nil {
		t.Fatal(err)
	}
	if string(live) == string(detached) {
		t.Fatal("fixture does not distinguish in-place from extracted canonicalization")
	}
	if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestAlgorithms(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	cases := []struct {
		signer crypto.Signer
		sig    string
		digest string
	}{
		{rsaKey, xmlsec.SigRSASHA256, xmlsec.DigestSHA256},
		{rsaKey, xmlsec.SigRSASHA384, xmlsec.DigestSHA384},
		{rsaKey, xmlsec.SigRSASHA512, xmlsec.DigestSHA512},
		{p256, xmlsec.SigECDSASHA256, xmlsec.DigestSHA256},
		{p384, xmlsec.SigECDSASHA384, xmlsec.DigestSHA384},
		{p521, xmlsec.SigECDSASHA512, xmlsec.DigestSHA512},
	}
	for _, c := range cases {
		t.Run(c.sig, func(t *testing.T) {
			doc := parse(t, signEnveloped(t, newKey(t, c.signer), c.sig, c.digest))
			if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{
				AllowedSignatureAlgorithms: []string{c.sig},
				AllowedDigestAlgorithms:    []string{c.digest},
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUnverifiable(t *testing.T) {
	signed := string(signEnveloped(t, newKey(t, rsaKey), xmlsec.SigRSASHA256, xmlsec.DigestSHA256))
	as4, _, _ := signAS4(t, newKey(t, rsaKey))
	if !strings.Contains(string(as4), `<ds:SignatureMethod `) {
		t.Fatal("fixture: no ds:SignatureMethod to rewrite")
	}
	cases := map[string]struct {
		doc   string
		cause error
	}{
		"xml 1.1":         {`<?xml version="1.1"?>` + signed, c14n.ErrXML11},
		"relative ns URI": {strings.Replace(signed, `xmlns:smp=`, `xmlns:rel="relative/uri" xmlns:smp=`, 1), c14n.ErrRelativeNamespaceURI},
		// Declared on ds:SignatureMethod, a sibling of the references: in
		// SignedInfo's canonical form, never in scope for any Reference, so
		// SignedInfo's canonicalization catches it rather than Coverage.Raw's.
		"relative ns URI outside every Reference": {strings.Replace(string(as4), `<ds:SignatureMethod `,
			`<ds:SignatureMethod xmlns:rel="relative/uri" rel:x="1" `, 1), c14n.ErrRelativeNamespaceURI},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			doc := parse(t, []byte(c.doc))
			_, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{})
			if !errors.Is(err, xmlsec.ErrUnverifiable) || !errors.Is(err, c.cause) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestSignRefusals(t *testing.T) {
	key := newKey(t, rsaKey)
	doc := parse(t, []byte(metadata))
	base := dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
	}
	ref := func(algs ...string) []dsig.Reference {
		var ts []dsig.TransformSpec
		for _, a := range algs {
			ts = append(ts, dsig.TransformSpec{Algorithm: a})
		}
		return []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: ts}}
	}
	cases := []struct {
		name string
		mod  func(*dsig.SignOptions)
		want error
	}{
		{"xslt without a stylesheet", func(o *dsig.SignOptions) {
			o.References = ref(xmlsec.TransformEnvelopedSignature, xmlsec.TransformXSLT)
		}, xmlsec.ErrMalformed},
		{"xpath without an expression", func(o *dsig.SignOptions) {
			o.References = ref(xmlsec.TransformEnvelopedSignature, xmlsec.TransformXPath)
		}, xmlsec.ErrMalformed},
		{"no final canonicalization", func(o *dsig.SignOptions) {
			o.References = ref(xmlsec.TransformEnvelopedSignature)
		}, xmlsec.ErrMalformed},
		{"whole document without enveloped", func(o *dsig.SignOptions) {
			o.References = ref(string(c14n.Exclusive10))
		}, xmlsec.ErrMalformed},
		// The legacy algorithms are verification-only.
		{"rsa-sha1", func(o *dsig.SignOptions) { o.SignatureAlgorithm = xmlsec.SigRSASHA1 }, xmlsec.ErrUnsupportedAlgorithm},
		{"dsa-sha1", func(o *dsig.SignOptions) { o.SignatureAlgorithm = xmlsec.SigDSASHA1 }, xmlsec.ErrUnsupportedAlgorithm},
		{"hmac-sha1", func(o *dsig.SignOptions) { o.SignatureAlgorithm = xmlsec.SigHMACSHA1 }, xmlsec.ErrUnsupportedAlgorithm},
		{"hmac-sha256", func(o *dsig.SignOptions) { o.SignatureAlgorithm = xmlsec.SigHMACSHA256 }, xmlsec.ErrUnsupportedAlgorithm},
		{"hmac-sha384", func(o *dsig.SignOptions) { o.SignatureAlgorithm = xmlsec.SigHMACSHA384 }, xmlsec.ErrUnsupportedAlgorithm},
		{"hmac-sha512", func(o *dsig.SignOptions) { o.SignatureAlgorithm = xmlsec.SigHMACSHA512 }, xmlsec.ErrUnsupportedAlgorithm},
		{"sha1 digest", func(o *dsig.SignOptions) { o.References[0].DigestAlgorithm = xmlsec.DigestSHA1 }, xmlsec.ErrUnsupportedAlgorithm},
		{"unknown signature", func(o *dsig.SignOptions) { o.SignatureAlgorithm = "urn:x" }, xmlsec.ErrUnsupportedAlgorithm},
		{"inclusive SignedInfo on a detached signature", func(o *dsig.SignOptions) {
			o.CanonicalizationAlgorithm = string(c14n.Inclusive10)
		}, xmlsec.ErrUnsupportedAlgorithm},
	}
	legacy := map[string]bool{"rsa-sha1": true, "dsa-sha1": true, "hmac-sha1": true, "hmac-sha256": true,
		"hmac-sha384": true, "hmac-sha512": true, "sha1 digest": true}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := base
			opts.References = ref(xmlsec.TransformEnvelopedSignature, string(c14n.Exclusive10))
			c.mod(&opts)
			_, err := dsig.Sign(doc, key, opts)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if !legacy[c.name] {
				return
			}
			if !strings.Contains(err.Error(), "verification only") {
				t.Fatalf("error does not say verification only: %v", err)
			}
			if _, err := dsig.SignEnveloped(doc, key, opts); !errors.Is(err, c.want) {
				t.Fatalf("SignEnveloped: got %v, want %v", err, c.want)
			}
		})
	}
}
