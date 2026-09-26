package dsig_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

// covSigner replaces the Sign method of a real signer.
type covSigner struct {
	crypto.Signer
	out []byte
	err error
}

// covOpaqueSigner's public key has no Equal method.
type covOpaqueSigner struct{ crypto.Signer }

// covTokenDoc is the SOAP envelope with a BST for cert, returning the
// document, the token's wsu:Id and the Body's wsu:Id.
func covTokenDoc(t *testing.T, key xmlsec.KeyProvider) (doc *xdm.Node, tokID, bodyID string) {
	t.Helper()
	doc = parse(t, []byte(envelope))
	body := xmltree.DocumentElement(doc).ChildElements()[1]
	var err error
	if bodyID, err = wss.AssignID(doc, body); err != nil {
		t.Fatal(err)
	}
	hdr, err := wss.NewHeader(doc, wss.NSSOAP12, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if tokID, err = hdr.AddBinarySecurityToken(key.Certificate, nil, xmlsec.BSTValueTypeX509v3); err != nil {
		t.Fatal(err)
	}
	return doc, tokID, bodyID
}

func TestSignErrors(t *testing.T) {
	key := newKey(t, rsaKey)
	ecKey := newKey(t, covECKey)
	otherRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherKey := newKey(t, otherRSA)
	doc, tokID, bodyID := covTokenDoc(t, otherKey)
	body := "#" + bodyID
	atts := attachments(t, "!!not base64")

	ref := func(uri string, algs ...string) []dsig.Reference {
		var ts []dsig.TransformSpec
		for _, a := range algs {
			ts = append(ts, dsig.TransformSpec{Algorithm: a})
		}
		return []dsig.Reference{{URI: uri, DigestAlgorithm: xmlsec.DigestSHA256, Transforms: ts}}
	}
	cases := []struct {
		name string
		key  xmlsec.KeyProvider
		mod  func(*dsig.SignOptions)
		want error // nil: any error
	}{
		{"nil Signer", xmlsec.KeyProvider{Certificate: key.Certificate}, nil, nil},
		{"nil Certificate", xmlsec.KeyProvider{Signer: rsaKey}, nil, nil},
		{"Signer does not match Certificate", xmlsec.KeyProvider{Signer: rsaKey, Certificate: otherKey.Certificate}, nil, nil},
		{"Signer public key without Equal", xmlsec.KeyProvider{Signer: covOpaqueSigner{rsaKey}, Certificate: key.Certificate}, nil, nil},
		{"no references", key, func(o *dsig.SignOptions) { o.References = nil }, nil},
		{"unknown digest", key, func(o *dsig.SignOptions) { o.References[0].DigestAlgorithm = "urn:x" }, xmlsec.ErrUnsupportedAlgorithm},
		{"sha1 digest", key, func(o *dsig.SignOptions) {
			o.References[0].DigestAlgorithm = "http://www.w3.org/2000/09/xmldsig#sha1"
		}, xmlsec.ErrUnsupportedAlgorithm},
		{"unknown KeyInfoSpec", key, func(o *dsig.SignOptions) { o.KeyInfo = dsig.KeyInfoSpec(99) }, nil},
		{"SecurityTokenID missing", key, func(o *dsig.SignOptions) {
			o.KeyInfo, o.SecurityTokenID = dsig.KeyInfoSecurityTokenReference, "nope"
		}, xmlsec.ErrIDNotFound},
		{"SecurityTokenID empty", key, func(o *dsig.SignOptions) { o.KeyInfo = dsig.KeyInfoSecurityTokenReference }, xmlsec.ErrIDNotFound},
		{"SecurityTokenID not a BST", key, func(o *dsig.SignOptions) {
			o.KeyInfo, o.SecurityTokenID = dsig.KeyInfoSecurityTokenReference, bodyID
		}, xmlsec.ErrUnsupportedKeyInfo},
		{"BST carries a different certificate", key, func(o *dsig.SignOptions) {
			o.KeyInfo, o.SecurityTokenID = dsig.KeyInfoSecurityTokenReference, tokID
		}, nil},
		{"cid: without attachments", key, func(o *dsig.SignOptions) {
			o.References = ref("cid:att-1@example.com", xmlsec.TransformAttachmentContentOnly)
			o.Attachments = nil
		}, xmlsec.ErrAttachmentNotFound},
		{"cid: not in the set", key, func(o *dsig.SignOptions) {
			o.References = ref("cid:other@example.com", xmlsec.TransformAttachmentContentOnly)
		}, xmlsec.ErrAttachmentNotFound},
		{"http URI", key, func(o *dsig.SignOptions) { o.References = ref("http://example.com/", covExc) }, xmlsec.ErrMalformed},
		{"relative URI", key, func(o *dsig.SignOptions) { o.References = ref("other.xml", covExc) }, xmlsec.ErrMalformed},
		{"#id not found", key, func(o *dsig.SignOptions) { o.References = ref("#nope", covExc) }, xmlsec.ErrIDNotFound},
		{"#id without transforms", key, func(o *dsig.SignOptions) { o.References = ref(body) }, xmlsec.ErrMalformed},
		{"too many transforms", key, func(o *dsig.SignOptions) {
			algs := slices.Repeat([]string{xmlsec.TransformEnvelopedSignature}, dsig.MaxTransformsPerReference)
			o.References = ref(body, append(algs, covExc)...)
		}, xmlsec.ErrLimitExceeded},
		{"enveloped on an attachment", key, func(o *dsig.SignOptions) {
			o.References = ref("cid:att-1@example.com", xmlsec.TransformEnvelopedSignature)
		}, xmlsec.ErrMalformed},
		{"canonicalization of an attachment", key, func(o *dsig.SignOptions) {
			o.References = ref("cid:att-1@example.com", covExc)
		}, xmlsec.ErrMalformed},
		{"canonicalization twice", key, func(o *dsig.SignOptions) { o.References = ref(body, covExc, covExc) }, xmlsec.ErrMalformed},
		{"base64 of a node set", key, func(o *dsig.SignOptions) { o.References = ref(body, xmlsec.TransformBase64) }, xmlsec.ErrMalformed},
		{"base64 of non-base64 octets", key, func(o *dsig.SignOptions) {
			o.References = ref("cid:att-1@example.com", xmlsec.TransformBase64)
		}, xmlsec.ErrMalformed},
		{"Attachment-Content-Only on an element", key, func(o *dsig.SignOptions) {
			o.References = ref(body, xmlsec.TransformAttachmentContentOnly)
		}, xmlsec.ErrMalformed},
		{"Attachment-Content-Only after canonicalization", key, func(o *dsig.SignOptions) {
			o.References = ref(body, covExc, xmlsec.TransformAttachmentContentOnly)
		}, xmlsec.ErrMalformed},
		{"Attachment-Complete", key, func(o *dsig.SignOptions) {
			o.References = ref("cid:att-1@example.com", xmlsec.TransformAttachmentComplete)
		}, xmlsec.ErrUnsupportedAlgorithm},
		{"XPath Filter 2.0", key, func(o *dsig.SignOptions) {
			o.References = ref(body, xmlsec.TransformXPathFilter2)
		}, xmlsec.ErrTransformRefused},
		{"unknown transform", key, func(o *dsig.SignOptions) { o.References = ref(body, "urn:x") }, xmlsec.ErrUnsupportedAlgorithm},
		{"ECDSA algorithm with an RSA key", key, func(o *dsig.SignOptions) {
			o.SignatureAlgorithm = xmlsec.SigECDSASHA256
		}, xmlsec.ErrUnsupportedAlgorithm},
		{"RSA algorithm with an ECDSA key", ecKey, nil, xmlsec.ErrUnsupportedAlgorithm},
		{"RSA signer fails", xmlsec.KeyProvider{Signer: covSigner{Signer: rsaKey, err: io.ErrUnexpectedEOF}, Certificate: key.Certificate},
			nil, io.ErrUnexpectedEOF},
		{"ECDSA signer fails", xmlsec.KeyProvider{Signer: covSigner{Signer: covECKey, err: io.ErrUnexpectedEOF}, Certificate: ecKey.Certificate},
			func(o *dsig.SignOptions) { o.SignatureAlgorithm = xmlsec.SigECDSASHA256 }, io.ErrUnexpectedEOF},
		{"ECDSA signer returns non-ASN.1", xmlsec.KeyProvider{Signer: covSigner{Signer: covECKey, out: []byte{1, 2, 3}}, Certificate: ecKey.Certificate},
			func(o *dsig.SignOptions) { o.SignatureAlgorithm = xmlsec.SigECDSASHA256 }, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := dsig.SignOptions{
				SignatureAlgorithm:        xmlsec.SigRSASHA256,
				CanonicalizationAlgorithm: covExc,
				References:                ref(body, covExc),
				KeyInfo:                   dsig.KeyInfoX509Data,
				Attachments:               atts,
			}
			if c.mod != nil {
				c.mod(&opts)
			}
			sig, err := dsig.Sign(doc, c.key, opts)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if sig != nil {
				t.Fatal("signature returned with an error")
			}
		})
	}
}

func TestSignEnvelopedErrors(t *testing.T) {
	key := newKey(t, rsaKey)
	enveloped := []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
		{Algorithm: xmlsec.TransformEnvelopedSignature},
		{Algorithm: covExc, InclusiveNamespacePrefixes: []string{"ec"}},
	}}}
	cases := []struct {
		name string
		doc  *xdm.Node
		c14n string
		want error // nil: any error
	}{
		{"no document element", &xdm.Node{Kind: xdm.KindDocument}, covExc, xmlsec.ErrMalformed},
		{"unknown canonicalization", parse(t, []byte(`<r/>`)), "urn:x", xmlsec.ErrUnsupportedAlgorithm},
		{"ds prefix bound elsewhere", parse(t, []byte(`<r xmlns:ds="urn:other"/>`)), covExc, nil},
		{"ec prefix bound elsewhere", parse(t, []byte(`<r xmlns:ec="urn:other"/>`)), covExc, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := dsig.SignEnveloped(c.doc, key, dsig.SignOptions{
				SignatureAlgorithm:        xmlsec.SigRSASHA256,
				CanonicalizationAlgorithm: c.c14n,
				References:                enveloped,
			})
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if findSignature(c.doc) != nil {
				t.Fatal("document modified on error")
			}
		})
	}
}

// covSignAndPlace signs refs over the envelope, places the signature in the
// security header, and returns the serialized document.
func covSignAndPlace(t *testing.T, key xmlsec.KeyProvider, ki dsig.KeyInfoSpec, atts xmlsec.AttachmentSet,
	refs func(bodyID string) []dsig.Reference) []byte {
	t.Helper()
	doc := parse(t, []byte(envelope))
	body := xmltree.DocumentElement(doc).ChildElements()[1]
	bodyID, err := wss.AssignID(doc, body)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := wss.NewHeader(doc, wss.NSSOAP12, "", false)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := dsig.Sign(doc, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10WithComments),
		References:                refs(bodyID),
		KeyInfo:                   ki,
		SignatureID:               "sig-1",
		Attachments:               atts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := hdr.Append(sig); err != nil {
		t.Fatal(err)
	}
	return serialize(t, doc)
}

// An exclusive PrefixList is emitted, read back, and changes what is
// digested: with "eb" listed, the Body's digest depends on the in-scope but
// unused eb binding.
func TestInclusiveNamespacePrefixes(t *testing.T) {
	key := newKey(t, rsaKey)
	tamper := func(s string) string {
		return strings.Replace(s, `xmlns:eb="urn:example:eb"`, `xmlns:eb="urn:example:changed"`, 1)
	}
	cases := []struct {
		name     string
		prefixes []string
		want     error // after tampering with the eb binding
	}{
		{"without PrefixList", nil, nil},
		{"with PrefixList", []string{"eb"}, xmlsec.ErrDigestMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			signed := covSignAndPlace(t, key, dsig.KeyInfoX509Data, nil, func(id string) []dsig.Reference {
				return []dsig.Reference{{URI: "#" + id, DigestAlgorithm: xmlsec.DigestSHA256,
					Transforms: []dsig.TransformSpec{{Algorithm: covExc, InclusiveNamespacePrefixes: c.prefixes}}}}
			})
			if got := strings.Contains(string(signed), `PrefixList="eb"`); got != (c.prefixes != nil) {
				t.Fatalf("PrefixList emitted: %v", got)
			}
			doc := parse(t, signed)
			cov, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if got := cov.References[0].Transforms[0].InclusiveNamespacePrefixes; !slices.Equal(got, c.prefixes) {
				t.Fatalf("prefixes read back %q", got)
			}
			doc = parse(t, []byte(tamper(string(signed))))
			if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{}); !errors.Is(err, c.want) {
				t.Fatalf("after tampering: got %v, want %v", err, c.want)
			}
		})
	}
}

// A relative namespace URI has no canonical form, wherever it is met.
func TestSignCanonicalizationFailure(t *testing.T) {
	key := newKey(t, rsaKey)
	incl := string(c14n.Inclusive10)
	cases := []struct {
		name string
		uri  string
		algs []string
	}{
		{"last transform", "", []string{xmlsec.TransformEnvelopedSignature, incl}},
		{"intermediate transform", "", []string{xmlsec.TransformEnvelopedSignature, incl, incl}},
		{"SignedInfo", "cid:att-1@example.com", []string{xmlsec.TransformAttachmentContentOnly}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ts []dsig.TransformSpec
			for _, a := range c.algs {
				ts = append(ts, dsig.TransformSpec{Algorithm: a})
			}
			_, err := dsig.SignEnveloped(parse(t, []byte(`<r xmlns:rel="relative/uri"/>`)), key, dsig.SignOptions{
				SignatureAlgorithm:        xmlsec.SigRSASHA256,
				CanonicalizationAlgorithm: incl,
				References:                []dsig.Reference{{URI: c.uri, DigestAlgorithm: xmlsec.DigestSHA256, Transforms: ts}},
				Attachments:               attachments(t, "x"),
			})
			if !errors.Is(err, c14n.ErrRelativeNamespaceURI) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// A token whose wsu:Id is empty resolves, but cannot be referenced.
func TestSignEmptyTokenID(t *testing.T) {
	key := newKey(t, rsaKey)
	doc := parse(t, []byte(`<r xmlns:wsu="`+wss.NSWSU+`"><wsse:BinarySecurityToken xmlns:wsse="`+wss.NSWSSE+`" wsu:Id=""`+
		` EncodingType="`+xmlsec.BSTEncodingBase64+`" ValueType="`+xmlsec.BSTValueTypeX509v3+`">`+
		base64.StdEncoding.EncodeToString(key.Certificate.Raw)+`</wsse:BinarySecurityToken></r>`))
	_, err := dsig.Sign(doc, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: covExc,
		References: []dsig.Reference{{URI: "cid:att-1@example.com", DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformAttachmentContentOnly}}}},
		KeyInfo:     dsig.KeyInfoSecurityTokenReference,
		Attachments: attachments(t, "x"),
	})
	if err == nil {
		t.Fatal("empty token ID accepted")
	}
}
