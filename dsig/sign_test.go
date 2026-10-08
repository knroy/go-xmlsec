package dsig_test

import (
	"bytes"
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
	hdr, err := wss.NewHeader(doc, xmlsec.NSSOAP12, "", false)
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
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
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
		{"unknown KeyInfoForm", key, func(o *dsig.SignOptions) { o.KeyInfo = dsig.KeyInfoForm(99) }, nil},
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
			o.References = ref("cid:att-1@example.com", xmlsec.TransformAttachmentContentSignature)
			o.Attachments = nil
		}, xmlsec.ErrAttachmentNotFound},
		{"cid: not in the set", key, func(o *dsig.SignOptions) {
			o.References = ref("cid:other@example.com", xmlsec.TransformAttachmentContentSignature)
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
		{"cid: without transforms", key, func(o *dsig.SignOptions) { o.References = ref("cid:att-1@example.com") }, xmlsec.ErrMalformed},
		{"cid: beginning with base64", key, func(o *dsig.SignOptions) {
			o.References = ref("cid:att-1@example.com", xmlsec.TransformBase64)
		}, xmlsec.ErrMalformed},
		{"canonicalization of octets that are not XML", key, func(o *dsig.SignOptions) {
			o.References = ref("cid:att-1@example.com", xmlsec.TransformAttachmentContentSignature, covExc)
		}, xmlsec.ErrMalformed},
		{"enveloped on octets", key, func(o *dsig.SignOptions) {
			o.References = ref(body, covExc, xmlsec.TransformEnvelopedSignature, covExc)
		}, xmlsec.ErrMalformed},
		{"base64 of a node set whose text is not base64", key, func(o *dsig.SignOptions) { o.References = ref(body, xmlsec.TransformBase64) }, xmlsec.ErrMalformed},
		{"base64 of non-base64 octets", key, func(o *dsig.SignOptions) {
			o.References = ref("cid:att-1@example.com", xmlsec.TransformAttachmentContentSignature, xmlsec.TransformBase64)
		}, xmlsec.ErrMalformed},
		{"Attachment-Content-Only EncryptedData Type as a transform", key, func(o *dsig.SignOptions) {
			o.References = ref("cid:att-1@example.com", xmlsec.TransformAttachmentContentSignature, xmlsec.TransformAttachmentContentOnly)
		}, xmlsec.ErrUnsupportedAlgorithm},
		{"Attachment-Content-Signature on an element", key, func(o *dsig.SignOptions) {
			o.References = ref(body, xmlsec.TransformAttachmentContentSignature)
		}, xmlsec.ErrMalformed},
		{"Attachment-Complete EncryptedData Type as a transform", key, func(o *dsig.SignOptions) {
			o.References = ref("cid:att-1@example.com", xmlsec.TransformAttachmentCompleteSignature, xmlsec.TransformAttachmentComplete)
		}, xmlsec.ErrUnsupportedAlgorithm},
		{"Attachment-Complete-Signature on an element", key, func(o *dsig.SignOptions) {
			o.References = ref(body, xmlsec.TransformAttachmentCompleteSignature)
		}, xmlsec.ErrMalformed},
		{"Attachment-Content-Signature not first", key, func(o *dsig.SignOptions) {
			o.References = ref("cid:att-1@example.com", xmlsec.TransformAttachmentContentSignature, xmlsec.TransformAttachmentContentSignature)
		}, xmlsec.ErrMalformed},

		// XML-DSig 6.4.2: at least 2048-bit RSA keys for creating signatures.
		{"1024-bit RSA signer", newKey(t, small), nil, xmlsec.ErrUnsupportedKeyInfo},

		// XML-DSig 4.2: a laxly schema-valid ds:Signature.
		{"SignatureID not an NCName", key, func(o *dsig.SignOptions) { o.SignatureID = "1sig" }, xmlsec.ErrMalformed},
		{"SignatureID with a colon", key, func(o *dsig.SignOptions) { o.SignatureID = "a:b" }, xmlsec.ErrMalformed},
		{"Reference.ID not an NCName", key, func(o *dsig.SignOptions) { o.References[0].ID = "ref 1" }, xmlsec.ErrMalformed},
		{"Reference.Type with whitespace", key, func(o *dsig.SignOptions) { o.References[0].Type = "urn:a b" }, xmlsec.ErrMalformed},
		{"Reference.Type not a URI", key, func(o *dsig.SignOptions) { o.References[0].Type = "%zz" }, xmlsec.ErrMalformed},

		// XPointer: only #xpointer(/) and #xpointer(id('ID')).
		{"#xpointer(/) without enveloped", key, func(o *dsig.SignOptions) { o.References = ref("#xpointer(/)", covExc) }, xmlsec.ErrMalformed},
		{"XPointer expression", key, func(o *dsig.SignOptions) { o.References = ref("#xpointer(//*)", covExc) }, xmlsec.ErrMalformed},
		{"XPointer id() not an NCName", key, func(o *dsig.SignOptions) { o.References = ref("#xpointer(id('1'))", covExc) }, xmlsec.ErrMalformed},
		{"XPointer id() with mixed quotes", key, func(o *dsig.SignOptions) {
			o.References = ref("#xpointer(id('"+bodyID+`"))`, covExc)
		}, xmlsec.ErrMalformed},
		{"XPointer id() not found", key, func(o *dsig.SignOptions) { o.References = ref("#xpointer(id('nope'))", covExc) }, xmlsec.ErrIDNotFound},
		{"Attachment-Complete-Signature over a malformed header", key, func(o *dsig.SignOptions) {
			o.References = ref("cid:att-1@example.com", xmlsec.TransformAttachmentCompleteSignature)
			o.Attachments, _ = xmlsec.NewAttachmentSet(&xmlsec.Attachment{ID: "att-1@example.com",
				MIMEHeaders: map[string][]string{"Content-Type": {"text/plain; charset"}}})
		}, xmlsec.ErrMalformed},
		{"XPath Filter 2.0 without filters", key, func(o *dsig.SignOptions) {
			o.References = ref(body, xmlsec.TransformXPathFilter2)
		}, xmlsec.ErrMalformed},
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
func covSignAndPlace(t *testing.T, key xmlsec.KeyProvider, ki dsig.KeyInfoForm, atts xmlsec.AttachmentSet,
	refs func(bodyID string) []dsig.Reference) []byte {
	t.Helper()
	doc := parse(t, []byte(envelope))
	body := xmltree.DocumentElement(doc).ChildElements()[1]
	bodyID, err := wss.AssignID(doc, body)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := wss.NewHeader(doc, xmlsec.NSSOAP12, "", false)
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
		{"SignedInfo", "cid:att-1@example.com", []string{xmlsec.TransformAttachmentContentSignature}},
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
	doc := parse(t, []byte(`<r xmlns:wsu="`+xmlsec.NSWSU+`"><wsse:BinarySecurityToken xmlns:wsse="`+xmlsec.NSWSSE+`" wsu:Id=""`+
		` EncodingType="`+xmlsec.BSTEncodingBase64+`" ValueType="`+xmlsec.BSTValueTypeX509v3+`">`+
		base64.StdEncoding.EncodeToString(key.Certificate.Raw)+`</wsse:BinarySecurityToken></r>`))
	_, err := dsig.Sign(doc, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: covExc,
		References: []dsig.Reference{{URI: "cid:att-1@example.com", DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformAttachmentContentSignature}}}},
		KeyInfo:     dsig.KeyInfoSecurityTokenReference,
		Attachments: attachments(t, "x"),
	})
	if err == nil {
		t.Fatal("empty token ID accepted")
	}
}

// With SignOptions.Parent, Sign computes the signature where it will stand,
// so inclusive canonicalization of ds:SignedInfo is valid even though the
// ancestors declare namespaces a detached computation would not see.
func TestSignInPlace(t *testing.T) {
	key := newKey(t, rsaKey)
	incl := string(c14n.Inclusive10)
	src := `<S:Envelope xmlns:S="` + xmlsec.NSSOAP12 + `" xmlns:extra="urn:extra" xmlns:wsu="` + xmlsec.NSWSU + `">` +
		`<S:Header><Sec/></S:Header><S:Body wsu:Id="body"><x>1</x></S:Body></S:Envelope>`
	doc := parse(t, []byte(src))
	sec := xmltree.DocumentElement(doc).ChildElements()[0].ChildElements()[0]
	opts := dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: incl,
		References: []dsig.Reference{{URI: "#body", DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms: []dsig.TransformSpec{{Algorithm: incl}}}},
		KeyInfo: dsig.KeyInfoX509Data,
		Parent:  sec,
	}
	sig, err := dsig.Sign(doc, key, opts)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Parent != sec {
		t.Fatal("signature not placed under Parent")
	}
	verifyOpts := dsig.VerifyOptions{Certificate: key.Certificate, AllowedCanonicalizationAlgorithms: []string{incl}}
	if cov, err := dsig.Verify(doc, sig, verifyOpts); err != nil || !cov.Covers("body") {
		t.Fatalf("in memory: %v", err)
	}
	// And as a receiver sees it, after serialization.
	out, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10})
	if err != nil {
		t.Fatal(err)
	}
	re := parse(t, out)
	if _, err := dsig.Verify(re, findSignature(re), verifyOpts); err != nil {
		t.Fatalf("after reparse: %v", err)
	}
}

func TestSignInPlaceRefusals(t *testing.T) {
	key := newKey(t, rsaKey)
	base := func(doc, parent *xdm.Node, uri string) dsig.SignOptions {
		return dsig.SignOptions{
			SignatureAlgorithm:        xmlsec.SigRSASHA256,
			CanonicalizationAlgorithm: string(c14n.Inclusive10),
			References: []dsig.Reference{{URI: uri, DigestAlgorithm: xmlsec.DigestSHA256,
				Transforms: []dsig.TransformSpec{{Algorithm: string(c14n.Inclusive10)}}}},
			Parent: parent,
		}
	}
	doc := parse(t, []byte(`<r><a/></r>`))
	other := parse(t, []byte(`<o/>`))
	root := xmltree.DocumentElement(doc)
	for name, c := range map[string]struct{ doc, parent *xdm.Node }{
		"parent in another document": {doc, xmltree.DocumentElement(other)},
		"parent not an element":      {doc, doc},
		"no document":                {nil, root},
	} {
		if _, err := dsig.Sign(c.doc, key, base(c.doc, c.parent, "")); !errors.Is(err, xmlsec.ErrMalformed) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// A failure after placing the signature leaves the document unchanged.
	before := serialize(t, doc)
	if _, err := dsig.Sign(doc, key, base(doc, root, "#nope")); !errors.Is(err, xmlsec.ErrIDNotFound) {
		t.Fatalf("got %v", err)
	}
	if after := serialize(t, doc); !bytes.Equal(after, before) {
		t.Fatalf("a failed Sign changed the document:\n%s", after)
	}
}

// XML-DSig 4.4.1: CanonicalizationPrefixes becomes the PrefixList of
// ds:CanonicalizationMethod and is applied to ds:SignedInfo: with "p"
// listed, the signature depends on the in-scope but unused p binding.
func TestCanonicalizationPrefixes(t *testing.T) {
	key := newKey(t, rsaKey)
	for _, prefixes := range [][]string{nil, {"p", ""}} {
		doc := parse(t, []byte(`<r xmlns:p="urn:p"><a xml:id="a">x</a></r>`))
		_, err := dsig.Sign(doc, key, dsig.SignOptions{
			SignatureAlgorithm:        xmlsec.SigRSASHA256,
			CanonicalizationAlgorithm: string(c14n.Exclusive10),
			CanonicalizationPrefixes:  prefixes,
			References:                []dsig.Reference{ref("#a")},
			Parent:                    xmltree.DocumentElement(doc),
		})
		if err != nil {
			t.Fatal(err)
		}
		signed := serialize(t, doc)
		if got := strings.Contains(string(signed), `<ec:InclusiveNamespaces xmlns:ec="`+xmlsec.NSExcC14N+`" PrefixList="p #default">`); got != (prefixes != nil) {
			t.Fatalf("PrefixList emitted %v:\n%s", got, signed)
		}
		opts := dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey}
		d := parse(t, signed)
		if _, err := dsig.Verify(d, findSignature(d), opts); err != nil {
			t.Fatal(err)
		}
		d = parse(t, []byte(strings.Replace(string(signed), `xmlns:p="urn:p"`, `xmlns:p="urn:changed"`, 1)))
		if _, err := dsig.Verify(d, findSignature(d), opts); (err != nil) != (prefixes != nil) {
			t.Fatalf("rebinding p with PrefixList %v: %v", prefixes, err)
		}
	}

	doc := parse(t, []byte(`<r/>`))
	for name, c := range map[string]struct {
		alg      c14n.Algorithm
		prefixes []string
		parent   *xdm.Node
	}{
		"detached":     {c14n.Exclusive10, []string{"p"}, nil},
		"inclusive":    {c14n.Inclusive10, []string{"p"}, xmltree.DocumentElement(doc)},
		"not a prefix": {c14n.Exclusive10, []string{"a b"}, xmltree.DocumentElement(doc)},
	} {
		_, err := dsig.Sign(doc, key, dsig.SignOptions{
			SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c.alg),
			CanonicalizationPrefixes: c.prefixes, Parent: c.parent,
			References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256,
				Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformEnvelopedSignature}, excC14N[0]}}},
		})
		if !errors.Is(err, xmlsec.ErrMalformed) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	// The ec prefix of the PrefixList element may not shadow another.
	doc = parse(t, []byte(`<r xmlns:ec="urn:other"><a xml:id="a"/></r>`))
	if _, err := dsig.Sign(doc, key, dsig.SignOptions{
		SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c14n.Exclusive10),
		CanonicalizationPrefixes: []string{"p"}, Parent: xmltree.DocumentElement(doc), References: []dsig.Reference{ref("#a")},
	}); err == nil || !strings.Contains(err.Error(), "already bound") {
		t.Fatalf("ec rebound: %v", err)
	}
}

// XML-DSig 4.4.3.1: one Reference may omit its URI; its data object is
// OmittedURIData, which the verifier supplies again.
func TestSignOmittedURI(t *testing.T) {
	key := newKey(t, rsaKey)
	omitted := dsig.Reference{OmitURI: true, DigestAlgorithm: xmlsec.DigestSHA256}
	doc := parse(t, []byte(`<r><a xml:id="a"/></r>`))
	_, err := dsig.Sign(doc, key, dsig.SignOptions{
		SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{ref("#a"), omitted}, OmittedURIData: []byte("known"),
		Parent: xmltree.DocumentElement(doc),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed := serialize(t, doc)
	if strings.Count(string(signed), "URI=") != 1 {
		t.Fatalf("the omitted URI is emitted:\n%s", signed)
	}
	for data, want := range map[string]error{"known": nil, "other": xmlsec.ErrDigestMismatch} {
		d := parse(t, signed)
		cov, err := dsig.Verify(d, findSignature(d), dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey,
			ResolveOmittedURI: func() ([]byte, error) { return []byte(data), nil }})
		if !errors.Is(err, want) || err == nil && !cov.OmittedURISigned {
			t.Fatalf("%s: %v", data, err)
		}
	}

	for name, c := range map[string]struct {
		refs []dsig.Reference
		data []byte
	}{
		"two":        {[]dsig.Reference{omitted, omitted}, []byte("x")},
		"no data":    {[]dsig.Reference{omitted}, nil},
		"with a URI": {[]dsig.Reference{{OmitURI: true, URI: "#a", DigestAlgorithm: xmlsec.DigestSHA256}}, []byte("x")},
		"enveloped":  {[]dsig.Reference{{OmitURI: true, DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformEnvelopedSignature}}}}, []byte("x")},
	} {
		_, err := dsig.Sign(doc, key, dsig.SignOptions{
			SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c14n.Exclusive10),
			References: c.refs, OmittedURIData: c.data,
		})
		if !errors.Is(err, xmlsec.ErrMalformed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// XML-DSig 4.4.3.3: without SignOptions.Parent, a reference to an element of
// the signature itself is digested before the caller places it, so only
// transforms independent of the placement are accepted (audit A10).
func TestSignDetachedSelfReference(t *testing.T) {
	key := newKey(t, rsaKey)
	sign := func(doc *xdm.Node, uri string, ts []dsig.TransformSpec, edit func(*dsig.SignOptions)) (*xdm.Node, error) {
		content := parse(t, []byte(`<x>data</x>`))
		opts := dsig.SignOptions{
			SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c14n.Exclusive10),
			Objects:    []dsig.Object{{ID: "obj", Content: []*xdm.Node{xmltree.DocumentElement(content)}}},
			References: []dsig.Reference{{URI: uri, DigestAlgorithm: xmlsec.DigestSHA256, Transforms: ts}},
			KeyInfo:    dsig.KeyInfoX509Data, KeyInfoID: "ki",
		}
		if edit != nil {
			edit(&opts)
		}
		return dsig.Sign(doc, key, opts)
	}
	const placed = `<root xmlns:foo="urn:foo" xml:lang="en"><hdr/></root>`
	refused := map[string][]dsig.TransformSpec{
		"C14N 1.0":                  {{Algorithm: string(c14n.Inclusive10)}},
		"C14N 1.0 with comments":    {{Algorithm: string(c14n.Inclusive10WithComments)}},
		"C14N 1.1":                  {{Algorithm: string(c14n.Inclusive11)}},
		"C14N 1.1 with comments":    {{Algorithm: string(c14n.Inclusive11WithComments)}},
		"exclusive with a prefix":   {{Algorithm: string(c14n.Exclusive10), InclusiveNamespacePrefixes: []string{"foo"}}},
		"exclusive, then inclusive": {excC14N[0], {Algorithm: string(c14n.Inclusive10)}},
		"XPath":                     {xp(xpNoX, xpNS), excC14N[0]},
		"XSLT":                      {xsltSpec(stylesheet(t, xsltSheet)), excC14N[0]},
	}
	for name, ts := range refused {
		for _, uri := range []string{"#obj", "#ki", "#xpointer(id('obj'))"} {
			if _, err := sign(parse(t, []byte(placed)), uri, ts, nil); !errors.Is(err, xmlsec.ErrUnsupportedAlgorithm) {
				t.Errorf("%s, %s: %v", name, uri, err)
			}
		}
	}

	// Exclusive canonicalization keeps the digest valid where the caller
	// places the signature, inside an element with namespaces of its own.
	for name, ts := range map[string][]dsig.TransformSpec{
		"exclusive":                 excC14N,
		"exclusive with comments":   {{Algorithm: string(c14n.Exclusive10WithComments)}},
		"enveloped, then exclusive": {{Algorithm: xmlsec.TransformEnvelopedSignature}, excC14N[0]},
		"base64":                    {{Algorithm: xmlsec.TransformBase64}},
	} {
		doc := parse(t, []byte(placed))
		uri := "#obj"
		if name == "base64" {
			uri = "#b64"
		}
		sig, err := sign(doc, uri, ts, func(o *dsig.SignOptions) {
			if uri == "#b64" {
				o.Objects = []dsig.Object{{ID: "b64", Content: []*xdm.Node{xmltree.DocumentElement(parse(t, []byte(`<x>ZGF0YQ==</x>`)))}}}
			}
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		xmltree.DocumentElement(doc).ChildElements()[0].AppendChild(sig)
		d := parse(t, serialize(t, doc))
		if _, err := dsig.Verify(d, findSignature(d), dsig.VerifyOptions{Certificate: key.Certificate}); err != nil {
			t.Errorf("%s, placed: %v", name, err)
		}
	}

	// In place, or enveloping with no document around it, nothing moves.
	doc := parse(t, []byte(placed))
	hdr := xmltree.DocumentElement(doc).ChildElements()[0]
	if _, err := sign(doc, "#obj", refused["C14N 1.1"], func(o *dsig.SignOptions) { o.Parent = hdr }); err != nil {
		t.Fatalf("in place: %v", err)
	}
	if _, err := sign(nil, "#obj", refused["C14N 1.1"], nil); err != nil {
		t.Fatalf("enveloping: %v", err)
	}
	// A target outside the signature stands where it will be verified.
	if _, err := sign(parse(t, []byte(`<root><a xml:id="a"/></root>`)), "#a", refused["C14N 1.0"], nil); err != nil {
		t.Fatalf("document element: %v", err)
	}
	// So does the whole document, and an external resource.
	if _, err := sign(parse(t, []byte(placed)), "", []dsig.TransformSpec{{Algorithm: xmlsec.TransformEnvelopedSignature}, refused["C14N 1.0"][0]}, nil); err != nil {
		t.Fatalf("whole document: %v", err)
	}
	if _, err := sign(parse(t, []byte(placed)), "http://example.com/a.xml", refused["C14N 1.0"], func(o *dsig.SignOptions) {
		o.ResolveURI = func(string) ([]byte, error) { return []byte(`<a/>`), nil }
	}); err != nil {
		t.Fatalf("external: %v", err)
	}
	// A reference that does not resolve is reported as before.
	if _, err := sign(parse(t, []byte(placed)), "#missing", refused["C14N 1.0"], nil); !errors.Is(err, xmlsec.ErrIDNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := sign(parse(t, []byte(placed)), "#xpointer(//x)", refused["C14N 1.0"], nil); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("XPointer: %v", err)
	}
}

// The STR Dereference Transform renders the default namespace in scope at
// the token, so a token embedded in the detached signature's own
// wsse:SecurityTokenReference is refused; one in the document is not.
func TestSignDetachedEmbeddedToken(t *testing.T) {
	key := newKey(t, rsaKey)
	doc, tokID, bodyID := covTokenDoc(t, key)
	tok, err := wss.FindByID(doc, tokID)
	if err != nil {
		t.Fatal(err)
	}
	str := xmltree.Element(nil, "wsse", xmlsec.NSWSSE, "SecurityTokenReference")
	str.AddNamespace("wsse", xmlsec.NSWSSE)
	str.AddNamespace("wsu", xmlsec.NSWSU)
	xmltree.SetAttr(str, "wsu", xmlsec.NSWSU, "Id", "str")
	xmltree.Element(str, "wsse", xmlsec.NSWSSE, "Embedded").AppendChild(xmltree.Clone(tok))
	_, err = dsig.Sign(doc, key, dsig.SignOptions{
		SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c14n.Exclusive10),
		KeyInfo: dsig.KeyInfoSecurityTokenReference, KeyInfoElement: str,
		References: []dsig.Reference{{URI: "#" + bodyID, Transforms: excC14N, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "#str", Transforms: strTransform, DigestAlgorithm: xmlsec.DigestSHA256}},
	})
	if !errors.Is(err, xmlsec.ErrUnsupportedAlgorithm) {
		t.Fatalf("embedded token: %v", err)
	}
}
