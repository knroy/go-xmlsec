package dsig_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

const samlAssertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0">` +
	`<saml:Issuer>https://idp.example.com/</saml:Issuer>` +
	`<saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>`

func samlOpts(ids ...xdm.QName) dsig.SignOptions {
	exc := string(c14n.Exclusive10)
	return dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: exc,
		References: []dsig.Reference{{
			URI:             "#_a1",
			DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms: []dsig.TransformSpec{
				{Algorithm: xmlsec.TransformEnvelopedSignature},
				{Algorithm: exc},
			},
		}},
		KeyInfo:      dsig.KeyInfoX509Data,
		IDAttributes: ids,
	}
}

func verifyWith(t *testing.T, signed string, ids ...xdm.QName) (*xdm.Node, *dsig.Coverage, error) {
	t.Helper()
	doc := parse(t, []byte(signed))
	cov, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{IDAttributes: ids})
	return doc, cov, err
}

// A SAML-style enveloped assertion, referenced by its unqualified ID.
func TestSAMLAssertionByID(t *testing.T) {
	key := newKey(t, rsaKey)

	// Default options resolve only wsu:Id and xml:id, as before.
	if _, err := dsig.SignEnveloped(parse(t, []byte(samlAssertion)), key, samlOpts()); !errors.Is(err, xmlsec.ErrIDNotFound) {
		t.Fatalf("default options signed over ID: %v", err)
	}

	b, err := dsig.SignEnveloped(parse(t, []byte(samlAssertion)), key, samlOpts(dsig.IDAttrSAML))
	if err != nil {
		t.Fatal(err)
	}
	signed := string(b)

	doc, cov, err := verifyWith(t, signed, dsig.IDAttrSAML)
	if err != nil {
		t.Fatal(err)
	}
	if !cov.Covers("_a1") || len(cov.SignedElements) != 1 || cov.SignedElements[0] != xmltree.DocumentElement(doc) {
		t.Fatalf("coverage %+v", cov)
	}
	if _, _, err := verifyWith(t, signed); !errors.Is(err, xmlsec.ErrIDNotFound) {
		t.Fatalf("default options verified over ID: %v", err)
	}
	if _, _, err := verifyWith(t, strings.Replace(signed, "alice", "mallory", 1), dsig.IDAttrSAML); !errors.Is(err, xmlsec.ErrDigestMismatch) {
		t.Fatalf("tampered: %v", err)
	}

	// Wrapping: the attacker's assertion carries the signed ID, with the
	// genuine one moved beside it. Resolving either would be wrong.
	forged := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1">` +
		`<saml:Subject><saml:NameID>mallory</saml:NameID></saml:Subject></saml:Assertion>`
	wrapped := `<w:Response xmlns:w="urn:example:w">` + forged + signed + `</w:Response>`
	if _, _, err := verifyWith(t, wrapped, dsig.IDAttrSAML); !errors.Is(err, xmlsec.ErrAmbiguousID) {
		t.Fatalf("wrapped: %v", err)
	}

	// The same value as a wsu:Id elsewhere is a duplicate too.
	withWSU := strings.Replace(signed, "<saml:Issuer>",
		`<x xmlns:wsu="`+wss.NSWSU+`" wsu:Id="_a1"/><saml:Issuer>`, 1)
	if _, _, err := verifyWith(t, withWSU, dsig.IDAttrSAML); !errors.Is(err, xmlsec.ErrAmbiguousID) {
		t.Fatalf("ID and wsu:Id: %v", err)
	}
	if _, err := dsig.SignEnveloped(parse(t, []byte(strings.Replace(samlAssertion, "<saml:Issuer>",
		`<x Id="_a1"/><saml:Issuer>`, 1))), key, samlOpts(dsig.IDAttrSAML, dsig.IDAttrDSig)); !errors.Is(err, xmlsec.ErrAmbiguousID) {
		t.Fatalf("signing over ID and Id: %v", err)
	}
}

// An XAdES-style detached reference to an element's plain Id.
func TestPlainIdReference(t *testing.T) {
	key := newKey(t, rsaKey)
	const in = `<doc><obj Id="o1">data</obj></doc>`
	opts := dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{{
			URI:             "#o1",
			DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms:      []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}},
		}},
		KeyInfo: dsig.KeyInfoX509Data,
	}
	if _, err := dsig.Sign(parse(t, []byte(in)), key, opts); !errors.Is(err, xmlsec.ErrIDNotFound) {
		t.Fatalf("default options signed over Id: %v", err)
	}

	opts.IDAttributes = []xdm.QName{dsig.IDAttrDSig}
	doc := parse(t, []byte(in))
	sig, err := dsig.Sign(doc, key, opts)
	if err != nil {
		t.Fatal(err)
	}
	xmltree.DocumentElement(doc).AppendChild(sig)
	signed := string(serialize(t, doc))

	_, cov, err := verifyWith(t, signed, dsig.IDAttrDSig)
	if err != nil || !cov.Covers("o1") {
		t.Fatalf("%v, %+v", err, cov)
	}
	if _, _, err := verifyWith(t, signed); !errors.Is(err, xmlsec.ErrIDNotFound) {
		t.Fatalf("default options verified over Id: %v", err)
	}
	// SAML's ID is not Id.
	if _, _, err := verifyWith(t, signed, dsig.IDAttrSAML); !errors.Is(err, xmlsec.ErrIDNotFound) {
		t.Fatalf("ID option resolved Id: %v", err)
	}
}

// An ID attribute that is not configured cannot make a wsu:Id reference
// ambiguous: the default set is unchanged. Once configured, it does.
func TestDefaultIDSetUnchanged(t *testing.T) {
	signed, _, bodyID := signAS4(t, newKey(t, rsaKey))
	s := strings.Replace(string(signed), "</eb:Messaging>", `</eb:Messaging><x ID="`+bodyID+`"/>`, 1)
	for _, c := range []struct {
		ids  []xdm.QName
		want error
	}{
		{nil, nil},
		{[]xdm.QName{dsig.IDAttrSAML}, xmlsec.ErrAmbiguousID},
	} {
		doc := parse(t, []byte(s))
		opts := as4Allow
		opts.Attachments = attachments(t, "payload")
		opts.IDAttributes = c.ids
		if _, err := dsig.Verify(doc, findSignature(doc), opts); !errors.Is(err, c.want) {
			t.Errorf("%v: got %v, want %v", c.ids, err, c.want)
		}
	}
}
