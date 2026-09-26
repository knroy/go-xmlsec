//go:build interop

package interop

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
)

const samlAssertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0">` +
	`<saml:Issuer>https://idp.example.com/</saml:Issuer>` +
	`<saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>`

// A SAML-style enveloped assertion signed over its unqualified ID: Santuario
// verifies ours, we verify Santuario's, and with the same RSA key both carry
// identical digests and SignatureValue.
func TestSantuarioSAMLAssertionByID(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	exc := string(c14n.Exclusive10)
	ours, err := dsig.SignEnveloped(parse(t, []byte(samlAssertion)), kp.provider, dsig.SignOptions{
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
		IDAttributes: []xdm.QName{dsig.IDAttrSAML},
	})
	if err != nil {
		t.Fatal(err)
	}
	oursPath := tempFile(t, "ours.xml", ours)
	mustSantuario(t, "--id-attr", "ID", "verify", oursPath, kp.certPEM)
	// Without the registration Santuario cannot resolve "#_a1" either, so
	// the option is what made the difference.
	if out, err := santuario(t, "verify", oursPath, kp.certPEM); err == nil {
		t.Fatalf("Santuario resolved an unregistered ID:\n%s", out)
	}
	tampered := bytes.Replace(ours, []byte("alice"), []byte("mallory"), 1)
	if out, err := santuario(t, "--id-attr", "ID", "verify", tempFile(t, "tampered.xml", tampered), kp.certPEM); err == nil {
		t.Fatalf("Santuario accepted a tampered assertion:\n%s", out)
	}

	out := filepath.Join(t.TempDir(), "out.xml")
	mustSantuario(t, "--id-attr", "ID", "sign-enveloped", tempFile(t, "in.xml", []byte(samlAssertion)),
		kp.keyPEM, kp.certPEM, exc, xmlsec.SigRSASHA256, out, "#_a1")
	theirs := readFile(t, out)
	compareSignatures(t, ours, theirs)

	doc := parse(t, theirs)
	cov, err := dsig.Verify(doc, find(doc, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{
		Certificate:  kp.provider.Certificate,
		IDAttributes: []xdm.QName{dsig.IDAttrSAML},
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, theirs)
	}
	if !cov.Covers("_a1") || cov.SignedElements[0] != find(doc, "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion") {
		t.Fatalf("coverage %+v", cov)
	}
}
