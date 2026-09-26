//go:build interop

package interop

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
)

// XML-DSig 4.4.3.3: #xpointer(/) and #xpointer(id('ID')) keep comments, so
// with a #WithComments canonicalization a comment is signed. Santuario
// verifies ours and we verify Santuario's, with identical digests and
// SignatureValue, and each side refuses the other's signature once the
// comment is changed.
func TestSantuarioXPointerReferences(t *testing.T) {
	const doc = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0">` +
		`<saml:Subject><saml:NameID>alice<!-- note --></saml:NameID></saml:Subject></saml:Assertion>`
	excWC := string(c14n.Exclusive10WithComments)
	kp := newKeypair(t, rsaKey(t))
	ids := []xdm.QName{dsig.IDAttrSAML}
	retag := func(b []byte) []byte { return bytes.Replace(b, []byte("<!-- note -->"), []byte("<!-- mallory -->"), 1) }

	for _, uri := range []string{"#xpointer(/)", "#xpointer(id('_a1'))"} {
		t.Run(uri, func(t *testing.T) {
			ours, err := dsig.SignEnveloped(parse(t, []byte(doc)), kp.provider, dsig.SignOptions{
				SignatureAlgorithm:        xmlsec.SigRSASHA256,
				CanonicalizationAlgorithm: excWC,
				References: []dsig.Reference{{URI: uri, DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
					{Algorithm: xmlsec.TransformEnvelopedSignature}, {Algorithm: excWC}}}},
				KeyInfo:      dsig.KeyInfoX509Data,
				IDAttributes: ids,
			})
			if err != nil {
				t.Fatal(err)
			}
			mustSantuario(t, "--id-attr", "ID", "verify", tempFile(t, "ours.xml", ours), kp.certPEM)
			if out, err := santuario(t, "--id-attr", "ID", "verify", tempFile(t, "tampered.xml", retag(ours)), kp.certPEM); err == nil {
				t.Fatalf("Santuario accepted a changed comment:\n%s", out)
			}

			out := filepath.Join(t.TempDir(), "out.xml")
			mustSantuario(t, "--id-attr", "ID", "sign-enveloped", tempFile(t, "in.xml", []byte(doc)),
				kp.keyPEM, kp.certPEM, excWC, xmlsec.SigRSASHA256, out, uri)
			theirs := readFile(t, out)
			compareSignatures(t, ours, theirs)

			verify := func(b []byte) (*dsig.Coverage, error) {
				d := parse(t, b)
				return dsig.Verify(d, find(d, dsig.NSDSig, "Signature"), dsig.VerifyOptions{
					Certificate: kp.provider.Certificate, IDAttributes: ids,
				})
			}
			cov, err := verify(theirs)
			if err != nil {
				t.Fatalf("%v\n%s", err, theirs)
			}
			if whole := uri == "#xpointer(/)"; cov.WholeDocumentSigned != whole || !whole && !cov.Covers("_a1") {
				t.Fatalf("coverage %+v", cov)
			}
			if _, err := verify(retag(theirs)); !errors.Is(err, xmlsec.ErrDigestMismatch) {
				t.Fatalf("changed comment in Santuario's signature: %v", err)
			}
		})
	}
}
