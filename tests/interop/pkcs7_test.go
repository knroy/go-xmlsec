//go:build interop

package interop

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

// PKCS7 tokens against the JDK's own PKCS#7 codec (sun.security.pkcs),
// through the harness's pkcs7 command. WSS4J 4.0.1 cannot be the peer: its
// DOM processor builds X509v3 and PKIPath tokens only.
//
// We sign a header whose token is a PKCS7 of a leaf and its CA; the JDK reads
// the token back to the same two certificates, and Santuario verifies the
// signature with the leaf. The JDK encodes the same two certificates to the
// same DER octets; its token, in place of ours, resolves to the leaf and the
// signature verifies with StrictSecurityTokenReference.
func TestPKCS7TokenWithJDK(t *testing.T) {
	ca := newKeypair(t, rsaKey(t))
	leafKey := rsaKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "go-xmlsec pkcs7 leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.provider.Certificate, leafKey.Public(), ca.provider.Signer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := tempFile(t, "leaf.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	doc := parse(t, []byte(envelope))
	bodyID, err := wss.AssignID(doc, xmltree.DocumentElement(doc).ChildElements()[1])
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := wss.NewHeader(doc, xmlsec.NSSOAP12, "", true)
	if err != nil {
		t.Fatal(err)
	}
	tokenID, err := hdr.AddBinarySecurityToken(leaf, []*x509.Certificate{ca.provider.Certificate}, xmlsec.BSTValueTypePKCS7)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := dsig.Sign(doc, xmlsec.KeyProvider{Signer: leafKey, Certificate: leaf}, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References:                []dsig.Reference{{URI: "#" + bodyID, Transforms: []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}, DigestAlgorithm: xmlsec.DigestSHA256}},
		KeyInfo:                   dsig.KeyInfoSecurityTokenReference,
		SecurityTokenID:           tokenID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := hdr.Append(sig); err != nil {
		t.Fatal(err)
	}
	signed, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10})
	if err != nil {
		t.Fatal(err)
	}
	ours := strings.TrimSpace(find(doc, xmlsec.NSWSSE, "BinarySecurityToken").StringValue())
	oursDER, err := base64.StdEncoding.DecodeString(ours)
	if err != nil {
		t.Fatal(err)
	}

	theirsPath := filepath.Join(t.TempDir(), "theirs.der")
	out, err := santuario(t, "pkcs7", tempFile(t, "ours.der", oursDER), theirsPath, leafPEM, ca.certPEM)
	if err != nil {
		t.Fatalf("the JDK refused our PKCS7: %v\n%s", err, out)
	}
	for _, want := range []string{"subject CN=go-xmlsec pkcs7 leaf\n", "subject CN=go-xmlsec interop\n"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the JDK read %q, want %q", out, strings.TrimSpace(want))
		}
	}
	mustSantuario(t, "verify", tempFile(t, "signed.xml", signed), leafPEM)
	// DER has one encoding of a value: the JDK's must be ours.
	theirs := base64.StdEncoding.EncodeToString(readFile(t, theirsPath))
	if theirs != ours {
		t.Errorf("the JDK encodes the two certificates as\n%s\nwe as\n%s", theirs, ours)
	}
	// The token is outside the signature, so replacing it leaves the
	// signature intact.
	replaced := parse(t, bytes.Replace(signed, []byte(ours), []byte(theirs), 1))
	cov, err := dsig.Verify(replaced, find(replaced, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{StrictSecurityTokenReference: true})
	if err != nil {
		t.Fatalf("the JDK's PKCS7: %v", err)
	}
	if !cov.Certificate.Equal(leaf) {
		t.Fatalf("resolved %s, want the leaf", cov.Certificate.Subject)
	}
}
