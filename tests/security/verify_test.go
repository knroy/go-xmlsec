package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

func keyPair(t *testing.T, signer crypto.Signer) xmlsec.KeyProvider {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "k"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0)}
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

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// signEnveloped signs src with an enveloped signature carrying X509Data.
func signEnveloped(t *testing.T, src string, kp xmlsec.KeyProvider, sigAlg string) *xdm.Node {
	t.Helper()
	tree, err := xmlsec.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := dsig.SignEnveloped(tree.Root, kp, dsig.SignOptions{
		SignatureAlgorithm:        sigAlg,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
			{Algorithm: xmlsec.TransformEnvelopedSignature}, {Algorithm: string(c14n.Exclusive10)}}}},
		KeyInfo: dsig.KeyInfoX509Data,
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := xmlsec.Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	return doc.Root
}

// An attacker who signs with their own key and embeds their own certificate
// is rejected once the caller pins the expected certificate: the embedded
// one is ignored.
func TestPinnedCertificateIgnoresEmbeddedKey(t *testing.T) {
	victim := keyPair(t, rsaKey(t))
	attacker := keyPair(t, rsaKey(t))
	doc := signEnveloped(t, `<r><amount>1000000</amount></r>`, attacker, xmlsec.SigRSASHA256)
	sig, _, _, _ := elements(doc)

	if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{}); err != nil {
		t.Fatalf("self-describing verification should succeed, and is the caller's trust problem: %v", err)
	}
	if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{Certificate: victim.Certificate}); !errors.Is(err, xmlsec.ErrSignatureInvalid) {
		t.Fatalf("pinned: got %v", err)
	}
}

// resign replaces SignatureMethod and re-signs SignedInfo with key, so the
// signature is authentic and only the algorithm checks stand in the way.
func resign(t *testing.T, doc *xdm.Node, method string, sign func(digest []byte) []byte) *xdm.Node {
	t.Helper()
	sig, si, _, value := elements(doc)
	si.ChildElements()[1].Attr("", "Algorithm").Value = method
	h := sha256.New()
	if _, err := c14n.Digest(h, si, c14n.Options{Algorithm: c14n.Exclusive10}); err != nil {
		t.Fatal(err)
	}
	value.Children[0].Value = base64.StdEncoding.EncodeToString(sign(h.Sum(nil)))
	return sig
}

func TestAlgorithmConfusion(t *testing.T) {
	rk := rsaKey(t)
	rsaKP := keyPair(t, rk)
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKP := keyPair(t, ek)
	rsaSign := func(d []byte) []byte {
		v, err := rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, d)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	cases := []struct {
		name   string
		kp     xmlsec.KeyProvider
		signed string
		method string
		sign   func([]byte) []byte
		want   error
	}{
		// HMAC keyed with the public key is the classic confusion.
		{"HMAC", rsaKP, xmlsec.SigRSASHA256, "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", rsaSign, xmlsec.ErrAlgorithmNotAllowed},
		{"RSA-SHA1", rsaKP, xmlsec.SigRSASHA256, "http://www.w3.org/2000/09/xmldsig#rsa-sha1", rsaSign, xmlsec.ErrAlgorithmNotAllowed},
		{"empty method", rsaKP, xmlsec.SigRSASHA256, "", rsaSign, xmlsec.ErrAlgorithmNotAllowed},
		{"ECDSA URI, RSA key", rsaKP, xmlsec.SigRSASHA256, xmlsec.SigECDSASHA256, rsaSign, xmlsec.ErrUnsupportedAlgorithm},
		{"RSA URI, ECDSA key", ecKP, xmlsec.SigECDSASHA256, xmlsec.SigRSASHA256, func(d []byte) []byte { return make([]byte, 64) }, xmlsec.ErrUnsupportedAlgorithm},
		{"ECDSA r = s = 0", ecKP, xmlsec.SigECDSASHA256, xmlsec.SigECDSASHA256, func(d []byte) []byte { return make([]byte, 64) }, xmlsec.ErrSignatureInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := signEnveloped(t, `<r>x</r>`, c.kp, c.signed)
			sig := resign(t, doc, c.method, c.sign)
			if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{Certificate: c.kp.Certificate}); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

// The comment-truncation class (CVE-2017-11427 and relatives): comments are
// not digested, so a signed value can be split by one. The element Coverage
// returns yields the whole value through StringValue, never the fragment
// before the comment.
func TestCommentCannotTruncateSignedText(t *testing.T) {
	kp := keyPair(t, rsaKey(t))
	doc := signEnveloped(t, `<r><user>admin@example.com<!---->.evil.com</user></r>`, kp, xmlsec.SigRSASHA256)
	sig, _, _, _ := elements(doc)
	cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{Certificate: kp.Certificate})
	if err != nil || !cov.WholeDocumentSigned {
		t.Fatal(err)
	}
	user := xmltree.DocumentElement(doc).ChildElements()[0]
	if got := user.StringValue(); got != "admin@example.com.evil.com" {
		t.Fatalf("StringValue = %q", got)
	}
}

// A received EncryptedData whose algorithm has been swapped is refused
// before any decryption is attempted, under explicit allow-lists and under
// the default set an empty list means. The legacy decryption-only
// algorithms are in neither; legacy_test.go shows each is accepted only
// when named.
func TestEncryptionAlgorithmSubstitution(t *testing.T) {
	kp := keyPair(t, rsaKey(t))
	opts := xenc.EncryptOptions{
		DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyTransportRSAOAEP,
		MGFAlgorithm: xmlsec.MGF1SHA256, DigestAlgorithm: xmlsec.DigestSHA256, Recipient: kp.Certificate,
	}
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := xmlsec.Parse([]byte(`<r><secret>s</secret></r>`))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := xenc.EncryptElement(tree.Root, xmltree.DocumentElement(tree.Root).ChildElements()[0], ek.SessionKey, opts)
	if err != nil {
		t.Fatal(err)
	}
	ekXML, err := c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Exclusive10})
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name, from, to string
		data           bool
	}{
		{"AES-GCM size", xmlsec.EncAES128GCM, xmlsec.EncAES256GCM, true},
		{"AES-CBC", xmlsec.EncAES128GCM, xmlsec.EncAES128CBC, true},
		{"3DES-CBC", xmlsec.EncAES128GCM, xmlsec.EncTripleDESCBC, true},
		{"rsa-oaep-mgf1p", xmlsec.KeyTransportRSAOAEP, xmlsec.KeyTransportRSAOAEPMGF1P, false},
		{"RSA PKCS#1 v1.5", xmlsec.KeyTransportRSAOAEP, xmlsec.KeyTransportRSA15, false},
		{"SHA-1 MGF", xmlsec.MGF1SHA256, xmlsec.MGF1SHA1, false},
		{"SHA-1 digest", xmlsec.DigestSHA256, xmlsec.DigestSHA1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.data {
				doc, err := xmlsec.Parse([]byte(strings.Replace(string(enc), c.from, c.to, 1)))
				if err != nil {
					t.Fatal(err)
				}
				ed := xmltree.DocumentElement(doc.Root).ChildElements()[0]
				if _, err := xenc.DecryptData(ed, ek.SessionKey, xenc.DecryptOptions{AllowedDataAlgorithms: []string{xmlsec.EncAES128GCM}}); err == nil {
					t.Fatal("decrypted")
				}
				if _, err := xenc.DecryptData(ed, ek.SessionKey, xenc.DecryptOptions{}); err == nil {
					t.Fatal("decrypted under the default set")
				}
				return
			}
			doc, err := xmlsec.Parse([]byte(strings.Replace(string(ekXML), c.from, c.to, 1)))
			if err != nil {
				t.Fatal(err)
			}
			el := xmltree.DocumentElement(doc.Root)
			if _, err := xenc.DecryptEncryptedKey(el, kp.Signer.(crypto.Decrypter), xenc.DecryptOptions{AllowedKeyTransportAlgorithms: []string{xmlsec.KeyTransportRSAOAEP}, AllowedMGFAlgorithms: []string{xmlsec.MGF1SHA256}, AllowedDigestAlgorithms: []string{xmlsec.DigestSHA256}}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
				t.Fatalf("got %v", err)
			}
			if _, err := xenc.DecryptEncryptedKey(el, kp.Signer.(crypto.Decrypter), xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
				t.Fatalf("default set: got %v", err)
			}
		})
	}
}
