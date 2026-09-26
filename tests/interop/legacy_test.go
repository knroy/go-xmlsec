//go:build interop

//lint:file-ignore SA1019 crypto/dsa generates the key xmlsec1 signs dsa-sha1 with.

package interop

import (
	"bytes"
	"crypto/dsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
)

// dsaKeyPEM writes a fresh (1024, 160) DSA key in the OpenSSL traditional
// "DSA PRIVATE KEY" form, which Go cannot marshal and xmlsec1 reads.
func dsaKeyPEM(t *testing.T) (*dsa.PrivateKey, string) {
	t.Helper()
	k := new(dsa.PrivateKey)
	if err := dsa.GenerateParameters(&k.Parameters, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	if err := dsa.GenerateKey(k, rand.Reader); err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		Version       int
		P, Q, G, Y, X *big.Int
	}{0, k.P, k.Q, k.G, k.Y, k.X})
	if err != nil {
		t.Fatal(err)
	}
	return k, tempFile(t, "dsa.pem", pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: der}))
}

// We verify xmlsec1's legacy signatures, which XML Signature 1.1 requires a
// verifier to accept, only when the caller names each algorithm: under
// empty allow-lists every one is refused.
func TestWeVerifyXmlsec1LegacySignatures(t *testing.T) {
	rsaKP := newKeypair(t, rsaKey(t))
	_, dsaPEM := dsaKeyPEM(t)
	secret := []byte("interop shared secret, 32 octets")
	secretFile := tempFile(t, "hmac.bin", secret)
	x509KI := `<ds:KeyInfo><ds:X509Data><ds:X509Certificate/></ds:X509Data></ds:KeyInfo>`

	cases := []struct {
		name, sigAlg, digestAlg string
		smChildren, keyInfo     string
		keyArgs                 []string
		opts                    dsig.VerifyOptions
		form                    dsig.KeyInfoSpec
	}{
		{"rsa-sha1 with sha1 digest", xmlsec.SigRSASHA1, xmlsec.DigestSHA1, "", x509KI,
			[]string{"--privkey-pem", rsaKP.keyPEM + "," + rsaKP.certPEM}, dsig.VerifyOptions{}, dsig.KeyInfoX509Data},
		{"dsa-sha1 with DSAKeyValue", xmlsec.SigDSASHA1, xmlsec.DigestSHA256, "", `<ds:KeyInfo><ds:KeyValue/></ds:KeyInfo>`,
			[]string{"--enabled-key-data", "key-value,dsa", "--privkey-pem", dsaPEM}, dsig.VerifyOptions{}, dsig.KeyInfoKeyValue},
		{"hmac-sha1", xmlsec.SigHMACSHA1, xmlsec.DigestSHA256, "", "",
			[]string{"--hmackey", secretFile}, dsig.VerifyOptions{HMACKey: secret}, dsig.KeyInfoNone},
		{"hmac-sha256", xmlsec.SigHMACSHA256, xmlsec.DigestSHA256, "", "",
			[]string{"--hmackey", secretFile}, dsig.VerifyOptions{HMACKey: secret}, dsig.KeyInfoNone},
		{"hmac-sha256 truncated to 128 bits", xmlsec.SigHMACSHA256, xmlsec.DigestSHA256, `<ds:HMACOutputLength>128</ds:HMACOutputLength>`, "",
			[]string{"--hmackey", secretFile}, dsig.VerifyOptions{HMACKey: secret}, dsig.KeyInfoNone},
		{"hmac-sha512", xmlsec.SigHMACSHA512, xmlsec.DigestSHA256, "", "",
			[]string{"--hmackey", secretFile}, dsig.VerifyOptions{HMACKey: secret}, dsig.KeyInfoNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			exc := string(c14n.Exclusive10)
			tmpl := `<smp:SignedServiceMetadata xmlns:smp="urn:example:smp">` +
				`<smp:ServiceMetadata><smp:Endpoint a="1">https://example.com/</smp:Endpoint></smp:ServiceMetadata>` +
				`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>` +
				`<ds:CanonicalizationMethod Algorithm="` + exc + `"/>` +
				`<ds:SignatureMethod Algorithm="` + c.sigAlg + `">` + c.smChildren + `</ds:SignatureMethod>` +
				`<ds:Reference URI=""><ds:Transforms>` +
				`<ds:Transform Algorithm="` + xmlsec.TransformEnvelopedSignature + `"/>` +
				`<ds:Transform Algorithm="` + exc + `"/>` +
				`</ds:Transforms><ds:DigestMethod Algorithm="` + c.digestAlg + `"/><ds:DigestValue/></ds:Reference>` +
				`</ds:SignedInfo><ds:SignatureValue/>` + c.keyInfo +
				`</ds:Signature></smp:SignedServiceMetadata>`
			out := filepath.Join(t.TempDir(), "out.xml")
			args := append([]string{"--sign"}, c.keyArgs...)
			run(t, append(args, "--output", out, tempFile(t, "tmpl.xml", []byte(tmpl)))...)
			signed, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}

			doc := parse(t, signed)
			sig := find(doc, dsig.NSDSig, "Signature")
			if _, err := dsig.Verify(doc, sig, c.opts); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
				t.Fatalf("empty allow-lists: got %v\n%s", err, signed)
			}
			opts := c.opts
			opts.AllowedSignatureAlgorithms = []string{c.sigAlg}
			opts.AllowedDigestAlgorithms = []string{c.digestAlg}
			cov, err := dsig.Verify(doc, sig, opts)
			if err != nil {
				t.Fatalf("named: %v\n%s", err, signed)
			}
			if !cov.WholeDocumentSigned || cov.KeyInfoForm != c.form {
				t.Fatalf("coverage %+v", cov)
			}

			// The control: the harness must be able to fail.
			tampered := parse(t, bytes.Replace(signed, []byte("example.com"), []byte("evil.com"), 1))
			if _, err := dsig.Verify(tampered, find(tampered, dsig.NSDSig, "Signature"), opts); !errors.Is(err, xmlsec.ErrDigestMismatch) {
				t.Fatalf("tampered: got %v", err)
			}
		})
	}
}
