package security

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// setKeyInfo replaces the content of the signature's ds:KeyInfo, which no
// reference signs, so the signature stays authentic.
func setKeyInfo(t *testing.T, doc *xdm.Node, inner string) (sig *xdm.Node) {
	t.Helper()
	xmltree.Walk(doc, func(e *xdm.Node) {
		if e.IsElement(xmlsec.NSDSig, "Signature") {
			sig = e
		}
	})
	ki := sig.ChildElements()[2]
	fresh, err := xmlsec.Parse([]byte(`<ds:KeyInfo xmlns:ds="` + xmlsec.NSDSig + `" xmlns:dsig11="` + xmlsec.NSDSig11 + `">` + inner + `</ds:KeyInfo>`))
	if err != nil {
		t.Fatal(err)
	}
	ki.Children = nil
	for _, c := range xmltree.DocumentElement(fresh.Root).ChildElements() {
		ki.AppendChild(c)
	}
	return sig
}

// issued is a certificate for signer, issued by the CA key and name.
func issued(t *testing.T, signer crypto.Signer, cn string, ca *x509.Certificate, caKey crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0), SubjectKeyId: []byte(cn)}
	if ca == nil {
		ca, caKey = tmpl, signer
		tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, signer.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func certElement(c *x509.Certificate) string {
	return `<ds:X509Certificate>` + base64.StdEncoding.EncodeToString(c.Raw) + `</ds:X509Certificate>`
}

// XML-DSig 4.5.4: an X509IssuerSerial, X509SKI, X509SubjectName or
// dsig11:X509Digest beside the certificate "MUST refer to" it. Under
// StrictX509Data one that describes another certificate is refused, even
// under an authentic signature; a chain with two leaves, where the signer
// is ambiguous, is refused always.
func TestX509DescriptorMismatchRefused(t *testing.T) {
	caKey, victimKey, otherKey := rsaKey(t), rsaKey(t), rsaKey(t)
	ca := issued(t, caKey, "CA", nil, nil)
	victim := issued(t, victimKey, "victim", ca, caKey)
	other := issued(t, otherKey, "other", ca, caKey)
	otherDigest := sha256.Sum256(other.Raw)
	b64 := base64.StdEncoding.EncodeToString
	cases := map[string]string{
		"issuer-serial of another certificate": `<ds:X509IssuerSerial><ds:X509IssuerName>CN=victim</ds:X509IssuerName><ds:X509SerialNumber>7</ds:X509SerialNumber></ds:X509IssuerSerial>`,
		"another serial number":                `<ds:X509IssuerSerial><ds:X509IssuerName>CN=CA</ds:X509IssuerName><ds:X509SerialNumber>8</ds:X509SerialNumber></ds:X509IssuerSerial>`,
		"SKI of another certificate":           `<ds:X509SKI>` + b64(other.SubjectKeyId) + `</ds:X509SKI>`,
		"subject of another certificate":       `<ds:X509SubjectName>CN=other</ds:X509SubjectName>`,
		"digest of another certificate":        `<dsig11:X509Digest Algorithm="` + xmlsec.DigestSHA256 + `">` + b64(otherDigest[:]) + `</dsig11:X509Digest>`,
		"two leaves":                           certElement(other) + certElement(ca),
	}
	kp := xmlsec.KeyProvider{Signer: victimKey, Certificate: victim}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			doc := signEnveloped(t, `<r><a>signed</a></r>`, kp, xmlsec.SigRSASHA256)
			sig := setKeyInfo(t, doc, `<ds:X509Data>`+certElement(victim)+extra+`</ds:X509Data>`)
			if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{StrictX509Data: true}); !errors.Is(err, xmlsec.ErrUnsupportedKeyInfo) {
				t.Fatalf("got %v", err)
			}
		})
	}
	// The same KeyInfo without the extra element verifies.
	doc := signEnveloped(t, `<r><a>signed</a></r>`, kp, xmlsec.SigRSASHA256)
	sig := setKeyInfo(t, doc, `<ds:X509Data>`+certElement(victim)+certElement(ca)+`</ds:X509Data>`)
	if cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{}); err != nil || !cov.Certificate.Equal(victim) {
		t.Fatalf("control: %v", err)
	}
}

// ResolveKeyName, ResolveX509 and ResolveKeyInfoURI run before the
// signature is verified, on names and URIs an attacker chose. None is
// called for a message whose SignatureMethod or DigestMethod the allow-lists
// refuse, nor for a key that is pinned.
func TestKeyResolversNotCalledBeforeAllowLists(t *testing.T) {
	kp := keyPair(t, rsaKey(t))
	calls := 0
	opts := dsig.VerifyOptions{
		ResolveKeyName: func(string) (*x509.Certificate, crypto.PublicKey, error) { calls++; return kp.Certificate, nil, nil },
		ResolveX509:    func(dsig.X509Identifier) (*x509.Certificate, error) { calls++; return kp.Certificate, nil },
		ResolveKeyInfoURI: func(uri string) ([]byte, error) {
			calls++
			if strings.HasSuffix(uri, ".cer") {
				return kp.Certificate.Raw, nil
			}
			return []byte(`<ds:KeyInfo xmlns:ds="` + xmlsec.NSDSig + `"><ds:KeyName>k</ds:KeyName></ds:KeyInfo>`), nil
		},
	}
	keyInfos := map[string]string{
		"KeyName":          `<ds:KeyName>k</ds:KeyName>`,
		"X509SubjectName":  `<ds:X509Data><ds:X509SubjectName>CN=k</ds:X509SubjectName></ds:X509Data>`,
		"KeyInfoReference": `<dsig11:KeyInfoReference URI="https://attacker.example/ki.xml"/>`,
		"RetrievalMethod":  `<ds:RetrievalMethod URI="https://attacker.example/k.cer" Type="` + xmlsec.NSDSig + `rawX509Certificate"/>`,
	}
	restrict := map[string]func(o *dsig.VerifyOptions){
		"signature algorithm":    func(o *dsig.VerifyOptions) { o.AllowedSignatureAlgorithms = []string{xmlsec.SigECDSASHA256} },
		"digest algorithm":       func(o *dsig.VerifyOptions) { o.AllowedDigestAlgorithms = []string{xmlsec.DigestSHA512} },
		"not in the default set": nil,
	}
	for kiName, ki := range keyInfos {
		for rName, r := range restrict {
			t.Run(kiName+", "+rName, func(t *testing.T) {
				alg := xmlsec.SigRSASHA256
				if r == nil {
					alg = xmlsec.SigRSASHA224 // outside the default set
				}
				doc := signEnveloped(t, `<r><a>signed</a></r>`, kp, alg)
				sig := setKeyInfo(t, doc, ki)
				o := opts
				if r != nil {
					r(&o)
				}
				calls = 0
				if _, err := dsig.Verify(doc, sig, o); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) || calls != 0 {
					t.Fatalf("got %v after %d resolver calls", err, calls)
				}
				// Allowed, the same resolver resolves it: the refusal above
				// came first, not from the resolver.
				o = opts
				o.AllowedSignatureAlgorithms = []string{alg}
				if _, err := dsig.Verify(doc, sig, o); err != nil || calls == 0 {
					t.Fatalf("allowed: %v after %d resolver calls", err, calls)
				}
				calls = 0
				o.Certificate = kp.Certificate
				if _, err := dsig.Verify(doc, sig, o); err != nil || calls != 0 {
					t.Fatalf("pinned: %v after %d resolver calls", err, calls)
				}
			})
		}
	}
}
