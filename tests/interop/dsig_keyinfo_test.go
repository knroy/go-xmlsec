//go:build interop

//lint:file-ignore SA1019 crypto/dsa generates the (2048, 256) key Santuario signs dsa-sha256 with.

package interop

import (
	"bytes"
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
)

// chain is a root CA, an intermediate CA and a leaf, each as a PEM file.
// The names carry an escaped comma and, in the leaf, an emailAddress, so
// that each implementation's distinguished name strings are exercised.
type chain struct {
	root, inter, leaf          *x509.Certificate
	leafKey                    *rsa.PrivateKey
	rootPEM, interPEM, leafPEM string
	keyPEM                     string // the leaf's PKCS#8 key
}

// leafSerial is distinctive enough to find and replace in a document.
const leafSerial = 4242424242

func newChain(t *testing.T) chain {
	t.Helper()
	dir := t.TempDir()
	org := []string{"Example, Inc."}
	issue := func(tmpl, parent *x509.Certificate, pub any, signer any, name string) (*x509.Certificate, string) {
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		write(t, p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		return c, p
	}
	ca := func(serial int64, cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn, Organization: org, Country: []string{"US"}},
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
	}
	var c chain
	rootKey, interKey := rsaKey(t), rsaKey(t)
	c.root, c.rootPEM = issue(ca(1, "go-xmlsec root"), nil, rootKey.Public(), rootKey, "root.pem")
	c.inter, c.interPEM = issue(ca(2, "go-xmlsec intermediate"), c.root, interKey.Public(), rootKey, "inter.pem")

	c.leafKey = rsaKey(t)
	spki, err := x509.MarshalPKIXPublicKey(c.leafKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	ski := sha1.Sum(spki) // Go generates a subject key identifier for CAs only
	c.leaf, c.leafPEM = issue(&x509.Certificate{
		SerialNumber: big.NewInt(leafSerial),
		Subject: pkix.Name{CommonName: "go-xmlsec leaf", OrganizationalUnit: []string{"Signing"}, Organization: org, Country: []string{"US"},
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "leaf@example.com"}}},
		SubjectKeyId: ski[:],
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, c.inter, c.leafKey.Public(), interKey, "leaf.pem")

	pk, err := x509.MarshalPKCS8PrivateKey(c.leafKey)
	if err != nil {
		t.Fatal(err)
	}
	c.keyPEM = filepath.Join(dir, "leaf.key")
	write(t, c.keyPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
	return c
}

// checkChainCoverage checks what Verify reports of a signature by c's leaf
// whose ds:X509Data carries the leaf and the intermediate.
func checkChainCoverage(t *testing.T, c chain, cov *dsig.Coverage, keyName string, signed []byte) {
	t.Helper()
	switch {
	case !cov.WholeDocumentSigned:
		t.Errorf("whole document not reported as signed")
	case cov.KeyInfoForm != dsig.KeyInfoX509Data:
		t.Errorf("KeyInfoForm %v, want KeyInfoX509Data", cov.KeyInfoForm)
	case cov.Certificate == nil || !cov.Certificate.Equal(c.leaf):
		t.Errorf("signing certificate is not the leaf")
	case len(cov.Intermediates) != 1 || !cov.Intermediates[0].Equal(c.inter):
		t.Errorf("%d intermediates, want the intermediate CA", len(cov.Intermediates))
	case cov.KeyName != keyName:
		t.Errorf("KeyName %q, want %q", cov.KeyName, keyName)
	default:
		return
	}
	t.Logf("%s", signed)
}

// verifyWrongSerial replaces the leaf's serial in ds:X509IssuerSerial,
// which the signature does not cover: the descriptor then no longer
// describes the signing certificate, and Verify under StrictX509Data must
// refuse it. The control that the descriptors the peer wrote were really
// compared. By default a stale descriptor is ignored, as it selects
// nothing.
func verifyWrongSerial(t *testing.T, signed []byte) {
	t.Helper()
	serial := big.NewInt(leafSerial).String()
	if !bytes.Contains(signed, []byte(">"+serial+"<")) {
		t.Fatalf("no X509SerialNumber %s in\n%s", serial, signed)
	}
	doc := parse(t, bytes.Replace(signed, []byte(">"+serial+"<"), []byte(">4242424243<"), 1))
	sig := find(doc, xmlsec.NSDSig, "Signature")
	if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{StrictX509Data: true}); !errors.Is(err, xmlsec.ErrUnsupportedKeyInfo) {
		t.Fatalf("wrong X509SerialNumber: got %v, want ErrUnsupportedKeyInfo", err)
	}
	if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{}); err != nil {
		t.Fatalf("wrong X509SerialNumber, not strict: %v", err)
	}
}

// We verify Santuario's signature by a leaf whose ds:X509Data holds
// Santuario's own X509IssuerSerial, X509SKI, X509SubjectName and
// dsig11:X509Digest of it, the leaf and the intermediate, beside a
// ds:KeyName: every descriptor matches the leaf, with Santuario's DN strings.
func TestWeVerifySantuarioX509Chain(t *testing.T) {
	c := newChain(t)
	out := filepath.Join(t.TempDir(), "out.xml")
	mustSantuario(t, "sign-keyinfo", tempFile(t, "in.xml", []byte(metadata)), c.keyPEM, out, "signer", c.leafPEM, c.interPEM)
	signed := readFile(t, out)
	doc := parse(t, signed)
	cov, err := dsig.Verify(doc, find(doc, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{})
	if err != nil {
		t.Fatalf("%v\n%s", err, signed)
	}
	checkChainCoverage(t, c, cov, "signer", signed)
	verifyWrongSerial(t, signed)
}

// We verify xmlsec1's signature by a leaf, its template asking for a
// ds:KeyName and ds:X509Data children. xmlsec1 writes each child it is asked
// for once per certificate loaded with the key, so:
//   - "chain": only ds:X509Certificate, with the leaf and intermediate loaded:
//     the leaf is found and the intermediate reported;
//   - "descriptors": every descriptor and ds:X509Certificate, with the leaf
//     alone loaded: each descriptor is compared with the leaf, with xmlsec1's
//     DN strings;
//   - "descriptors of the chain": both at once, which xmlsec1 writes as a
//     descriptor of each kind for the leaf AND the intermediate.
func TestWeVerifyXmlsec1X509Chain(t *testing.T) {
	c := newChain(t)
	desc := `<ds:X509IssuerSerial/><ds:X509SKI/><ds:X509SubjectName/>` +
		`<dsig11:X509Digest xmlns:dsig11="` + xmlsec.NSDSig11 + `" Algorithm="` + xmlsec.DigestSHA256 + `"/>`
	t.Run("chain", func(t *testing.T) {
		signed := xmlsec1SignX509(t, c, "", c.leafPEM, c.interPEM)
		doc := parse(t, signed)
		cov, err := dsig.Verify(doc, find(doc, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{})
		if err != nil {
			t.Fatalf("%v\n%s", err, signed)
		}
		checkChainCoverage(t, c, cov, "signer", signed)
	})
	t.Run("descriptors", func(t *testing.T) {
		signed := xmlsec1SignX509(t, c, desc, c.leafPEM)
		for _, want := range []string{"X509IssuerName", "X509SKI", "X509SubjectName", "X509Digest"} {
			if !bytes.Contains(signed, []byte(want)) {
				t.Fatalf("xmlsec1 wrote no %s:\n%s", want, signed)
			}
		}
		doc := parse(t, signed)
		cov, err := dsig.Verify(doc, find(doc, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{})
		if err != nil {
			t.Fatalf("%v\n%s", err, signed)
		}
		if cov.KeyInfoForm != dsig.KeyInfoX509Data || !cov.Certificate.Equal(c.leaf) || cov.KeyName != "signer" || len(cov.Intermediates) != 0 {
			t.Fatalf("coverage %+v", cov)
		}
		verifyWrongSerial(t, signed)
	})
	t.Run("descriptors of the chain", func(t *testing.T) {
		signed := xmlsec1SignX509(t, c, desc, c.leafPEM, c.interPEM)
		doc := parse(t, signed)
		// xmlsec1 describes each certificate it carries, the intermediate
		// too; each descriptor must describe one of them.
		cov, err := dsig.Verify(doc, find(doc, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{})
		if err != nil {
			t.Fatalf("%v\n%s", err, signed)
		}
		checkChainCoverage(t, c, cov, "signer", signed)
		verifyWrongSerial(t, signed)
	})
}

// xmlsec1SignX509 has xmlsec1 sign metadata with c's leaf key, loaded with
// certs under the key name "signer", from a template whose ds:KeyInfo holds
// ds:KeyName and ds:X509Data with the children desc and ds:X509Certificate.
func xmlsec1SignX509(t *testing.T, c chain, desc string, certs ...string) []byte {
	t.Helper()
	exc := string(c14n.Exclusive10)
	tmpl := `<smp:SignedServiceMetadata xmlns:smp="urn:example:smp">` +
		`<smp:ServiceMetadata><smp:Endpoint a="1">https://example.com/</smp:Endpoint></smp:ServiceMetadata>` +
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>` +
		`<ds:CanonicalizationMethod Algorithm="` + exc + `"/>` +
		`<ds:SignatureMethod Algorithm="` + xmlsec.SigRSASHA256 + `"/>` +
		`<ds:Reference URI=""><ds:Transforms>` +
		`<ds:Transform Algorithm="` + xmlsec.TransformEnvelopedSignature + `"/>` +
		`<ds:Transform Algorithm="` + exc + `"/>` +
		`</ds:Transforms><ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"/><ds:DigestValue/></ds:Reference>` +
		`</ds:SignedInfo><ds:SignatureValue/>` +
		`<ds:KeyInfo><ds:KeyName/><ds:X509Data>` + desc +
		`<ds:X509Certificate/></ds:X509Data></ds:KeyInfo>` +
		`</ds:Signature></smp:SignedServiceMetadata>`
	out := filepath.Join(t.TempDir(), "out.xml")
	files := strings.Join(append([]string{c.keyPEM}, certs...), ",")
	run(t, "--sign", "--privkey-pem:signer", files, "--output", out, tempFile(t, "tmpl.xml", []byte(tmpl)))
	signed := readFile(t, out)
	if !bytes.Contains(signed, []byte(">signer</")) {
		t.Fatalf("xmlsec1 wrote no ds:KeyName:\n%s", signed)
	}
	return signed
}

// Santuario and xmlsec1 accept our signature whose ds:X509Data holds all
// four descriptors of the leaf, the leaf and its intermediate, beside a
// ds:KeyName: Santuario resolves the leaf from it, and xmlsec1 builds the
// path from the leaf through the intermediate to the trusted root.
func TestReferenceImplementationsVerifyOurX509Chain(t *testing.T) {
	c := newChain(t)
	exc := string(c14n.Exclusive10)
	signed, err := dsig.SignEnveloped(parse(t, []byte(metadata)), xmlsec.KeyProvider{Signer: c.leafKey, Certificate: c.leaf}, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: exc,
		References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
			{Algorithm: xmlsec.TransformEnvelopedSignature}, {Algorithm: exc}}}},
		KeyInfo:         dsig.KeyInfoX509Data,
		KeyName:         "signer",
		Chain:           []*x509.Certificate{c.inter},
		X509Descriptors: []dsig.X509Descriptor{dsig.X509IssuerSerial, dsig.X509SKI, dsig.X509SubjectName, dsig.X509Digest},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := tempFile(t, "signed.xml", signed)

	out, err := santuario(t, "verify-keyinfo", path, c.leafPEM)
	if err != nil {
		t.Fatalf("Santuario: %v\n%s\n%s", err, out, signed)
	}
	if !strings.Contains(string(out), "keyname signer\n") {
		t.Errorf("Santuario read no ds:KeyName: %s", out)
	}
	run(t, "--verify", "--trusted-pem", c.rootPEM, path)

	// The control: without the root trusted, xmlsec1 has no path.
	if out, err := runErr(t, "--verify", path); err == nil {
		t.Fatalf("xmlsec1 verified without a trust anchor:\n%s", out)
	}

	doc := parse(t, signed)
	cov, err := dsig.Verify(doc, find(doc, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{})
	if err != nil {
		t.Fatalf("we refuse our own: %v", err)
	}
	checkChainCoverage(t, c, cov, "signer", signed)
}

// We verify Santuario's signature whose ds:KeyInfo is only a
// ds:RetrievalMethod of Type X509Data to "#x509", a ds:X509Data with
// Id="x509" in a ds:Object of the signature: found only when the Id
// attribute is named in IDAttributes.
func TestWeVerifySantuarioRetrievalMethod(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	out := filepath.Join(t.TempDir(), "out.xml")
	mustSantuario(t, "sign-retrieval", tempFile(t, "in.xml", []byte(metadata)), kp.keyPEM, kp.certPEM, out)
	signed := readFile(t, out)
	if !bytes.Contains(signed, []byte("RetrievalMethod")) {
		t.Fatalf("no ds:RetrievalMethod:\n%s", signed)
	}
	doc := parse(t, signed)
	sig := find(doc, xmlsec.NSDSig, "Signature")
	if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{}); err == nil {
		t.Fatal("resolved #x509 without its Id attribute named")
	}
	cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{IDAttributes: []xdm.QName{dsig.IDAttrDSig}})
	if err != nil {
		t.Fatalf("%v\n%s", err, signed)
	}
	if !cov.WholeDocumentSigned || cov.KeyInfoForm != dsig.KeyInfoX509Data || !cov.Certificate.Equal(kp.provider.Certificate) {
		t.Fatalf("coverage %+v", cov)
	}
}

// sha224Cases are the SHA-224 signature methods, each with a SHA-224 digest.
var sha224Cases = []struct {
	name, sigAlg string
	key          func(*testing.T) keypair
}{
	{"rsa-sha224", xmlsec.SigRSASHA224, func(t *testing.T) keypair { return newKeypair(t, rsaKey(t)) }},
	{"ecdsa-sha224 P-256", xmlsec.SigECDSASHA224, func(t *testing.T) keypair { return newKeypair(t, ecKey(t)) }},
}

// Santuario and xmlsec1 accept our SHA-224 signatures.
func TestReferenceImplementationsVerifyOurSHA224(t *testing.T) {
	exc := string(c14n.Exclusive10)
	for _, c := range sha224Cases {
		t.Run(c.name, func(t *testing.T) {
			kp := c.key(t)
			signed, err := dsig.SignEnveloped(parse(t, []byte(metadata)), kp.provider, dsig.SignOptions{
				SignatureAlgorithm:        c.sigAlg,
				CanonicalizationAlgorithm: exc,
				References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA224, Transforms: []dsig.TransformSpec{
					{Algorithm: xmlsec.TransformEnvelopedSignature}, {Algorithm: exc}}}},
				KeyInfo: dsig.KeyInfoX509Data,
			})
			if err != nil {
				t.Fatal(err)
			}
			path := tempFile(t, "signed.xml", signed)
			mustSantuario(t, "verify", path, kp.certPEM)
			run(t, "--verify", "--trusted-pem", kp.certPEM, path)

			tampered := tempFile(t, "tampered.xml", bytes.Replace(signed, []byte("example.com"), []byte("evil.com"), 1))
			if out, err := santuario(t, "verify", tampered, kp.certPEM); err == nil {
				t.Fatalf("Santuario accepted a tampered document:\n%s", out)
			}
			if out, err := runErr(t, "--verify", "--trusted-pem", kp.certPEM, tampered); err == nil {
				t.Fatalf("xmlsec1 accepted a tampered document:\n%s", out)
			}
		})
	}
}

// verifyNamed verifies signed, refused under the default allow-lists and
// accepted with sigAlg and digestAlg named, and returns the coverage.
func verifyNamed(t *testing.T, signed []byte, sigAlg, digestAlg string) *dsig.Coverage {
	t.Helper()
	doc := parse(t, signed)
	sig := find(doc, xmlsec.NSDSig, "Signature")
	if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("default allow-lists: got %v, want ErrAlgorithmNotAllowed\n%s", err, signed)
	}
	cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{
		AllowedSignatureAlgorithms: []string{sigAlg},
		AllowedDigestAlgorithms:    []string{digestAlg},
	})
	if err != nil {
		t.Fatalf("named: %v\n%s", err, signed)
	}
	if !cov.WholeDocumentSigned {
		t.Fatalf("coverage %+v", cov)
	}
	tampered := parse(t, bytes.Replace(signed, []byte("example.com"), []byte("evil.com"), 1))
	if _, err := dsig.Verify(tampered, find(tampered, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{
		AllowedSignatureAlgorithms: []string{sigAlg},
		AllowedDigestAlgorithms:    []string{digestAlg},
	}); !errors.Is(err, xmlsec.ErrDigestMismatch) {
		t.Fatalf("tampered: got %v", err)
	}
	return cov
}

// We verify Santuario's and xmlsec1's SHA-224 signatures, once named in
// the allow-lists.
func TestWeVerifySHA224FromReferenceImplementations(t *testing.T) {
	exc := string(c14n.Exclusive10)
	for _, c := range sha224Cases {
		t.Run(c.name+" Santuario", func(t *testing.T) {
			kp := c.key(t)
			out := filepath.Join(t.TempDir(), "out.xml")
			mustSantuario(t, "sign-alg", tempFile(t, "in.xml", []byte(metadata)), kp.keyPEM, kp.certPEM, c.sigAlg, xmlsec.DigestSHA224, out)
			cov := verifyNamed(t, readFile(t, out), c.sigAlg, xmlsec.DigestSHA224)
			if !cov.Certificate.Equal(kp.provider.Certificate) {
				t.Fatal("wrong certificate")
			}
		})
		t.Run(c.name+" xmlsec1", func(t *testing.T) {
			kp := c.key(t)
			tmpl := `<smp:SignedServiceMetadata xmlns:smp="urn:example:smp">` +
				`<smp:ServiceMetadata><smp:Endpoint a="1">https://example.com/</smp:Endpoint></smp:ServiceMetadata>` +
				`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>` +
				`<ds:CanonicalizationMethod Algorithm="` + exc + `"/>` +
				`<ds:SignatureMethod Algorithm="` + c.sigAlg + `"/>` +
				`<ds:Reference URI=""><ds:Transforms>` +
				`<ds:Transform Algorithm="` + xmlsec.TransformEnvelopedSignature + `"/>` +
				`<ds:Transform Algorithm="` + exc + `"/>` +
				`</ds:Transforms><ds:DigestMethod Algorithm="` + xmlsec.DigestSHA224 + `"/><ds:DigestValue/></ds:Reference>` +
				`</ds:SignedInfo><ds:SignatureValue/>` +
				`<ds:KeyInfo><ds:X509Data><ds:X509Certificate/></ds:X509Data></ds:KeyInfo>` +
				`</ds:Signature></smp:SignedServiceMetadata>`
			out := filepath.Join(t.TempDir(), "out.xml")
			run(t, "--sign", "--privkey-pem", kp.keyPEM+","+kp.certPEM, "--output", out, tempFile(t, "tmpl.xml", []byte(tmpl)))
			cov := verifyNamed(t, readFile(t, out), c.sigAlg, xmlsec.DigestSHA224)
			if !cov.Certificate.Equal(kp.provider.Certificate) {
				t.Fatal("wrong certificate")
			}
		})
	}
}

// dsaPKCS8 writes k as a PKCS#8 "PRIVATE KEY", which Go cannot marshal
// for DSA and the JDK reads.
func dsaPKCS8(t *testing.T, k *dsa.PrivateKey) string {
	t.Helper()
	params, err := asn1.Marshal(struct{ P, Q, G *big.Int }{k.P, k.Q, k.G})
	if err != nil {
		t.Fatal(err)
	}
	x, err := asn1.Marshal(k.X)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}, Parameters: asn1.RawValue{FullBytes: params}}, x})
	if err != nil {
		t.Fatal(err)
	}
	return tempFile(t, "dsa.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// We verify Santuario's verify-only signatures, once named: dsa-sha256
// with a (2048, 256) key in ds:DSAKeyValue, and ecdsa-sha1.
func TestWeVerifySantuarioDSASHA256AndECDSASHA1(t *testing.T) {
	t.Run("dsa-sha256", func(t *testing.T) {
		k := new(dsa.PrivateKey)
		if err := dsa.GenerateParameters(&k.Parameters, rand.Reader, dsa.L2048N256); err != nil {
			t.Fatal(err)
		}
		if err := dsa.GenerateKey(k, rand.Reader); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "out.xml")
		mustSantuario(t, "sign-alg", tempFile(t, "in.xml", []byte(metadata)), dsaPKCS8(t, k), "-", xmlsec.SigDSASHA256, xmlsec.DigestSHA256, out)
		cov := verifyNamed(t, readFile(t, out), xmlsec.SigDSASHA256, xmlsec.DigestSHA256)
		pub, ok := cov.PublicKey.(*dsa.PublicKey)
		if cov.KeyInfoForm != dsig.KeyInfoKeyValue || !ok || pub.Y.Cmp(k.Y) != 0 {
			t.Fatalf("coverage %+v", cov)
		}
	})
	t.Run("ecdsa-sha1", func(t *testing.T) {
		kp := newKeypair(t, ecKey(t))
		out := filepath.Join(t.TempDir(), "out.xml")
		mustSantuario(t, "sign-alg", tempFile(t, "in.xml", []byte(metadata)), kp.keyPEM, kp.certPEM, xmlsec.SigECDSASHA1, xmlsec.DigestSHA256, out)
		cov := verifyNamed(t, readFile(t, out), xmlsec.SigECDSASHA1, xmlsec.DigestSHA256)
		if cov.KeyInfoForm != dsig.KeyInfoX509Data || !cov.Certificate.Equal(kp.provider.Certificate) {
			t.Fatalf("coverage %+v", cov)
		}
	})
}
