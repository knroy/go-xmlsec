//go:build interop

package interop

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
	"github.com/knroy/go-xmlsec/xenc"
)

// tool returns the path of a reference implementation's command. It skips
// the test when the command is absent, unless GOXMLSEC_REQUIRE_INTEROP is
// set, as tests/interop.sh and CI set it: a differential that skips in the
// one place it is meant to run is a pass that checked nothing.
func tool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		if os.Getenv("GOXMLSEC_REQUIRE_INTEROP") != "" {
			t.Fatalf("%s is required but not on the PATH", name)
		}
		t.Skipf("%s not on the PATH; run tests/interop.sh", name)
	}
	return p
}

// run executes xmlsec1 and fails the test with its output on error. args[0]
// is the command, such as --verify.
//
// --lax-key-search restores the pre-1.3 behaviour of using a key loaded on
// the command line when KeyInfo does not name it; 1.3 otherwise reports
// KEY-NOT-FOUND for a directly supplied key.
func run(t *testing.T, args ...string) []byte {
	t.Helper()
	out, err := runErr(t, args...)
	if err != nil {
		t.Fatalf("xmlsec1 %v: %v\n%s", args, err, out)
	}
	return out
}

func runErr(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	args = append([]string{args[0], "--lax-key-search"}, args[1:]...)
	cmd := exec.Command(tool(t, "xmlsec1"), args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.Bytes(), err
}

type keypair struct {
	provider xmlsec.KeyProvider
	keyPEM   string // path
	certPEM  string // path
}

func newKeypair(t *testing.T, signer crypto.Signer) keypair {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go-xmlsec interop"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	kp := keypair{
		provider: xmlsec.KeyProvider{Signer: signer, Certificate: cert},
		keyPEM:   filepath.Join(dir, "key.pem"),
		certPEM:  filepath.Join(dir, "cert.pem"),
	}
	write(t, kp.keyPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
	write(t, kp.certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return kp
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func tempFile(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	write(t, p, b)
	return p
}

func parse(t *testing.T, b []byte) *xdm.Node {
	t.Helper()
	tree, err := xmlsec.Parse(b)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	return tree.Root
}

func find(doc *xdm.Node, uri, local string) *xdm.Node {
	var found *xdm.Node
	xmltree.Walk(doc, func(e *xdm.Node) {
		if found == nil && e.IsElement(uri, local) {
			found = e
		}
	})
	return found
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// --- signatures ---------------------------------------------------------------

const metadata = `<smp:SignedServiceMetadata xmlns:smp="urn:example:smp" xmlns:unused="urn:example:unused">` +
	`<smp:ServiceMetadata><smp:Endpoint a="1">https://example.com/</smp:Endpoint></smp:ServiceMetadata>` +
	`</smp:SignedServiceMetadata>`

var sigCases = []struct {
	name   string
	key    func(*testing.T) crypto.Signer
	sigAlg string
	c14n   c14n.Algorithm
}{
	{"rsa-sha256 inclusive", func(t *testing.T) crypto.Signer { return rsaKey(t) }, xmlsec.SigRSASHA256, c14n.Inclusive10},
	{"rsa-sha256 exclusive", func(t *testing.T) crypto.Signer { return rsaKey(t) }, xmlsec.SigRSASHA256, c14n.Exclusive10},
	{"ecdsa-sha256 inclusive", func(t *testing.T) crypto.Signer { return ecKey(t) }, xmlsec.SigECDSASHA256, c14n.Inclusive10},
}

// xmlsec1 accepts our enveloped signatures, with the certificate carried in
// ds:X509Data and trusted as a root.
func TestXmlsec1VerifiesOurEnvelopedSignature(t *testing.T) {
	for _, c := range sigCases {
		t.Run(c.name, func(t *testing.T) {
			kp := newKeypair(t, c.key(t))
			signed, err := dsig.SignEnveloped(parse(t, []byte(metadata)), kp.provider, dsig.SignOptions{
				SignatureAlgorithm:        c.sigAlg,
				CanonicalizationAlgorithm: string(c.c14n),
				References: []dsig.Reference{{
					URI:             "",
					DigestAlgorithm: xmlsec.DigestSHA256,
					Transforms: []dsig.TransformSpec{
						{Algorithm: xmlsec.TransformEnvelopedSignature},
						{Algorithm: string(c.c14n)},
					},
				}},
				KeyInfo: dsig.KeyInfoX509Data,
			})
			if err != nil {
				t.Fatal(err)
			}
			run(t, "--verify", "--trusted-pem", kp.certPEM, tempFile(t, "signed.xml", signed))

			// The control: the harness must be able to fail.
			tampered := bytes.Replace(signed, []byte("example.com"), []byte("evil.com"), 1)
			if out, err := runErr(t, "--verify", "--trusted-pem", kp.certPEM, tempFile(t, "tampered.xml", tampered)); err == nil {
				t.Fatalf("xmlsec1 accepted a tampered document:\n%s", out)
			}
		})
	}
}

// We accept enveloped signatures made by xmlsec1.
func TestWeVerifyXmlsec1EnvelopedSignature(t *testing.T) {
	for _, c := range sigCases {
		t.Run(c.name, func(t *testing.T) {
			kp := newKeypair(t, c.key(t))
			tmpl := `<smp:SignedServiceMetadata xmlns:smp="urn:example:smp" xmlns:unused="urn:example:unused">` +
				`<smp:ServiceMetadata><smp:Endpoint a="1">https://example.com/</smp:Endpoint></smp:ServiceMetadata>` +
				`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>` +
				`<ds:CanonicalizationMethod Algorithm="` + string(c.c14n) + `"/>` +
				`<ds:SignatureMethod Algorithm="` + c.sigAlg + `"/>` +
				`<ds:Reference URI=""><ds:Transforms>` +
				`<ds:Transform Algorithm="` + xmlsec.TransformEnvelopedSignature + `"/>` +
				`<ds:Transform Algorithm="` + string(c.c14n) + `"/>` +
				`</ds:Transforms><ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"/><ds:DigestValue/></ds:Reference>` +
				`</ds:SignedInfo><ds:SignatureValue/>` +
				`<ds:KeyInfo><ds:X509Data><ds:X509Certificate/></ds:X509Data></ds:KeyInfo>` +
				`</ds:Signature></smp:SignedServiceMetadata>`
			out := filepath.Join(t.TempDir(), "out.xml")
			run(t, "--sign", "--privkey-pem", kp.keyPEM+","+kp.certPEM, "--output", out, tempFile(t, "tmpl.xml", []byte(tmpl)))
			signed, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			doc := parse(t, signed)
			cov, err := dsig.Verify(doc, find(doc, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{
				AllowedSignatureAlgorithms:        []string{c.sigAlg},
				AllowedCanonicalizationAlgorithms: []string{string(c.c14n)},
			})
			if err != nil {
				t.Fatalf("%v\n%s", err, signed)
			}
			if !cov.WholeDocumentSigned || cov.KeyInfoForm != dsig.KeyInfoX509Data || !cov.Certificate.Equal(kp.provider.Certificate) {
				t.Fatalf("coverage %+v", cov)
			}
		})
	}
}

const envelope = `<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="urn:example:eb">` +
	`<S:Header><eb:Messaging><eb:MessageId>m1</eb:MessageId></eb:Messaging></S:Header>` +
	`<S:Body><p:Payload xmlns:p="urn:example:p">hello</p:Payload></S:Body></S:Envelope>`

// xmlsec1 has no notion of wsu:Id, so each signed element is registered with
// --id-attr. It matches the attribute by local name.
var idAttrs = []string{
	"--id-attr:Id", "urn:example:eb:Messaging",
	"--id-attr:Id", xmlsec.NSSOAP12 + ":Body",
}

// xmlsec1 accepts our detached WS-Security signature over #id references,
// with an InclusiveNamespaces prefix list. The key is supplied directly,
// since xmlsec1 does not resolve a wsse:SecurityTokenReference.
func TestXmlsec1VerifiesOurDetachedSignature(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	doc := parse(t, []byte(envelope))
	env := xmltree.DocumentElement(doc)
	msgID, err := wss.AssignID(doc, env.ChildElements()[0].ChildElements()[0])
	if err != nil {
		t.Fatal(err)
	}
	bodyID, err := wss.AssignID(doc, env.ChildElements()[1])
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := wss.NewHeader(doc, xmlsec.NSSOAP12, "", true)
	if err != nil {
		t.Fatal(err)
	}
	exc := []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10), InclusiveNamespacePrefixes: []string{"S"}}}
	sig, err := dsig.Sign(doc, kp.provider, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{
			{URI: "#" + msgID, Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "#" + bodyID, Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
		},
		KeyInfo: dsig.KeyInfoNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := hdr.Append(sig); err != nil {
		t.Fatal(err)
	}
	signed, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"--verify", "--pubkey-cert-pem", kp.certPEM}, idAttrs...)
	run(t, append(args, tempFile(t, "signed.xml", signed))...)
}

// We accept a detached signature over #id references made by xmlsec1.
func TestWeVerifyXmlsec1DetachedSignature(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	exc := string(c14n.Exclusive10)
	ref := func(id string) string {
		return `<ds:Reference URI="#` + id + `"><ds:Transforms><ds:Transform Algorithm="` + exc + `"/></ds:Transforms>` +
			`<ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"/><ds:DigestValue/></ds:Reference>`
	}
	tmpl := `<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="urn:example:eb" xmlns:wsu="` + xmlsec.NSWSU + `">` +
		`<S:Header><eb:Messaging wsu:Id="msg"><eb:MessageId>m1</eb:MessageId></eb:Messaging>` +
		`<wsse:Security xmlns:wsse="` + xmlsec.NSWSSE + `">` +
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>` +
		`<ds:CanonicalizationMethod Algorithm="` + exc + `"/>` +
		`<ds:SignatureMethod Algorithm="` + xmlsec.SigRSASHA256 + `"/>` +
		ref("msg") + ref("body") +
		`</ds:SignedInfo><ds:SignatureValue/></ds:Signature></wsse:Security></S:Header>` +
		`<S:Body wsu:Id="body"><p:Payload xmlns:p="urn:example:p">hello</p:Payload></S:Body></S:Envelope>`
	out := filepath.Join(t.TempDir(), "out.xml")
	args := append([]string{"--sign", "--privkey-pem", kp.keyPEM, "--output", out}, idAttrs...)
	run(t, append(args, tempFile(t, "tmpl.xml", []byte(tmpl)))...)
	signed, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	doc := parse(t, signed)
	cov, err := dsig.Verify(doc, find(doc, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{
		Certificate:                       kp.provider.Certificate,
		AllowedSignatureAlgorithms:        []string{xmlsec.SigRSASHA256},
		AllowedDigestAlgorithms:           []string{xmlsec.DigestSHA256},
		AllowedCanonicalizationAlgorithms: []string{exc},
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, signed)
	}
	if !cov.Covers("msg", "body") {
		t.Fatalf("coverage %v", cov.SignedElementIDs)
	}
}

// --- encryption ---------------------------------------------------------------

var encOpts = xenc.EncryptOptions{
	DataAlgorithm:         xmlsec.EncAES128GCM,
	KeyTransportAlgorithm: xmlsec.KeyTransportRSAOAEP,
	MGFAlgorithm:          xmlsec.MGF1SHA256,
	DigestAlgorithm:       xmlsec.DigestSHA256,
}

// xmlsec1 decrypts our element encryption: AES-128-GCM under an RSA-OAEP
// key with explicit SHA-256 MGF and digest. xmlsec1 finds the key through
// ds:KeyInfo, so the test places the EncryptedKey there; this library leaves
// that composition to the caller.
func TestXmlsec1DecryptsOurEncryption(t *testing.T) {
	key := rsaKey(t)
	kp := newKeypair(t, key)
	withKey := encryptWithKeyInfo(t, kp)
	out := filepath.Join(t.TempDir(), "out.xml")
	run(t, "--decrypt", "--privkey-pem", kp.keyPEM, "--output", out, tempFile(t, "enc.xml", withKey))
	decrypted, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	assertDecryptedEnvelope(t, decrypted)
}

// encryptWithKeyInfo encrypts envelope's payload for kp and places the
// EncryptedKey in EncryptedData/ds:KeyInfo, which is where both reference
// implementations look for it; this library leaves that composition to the
// caller.
func encryptWithKeyInfo(t *testing.T, kp keypair) []byte {
	t.Helper()
	opts := encOpts
	opts.Recipient = kp.provider.Certificate
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	doc := parse(t, []byte(envelope))
	body := xmltree.DocumentElement(doc).ChildElements()[1]
	payload := body.ChildElements()[0]
	encrypted, err := xenc.EncryptElement(doc, payload, ek.SessionKey, opts)
	if err != nil {
		t.Fatal(err)
	}

	edoc := parse(t, encrypted)
	ed := find(edoc, xmlsec.NSXEnc, "EncryptedData")
	ki := xmltree.Element(nil, "ds", xmlsec.NSDSig, "KeyInfo")
	ki.AddNamespace("ds", xmlsec.NSDSig)
	ki.AppendChild(ek.Element)
	// ds:KeyInfo belongs between EncryptionMethod and CipherData.
	ed.AppendChild(ki)
	ed.Children = []*xdm.Node{ed.Children[0], ki, ed.Children[1]}
	withKey, err := c14n.Bytes(edoc, c14n.Options{Algorithm: c14n.Inclusive10})
	if err != nil {
		t.Fatal(err)
	}
	return withKey
}

// assertDecryptedEnvelope checks a decrypted document equals envelope.
func assertDecryptedEnvelope(t *testing.T, decrypted []byte) {
	t.Helper()
	want, _ := c14n.Bytes(parse(t, []byte(envelope)), c14n.Options{Algorithm: c14n.Exclusive10})
	got, _ := c14n.Bytes(parse(t, decrypted), c14n.Options{Algorithm: c14n.Exclusive10})
	if !bytes.Equal(got, want) {
		t.Fatalf("decrypted document differs:\n%s\nwant\n%s", got, want)
	}
}

// We decrypt xmlsec1's element encryption with the same algorithms.
func TestWeDecryptXmlsec1Encryption(t *testing.T) {
	key := rsaKey(t)
	kp := newKeypair(t, key)
	tmpl := `<xenc:EncryptedData xmlns:xenc="` + xmlsec.NSXEnc + `" Type="` + xenc.TypeElement + `">` +
		`<xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128GCM + `"/>` +
		`<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
		`<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="` + xmlsec.KeyTransportRSAOAEP + `">` +
		`<ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"/>` +
		`<xenc11:MGF xmlns:xenc11="` + xmlsec.NSXEnc11 + `" Algorithm="` + xmlsec.MGF1SHA256 + `"/>` +
		`</xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey>` +
		`</ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>`
	out := filepath.Join(t.TempDir(), "out.xml")
	run(t, "--encrypt", "--pubkey-cert-pem", kp.certPEM, "--session-key", "aes-128",
		"--xml-data", tempFile(t, "data.xml", []byte(envelope)),
		"--node-name", "urn:example:p:Payload",
		"--output", out, tempFile(t, "tmpl.xml", []byte(tmpl)))
	encrypted, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	doc := parse(t, encrypted)
	sessionKey, err := xenc.DecryptEncryptedKey(find(doc, xmlsec.NSXEnc, "EncryptedKey"), key, xenc.DecryptOptions{AllowedKeyTransportAlgorithms: []string{xmlsec.KeyTransportRSAOAEP}, AllowedMGFAlgorithms: []string{xmlsec.MGF1SHA256}, AllowedDigestAlgorithms: []string{xmlsec.DigestSHA256}})
	if err != nil {
		t.Fatalf("%v\n%s", err, encrypted)
	}
	plain, err := xenc.DecryptData(find(doc, xmlsec.NSXEnc, "EncryptedData"), sessionKey, xenc.DecryptOptions{AllowedDataAlgorithms: []string{xmlsec.EncAES128GCM}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plain, []byte(">hello</p:Payload>")) {
		t.Fatalf("plaintext %s", plain)
	}
}
