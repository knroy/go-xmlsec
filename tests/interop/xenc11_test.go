//go:build interop

package interop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
	"github.com/knroy/go-xmlsec/xenc"
)

// encryptWithEK encrypts the element named local in src under ek and
// places ek in EncryptedData/ds:KeyInfo, where xmlsec1 and Santuario look
// for it.
func encryptWithEK(t *testing.T, src, local string, ek *xenc.EncryptedKey, opts xenc.EncryptOptions) []byte {
	t.Helper()
	doc := parse(t, []byte(src))
	var target *xdm.Node
	xmltree.Walk(doc, func(e *xdm.Node) {
		if target == nil && e.Name.Local == local {
			target = e
		}
	})
	encrypted, err := xenc.EncryptElement(doc, target, ek.SessionKey, opts)
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

// weDecrypt finds the EncryptedKey of the first EncryptedData in b with
// FindEncryptedKey, unwraps it with unwrap and returns the plaintext.
func weDecrypt(t *testing.T, b []byte, unwrap func(ek *xdm.Node) ([]byte, error)) []byte {
	t.Helper()
	doc := parse(t, b)
	ed := find(doc, xmlsec.NSXEnc, "EncryptedData")
	ek, err := xenc.FindEncryptedKey(ed)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	key, err := unwrap(ek)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	plain, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{AllowedDataAlgorithms: []string{xmlsec.EncAES128GCM}})
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

var ecdhCases = []struct {
	name   string
	curve  elliptic.Curve
	wrap   string
	digest string
}{
	{"P-256 kw-aes128 SHA-256", elliptic.P256(), xmlsec.KeyWrapAES128, xmlsec.DigestSHA256},
	{"P-384 kw-aes192 SHA-384", elliptic.P384(), xmlsec.KeyWrapAES192, xmlsec.DigestSHA384},
	{"P-521 kw-aes256 SHA-512", elliptic.P521(), xmlsec.KeyWrapAES256, xmlsec.DigestSHA512},
}

// ourECDH encrypts envelope's payload for kp's EC key by ECDH-ES,
// ConcatKDF and AES key wrap.
func ourECDH(t *testing.T, kp keypair, wrap, digest string) []byte {
	t.Helper()
	opts := xenc.EncryptOptions{
		DataAlgorithm:         xmlsec.EncAES128GCM,
		KeyTransportAlgorithm: wrap,
		KeyAgreementAlgorithm: xmlsec.KeyAgreementECDHES,
		DigestAlgorithm:       digest,
		Recipient:             kp.provider.Certificate,
	}
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	return encryptWithEK(t, envelope, "Payload", ek, opts)
}

// xmlsec1AgreementKeyData enables key agreement in xmlsec1, which 1.3 leaves
// off by default.
const xmlsec1AgreementKeyData = "agreement-method,enc-key,key-value,key-name,ec,x509"

// xmlsec1 and Santuario decrypt our ECDH-ES key agreement (XML Encryption
// 1.1 section 5.6.4, REQUIRED on P-256) on each NIST curve.
func TestReferenceImplementationsDecryptOurECDHES(t *testing.T) {
	for _, c := range ecdhCases {
		t.Run(c.name, func(t *testing.T) {
			k, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			kp := newKeypair(t, k)
			enc := tempFile(t, "enc.xml", ourECDH(t, kp, c.wrap, c.digest))

			out := filepath.Join(t.TempDir(), "xmlsec1.xml")
			run(t, "--decrypt", "--enabled-key-data", xmlsec1AgreementKeyData,
				"--privkey-pem", kp.keyPEM+","+kp.certPEM, "--output", out, enc)
			assertDecryptedEnvelope(t, readFile(t, out))

			out = filepath.Join(t.TempDir(), "santuario.xml")
			mustSantuario(t, "decrypt", enc, kp.keyPEM, out)
			assertDecryptedEnvelope(t, readFile(t, out))
		})
	}
}

// We decrypt Santuario's ECDH-ES: P-256, ConcatKDF with SHA-256, kw-aes128.
func TestWeDecryptSantuarioECDHES(t *testing.T) {
	k := ecKey(t)
	kp := newKeypair(t, k)
	out := filepath.Join(t.TempDir(), "out.xml")
	mustSantuario(t, "encrypt-ecdh", tempFile(t, "in.xml", []byte(envelope)), kp.certPEM, "Payload", out)
	priv, err := k.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	plain := weDecrypt(t, readFile(t, out), func(ek *xdm.Node) ([]byte, error) {
		return xenc.DecryptAgreedKey(ek, priv, xenc.DecryptOptions{AllowedKeyWrapAlgorithms: []string{xmlsec.KeyWrapAES128}, AllowedKeyAgreementAlgorithms: []string{xmlsec.KeyAgreementECDHES}, AllowedDigestAlgorithms: []string{xmlsec.DigestSHA256}})
	})
	if !bytes.Contains(plain, []byte(">hello</p:Payload>")) {
		t.Fatalf("plaintext %s", plain)
	}
}

// We decrypt xmlsec1's ECDH-ES. xmlsec1 takes the originator key from the
// keys manager, by the template's ds:KeyName, rather than generating one,
// and writes its public key into the empty ds:KeyValue beside the name. It
// refuses an empty ConcatKDF OtherInfo, so AlgorithmID carries an octet.
func TestWeDecryptXmlsec1ECDHES(t *testing.T) {
	recipient := newKeypair(t, ecKey(t))
	originator := newKeypair(t, ecKey(t))
	tmpl := `<xenc:EncryptedData xmlns:xenc="` + xmlsec.NSXEnc + `" Type="` + xenc.TypeElement + `">` +
		`<xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128GCM + `"/>` +
		`<ds:KeyInfo xmlns:ds="` + xmlsec.NSDSig + `"><xenc:EncryptedKey>` +
		`<xenc:EncryptionMethod Algorithm="` + xmlsec.KeyWrapAES128 + `"/>` +
		`<ds:KeyInfo><xenc:AgreementMethod Algorithm="` + xmlsec.KeyAgreementECDHES + `">` +
		`<xenc11:KeyDerivationMethod xmlns:xenc11="` + xmlsec.NSXEnc11 + `" Algorithm="` + xmlsec.KeyDerivationConcatKDF + `">` +
		`<xenc11:ConcatKDFParams AlgorithmID="0001" PartyUInfo="" PartyVInfo=""><ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"/></xenc11:ConcatKDFParams>` +
		`</xenc11:KeyDerivationMethod>` +
		`<xenc:OriginatorKeyInfo><ds:KeyName>originator</ds:KeyName><ds:KeyValue/></xenc:OriginatorKeyInfo>` +
		`<xenc:RecipientKeyInfo><ds:KeyName>recipient</ds:KeyName></xenc:RecipientKeyInfo>` +
		`</xenc:AgreementMethod></ds:KeyInfo>` +
		`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>` +
		`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>`
	out := filepath.Join(t.TempDir(), "out.xml")
	run(t, "--encrypt", "--enabled-key-data", xmlsec1AgreementKeyData, "--session-key", "aes-128",
		"--privkey-pem:originator", originator.keyPEM,
		"--pubkey-cert-pem:recipient", recipient.certPEM,
		"--xml-data", tempFile(t, "data.xml", []byte(envelope)),
		"--node-name", "urn:example:p:Payload",
		"--output", out, tempFile(t, "tmpl.xml", []byte(tmpl)))
	priv, err := recipient.provider.Signer.(*ecdsa.PrivateKey).ECDH()
	if err != nil {
		t.Fatal(err)
	}
	plain := weDecrypt(t, readFile(t, out), func(ek *xdm.Node) ([]byte, error) {
		return xenc.DecryptAgreedKey(ek, priv, xenc.DecryptOptions{})
	})
	if !bytes.Contains(plain, []byte(">hello</p:Payload>")) {
		t.Fatalf("plaintext %s", plain)
	}
}

// kekFile writes a fresh AES key of n octets and returns it and its path.
func kekFile(t *testing.T, n int) ([]byte, string) {
	t.Helper()
	kek := make([]byte, n)
	rand.Read(kek)
	return kek, tempFile(t, "kek.bin", kek)
}

// xmlsec1 and Santuario unwrap our AES key wrap (section 5.7.2, kw-aes128
// and kw-aes256 REQUIRED) under a shared KEK, which xmlsec1 finds by the
// ds:KeyName our EncryptedKey carries.
func TestReferenceImplementationsDecryptOurKeyWrap(t *testing.T) {
	for _, wrap := range []string{xmlsec.KeyWrapAES128, xmlsec.KeyWrapAES192, xmlsec.KeyWrapAES256} {
		t.Run(wrap, func(t *testing.T) {
			size := map[string]int{xmlsec.KeyWrapAES128: 16, xmlsec.KeyWrapAES192: 24, xmlsec.KeyWrapAES256: 32}[wrap]
			kek, kekPath := kekFile(t, size)
			opts := xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: wrap, KeyEncryptionKey: kek}
			ek, err := xenc.GenerateEncryptedKey(opts)
			if err != nil {
				t.Fatal(err)
			}
			name := xmltree.Element(nil, "ds", xmlsec.NSDSig, "KeyName")
			name.AddNamespace("ds", xmlsec.NSDSig)
			xmltree.Text(name, "kek")
			if err := ek.SetKeyInfo(name); err != nil {
				t.Fatal(err)
			}
			enc := tempFile(t, "enc.xml", encryptWithEK(t, envelope, "Payload", ek, opts))

			out := filepath.Join(t.TempDir(), "xmlsec1.xml")
			run(t, "--decrypt", "--aeskey:kek", kekPath, "--output", out, enc)
			assertDecryptedEnvelope(t, readFile(t, out))

			out = filepath.Join(t.TempDir(), "santuario.xml")
			mustSantuario(t, "decrypt-kw", enc, kekPath, out)
			assertDecryptedEnvelope(t, readFile(t, out))
		})
	}
}

// We unwrap Santuario's and xmlsec1's AES key wrap.
func TestWeDecryptTheirKeyWrap(t *testing.T) {
	for _, n := range []int{16, 32} {
		wrap := map[int]string{16: xmlsec.KeyWrapAES128, 32: xmlsec.KeyWrapAES256}[n]
		t.Run(wrap, func(t *testing.T) {
			kek, kekPath := kekFile(t, n)
			unwrap := func(ek *xdm.Node) ([]byte, error) {
				return xenc.UnwrapEncryptedKey(ek, kek, xenc.DecryptOptions{AllowedKeyWrapAlgorithms: []string{wrap}})
			}

			out := filepath.Join(t.TempDir(), "santuario.xml")
			mustSantuario(t, "encrypt-kw", tempFile(t, "in.xml", []byte(envelope)), kekPath, "Payload", out)
			if plain := weDecrypt(t, readFile(t, out), unwrap); !bytes.Contains(plain, []byte(">hello</p:Payload>")) {
				t.Fatalf("Santuario plaintext %s", plain)
			}

			tmpl := `<xenc:EncryptedData xmlns:xenc="` + xmlsec.NSXEnc + `" Type="` + xenc.TypeElement + `">` +
				`<xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128GCM + `"/>` +
				`<ds:KeyInfo xmlns:ds="` + xmlsec.NSDSig + `"><xenc:EncryptedKey>` +
				`<xenc:EncryptionMethod Algorithm="` + wrap + `"/><ds:KeyInfo><ds:KeyName>kek</ds:KeyName></ds:KeyInfo>` +
				`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>` +
				`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>`
			out = filepath.Join(t.TempDir(), "xmlsec1.xml")
			run(t, "--encrypt", "--session-key", "aes-128", "--aeskey:kek", kekPath,
				"--xml-data", tempFile(t, "data.xml", []byte(envelope)),
				"--node-name", "urn:example:p:Payload",
				"--output", out, tempFile(t, "tmpl.xml", []byte(tmpl)))
			if plain := weDecrypt(t, readFile(t, out), unwrap); !bytes.Contains(plain, []byte(">hello</p:Payload>")) {
				t.Fatalf("xmlsec1 plaintext %s", plain)
			}
		})
	}
}

// Section 4.5.3.1: an element in no namespace under a default namespace
// stays in no namespace after xmlsec1 and Santuario decrypt and replace it.
func TestDecryptReplaceKeepsNoNamespace(t *testing.T) {
	const src = `<Document xmlns="urn:example:d"><ToBeEncrypted xmlns=""><c>v</c></ToBeEncrypted><after/></Document>`
	kp := newKeypair(t, rsaKey(t))
	opts := encOpts
	opts.Recipient = kp.provider.Certificate
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	enc := tempFile(t, "enc.xml", encryptWithEK(t, src, "ToBeEncrypted", ek, opts))
	check := func(who string, b []byte) {
		doc := parse(t, b)
		var names []string
		xmltree.Walk(doc, func(e *xdm.Node) { names = append(names, "{"+e.Name.URI+"}"+e.Name.Local) })
		want := "{urn:example:d}Document {}ToBeEncrypted {}c {urn:example:d}after"
		if got := strings.Join(names, " "); got != want {
			t.Errorf("%s: %s, want %s\n%s", who, got, want, b)
		}
	}
	out := filepath.Join(t.TempDir(), "xmlsec1.xml")
	run(t, "--decrypt", "--privkey-pem", kp.keyPEM+","+kp.certPEM, "--output", out, enc)
	check("xmlsec1", readFile(t, out))
	out = filepath.Join(t.TempDir(), "santuario.xml")
	mustSantuario(t, "decrypt", enc, kp.keyPEM, out)
	check("Santuario", readFile(t, out))
}

// wss4jMessage builds a WS-Security message for recipient: its certificate
// as a binary security token, and an EncryptedKey naming it and listing
// dataID. encrypt then encrypts part of doc under the session key.
func wss4jMessage(t *testing.T, recipient keypair, dataID string,
	encrypt func(doc, security *xdm.Node, key []byte, opts xenc.EncryptOptions) ([]byte, error)) []byte {
	t.Helper()
	doc := parse(t, []byte(envelope))
	hdr, err := wss.NewHeader(doc, xmlsec.NSSOAP12, "", true)
	if err != nil {
		t.Fatal(err)
	}
	tokenID, err := hdr.AddBinarySecurityToken(recipient.provider.Certificate, nil, xmlsec.BSTValueTypeX509v3)
	if err != nil {
		t.Fatal(err)
	}
	opts := encOpts
	opts.Recipient = recipient.provider.Certificate
	opts.DataID = dataID
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	str, err := wss.NewSecurityTokenReference(doc, tokenID, xmlsec.BSTValueTypeX509v3)
	if err != nil {
		t.Fatal(err)
	}
	if err := ek.SetKeyInfo(str); err != nil {
		t.Fatal(err)
	}
	if err := ek.AddDataReference(dataID); err != nil {
		t.Fatal(err)
	}
	if err := hdr.Append(ek.Element); err != nil {
		t.Fatal(err)
	}
	encrypted, err := encrypt(doc, hdr.Element(), ek.SessionKey, opts)
	if err != nil {
		t.Fatal(err)
	}
	return encrypted
}

// WSS4J decrypts a header block we encrypted as a wsse11:EncryptedHeader
// (WS-Security 1.1.1 section 9.4.3), and the SOAP Body content we
// encrypted with Type Content, each referenced from the EncryptedKey.
func TestWSS4JDecryptsOurEncryptedHeaderAndContent(t *testing.T) {
	recipient := newKeypair(t, rsaKey(t))
	for name, c := range map[string]struct {
		encrypt func(doc, security *xdm.Node, key []byte, opts xenc.EncryptOptions) ([]byte, error)
		hidden  string
		want    []string
	}{
		"EncryptedHeader": {func(doc, security *xdm.Node, key []byte, opts xenc.EncryptOptions) ([]byte, error) {
			return xenc.EncryptHeader(doc, find(doc, "urn:example:eb", "Messaging"), security, key, opts)
		}, "MessageId", []string{"<eb:Messaging", "<eb:MessageId>m1</eb:MessageId>"}},
		"Body content": {func(doc, _ *xdm.Node, key []byte, opts xenc.EncryptOptions) ([]byte, error) {
			return xenc.EncryptContent(doc, find(doc, xmlsec.NSSOAP12, "Body"), key, opts)
		}, ">hello<", []string{">hello</p:Payload>"}},
	} {
		t.Run(name, func(t *testing.T) {
			encrypted := wss4jMessage(t, recipient, "ED-1", c.encrypt)
			if strings.Contains(string(encrypted), c.hidden) {
				t.Fatalf("not encrypted:\n%s", encrypted)
			}
			out, err := santuario(t, "wss4j-decrypt", tempFile(t, "soap.xml", encrypted), recipient.keyPEM, recipient.certPEM)
			if err != nil {
				t.Fatalf("WSS4J could not decrypt: %v\n%s\n%s", err, out, encrypted)
			}
			for _, want := range append([]string{"action 4\n"}, c.want...) {
				if !strings.Contains(string(out), want) {
					t.Errorf("WSS4J output lacks %q:\n%s", want, out)
				}
			}
		})
	}
}
