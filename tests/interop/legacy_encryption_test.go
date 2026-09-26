//go:build interop

package interop

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"path/filepath"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

// The legacy algorithms XML Encryption 1.1 requires, which this library
// decrypts only: xmlsec1 and Santuario encrypt with them, and we decrypt
// their output when, and only when, the allow-lists name every legacy
// algorithm involved.
var legacyCases = []struct {
	name, data, session, transport, digest string
}{
	{"aes128-cbc rsa-1_5", xmlsec.EncAES128CBC, "aes-128", xmlsec.KeyTransportRSA15, ""},
	{"aes256-cbc rsa-1_5", xmlsec.EncAES256CBC, "aes-256", xmlsec.KeyTransportRSA15, ""},
	{"tripledes-cbc rsa-1_5", xmlsec.EncTripleDESCBC, "des-192", xmlsec.KeyTransportRSA15, ""},
	{"aes128-cbc rsa-oaep-mgf1p", xmlsec.EncAES128CBC, "aes-128", xmlsec.KeyTransportRSAOAEPMGF1P, xmlsec.DigestSHA1},
	{"aes256-cbc rsa-oaep-mgf1p implicit digest", xmlsec.EncAES256CBC, "aes-256", xmlsec.KeyTransportRSAOAEPMGF1P, ""},
	{"tripledes-cbc rsa-oaep-mgf1p", xmlsec.EncTripleDESCBC, "des-192", xmlsec.KeyTransportRSAOAEPMGF1P, xmlsec.DigestSHA1},
}

// legacyTemplate is an xmlsec1 encryption template for data under the
// EncryptedKey method em.
func legacyTemplate(data, em string) string {
	return `<xenc:EncryptedData xmlns:xenc="` + xenc.NSXEnc + `" Type="` + xenc.TypeElement + `">` +
		`<xenc:EncryptionMethod Algorithm="` + data + `"/>` +
		`<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
		`<xenc:EncryptedKey>` + em + `<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey>` +
		`</ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>`
}

// legacyUnwrap recovers the session key of doc's EncryptedData, first
// checking that the default set refuses it, then naming the legacy
// algorithms.
func legacyUnwrap(t *testing.T, doc *xdm.Node, priv *rsa.PrivateKey, transport, data string) []byte {
	t.Helper()
	ek, ed := find(doc, xenc.NSXEnc, "EncryptedKey"), find(doc, xenc.NSXEnc, "EncryptedData")
	named := []string{transport}
	if transport == xmlsec.KeyTransportRSA15 {
		if _, err := xenc.DecryptEncryptedKeyPKCS1v15(ek, ed, priv, nil, nil); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
			t.Fatalf("default set: %v", err)
		}
		if _, err := xenc.DecryptEncryptedKeyPKCS1v15(ek, ed, priv, named, nil); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
			t.Fatalf("default data set: %v", err)
		}
		key, err := xenc.DecryptEncryptedKeyPKCS1v15(ek, ed, priv, named, []string{data})
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	if _, err := xenc.DecryptEncryptedKey(ek, priv, nil, nil, nil); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("default set: %v", err)
	}
	if _, err := xenc.DecryptEncryptedKey(ek, priv, named, nil, []string{xmlsec.DigestSHA1}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("default MGF set: %v", err)
	}
	key, err := xenc.DecryptEncryptedKey(ek, priv, named, []string{xmlsec.MGF1SHA1}, []string{xmlsec.DigestSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// legacyOpen decrypts doc's EncryptedData under key, refused by the
// default set, and checks the payload.
func legacyOpen(t *testing.T, doc *xdm.Node, key []byte, data string) {
	t.Helper()
	ed := find(doc, xenc.NSXEnc, "EncryptedData")
	if _, err := xenc.DecryptData(ed, key, nil); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("default data set: %v", err)
	}
	plain, err := xenc.DecryptData(ed, key, []string{data})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plain, []byte(">hello</p:Payload>")) {
		t.Fatalf("plaintext %s", plain)
	}
}

// We decrypt xmlsec1's legacy element encryption.
func TestWeDecryptXmlsec1LegacyEncryption(t *testing.T) {
	key := rsaKey(t)
	kp := newKeypair(t, key)
	for _, c := range legacyCases {
		t.Run(c.name, func(t *testing.T) {
			em := `<xenc:EncryptionMethod Algorithm="` + c.transport + `"/>`
			if c.digest != "" {
				em = `<xenc:EncryptionMethod Algorithm="` + c.transport + `"><ds:DigestMethod Algorithm="` + c.digest + `"/></xenc:EncryptionMethod>`
			}
			out := filepath.Join(t.TempDir(), "out.xml")
			run(t, "--encrypt", "--pubkey-cert-pem", kp.certPEM, "--session-key", c.session,
				"--xml-data", tempFile(t, "data.xml", []byte(envelope)),
				"--node-name", "urn:example:p:Payload",
				"--output", out, tempFile(t, "tmpl.xml", []byte(legacyTemplate(c.data, em))))
			doc := parse(t, readFile(t, out))
			legacyOpen(t, doc, legacyUnwrap(t, doc, key, c.transport, c.data), c.data)
		})
	}
}

// We unwrap xmlsec1's kw-tripledes under a shared KEK.
func TestWeUnwrapXmlsec1TripleDESKeyWrap(t *testing.T) {
	for _, c := range []struct{ data, session string }{
		{xmlsec.EncTripleDESCBC, "des-192"},
		{xmlsec.EncAES128CBC, "aes-128"},
	} {
		t.Run(c.data, func(t *testing.T) {
			kek := make([]byte, 24)
			rand.Read(kek)
			em := `<xenc:EncryptionMethod Algorithm="` + xmlsec.KeyWrapTripleDES + `"/>`
			out := filepath.Join(t.TempDir(), "out.xml")
			run(t, "--encrypt", "--des-key", tempFile(t, "kek.bin", kek), "--session-key", c.session,
				"--xml-data", tempFile(t, "data.xml", []byte(envelope)),
				"--node-name", "urn:example:p:Payload",
				"--output", out, tempFile(t, "tmpl.xml", []byte(legacyTemplate(c.data, em))))
			doc := parse(t, readFile(t, out))
			legacyKW(t, doc, kek, c.data)
		})
	}
}

// legacyKW unwraps and decrypts doc's kw-tripledes EncryptedKey and
// EncryptedData, checking the default sets refuse both.
func legacyKW(t *testing.T, doc *xdm.Node, kek []byte, data string) {
	t.Helper()
	ek := find(doc, xenc.NSXEnc, "EncryptedKey")
	if _, err := xenc.UnwrapEncryptedKey(ek, kek, nil); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("default set: %v", err)
	}
	key, err := xenc.UnwrapEncryptedKey(ek, kek, []string{xmlsec.KeyWrapTripleDES})
	if err != nil {
		t.Fatal(err)
	}
	legacyOpen(t, doc, key, data)
}

// We decrypt Santuario's legacy element encryption.
func TestWeDecryptSantuarioLegacyEncryption(t *testing.T) {
	key := rsaKey(t)
	kp := newKeypair(t, key)
	for _, c := range legacyCases {
		if c.digest == "" && c.transport == xmlsec.KeyTransportRSAOAEPMGF1P {
			continue // Santuario always writes the digest; xmlsec1 covers its absence
		}
		t.Run(c.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out.xml")
			mustSantuario(t, "encrypt-legacy", tempFile(t, "in.xml", []byte(envelope)), kp.certPEM, "Payload", out, c.data, c.transport)
			doc := parse(t, readFile(t, out))
			legacyOpen(t, doc, legacyUnwrap(t, doc, key, c.transport, c.data), c.data)
		})
	}
	t.Run("kw-tripledes", func(t *testing.T) {
		kek := make([]byte, 24)
		rand.Read(kek)
		out := filepath.Join(t.TempDir(), "out.xml")
		mustSantuario(t, "encrypt-legacy", tempFile(t, "in.xml", []byte(envelope)), tempFile(t, "kek.bin", kek), "Payload", out,
			xmlsec.EncTripleDESCBC, xmlsec.KeyWrapTripleDES)
		legacyKW(t, parse(t, readFile(t, out)), kek, xmlsec.EncTripleDESCBC)
	})
}
