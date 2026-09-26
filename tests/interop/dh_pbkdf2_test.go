//go:build interop

package interop

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

// The OPTIONAL key agreement and derivation of XML Encryption 1.1 section
// 5: finite-field dh-es (5.6.2.1) and PBKDF2 (5.4.2), against xmlsec1 1.3,
// both directions. Santuario 4.0.4 implements neither (it has no
// xenc:DHKeyValue and no PBKDF2 derivation), and neither reference
// implements the Legacy KDF of dh (5.6.2.2), so those are checked only by
// the unit tests' known answers.

func groupHex(s string) *big.Int {
	n, _ := new(big.Int).SetString(strings.Join(strings.Fields(s), ""), 16)
	return n
}

// ffdhe2048 is the RFC 7919 appendix A.1 group: generator 2, Q = (P-1)/2.
var ffdhe2048 = groupHex(`FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1
    D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9
    7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561
    2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935
    984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735
    30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB
    B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19
    0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61
    9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73
    3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA
    886B4238 61285C97 FFFFFFFF FFFFFFFF`)

// dhKeyPEM generates a key in ffdhe2048 and writes it as the X9.42 (DHX)
// PKCS #8 PEM OpenSSL reads, with Q in its domain parameters.
func dhKeyPEM(t *testing.T) (*xenc.DHPrivateKey, string) {
	t.Helper()
	k, err := xenc.GenerateDHKey(ffdhe2048, new(big.Int).Rsh(ffdhe2048, 1), big.NewInt(2))
	if err != nil {
		t.Fatal(err)
	}
	type domain struct{ P, G, Q *big.Int } // RFC 3279 section 2.3.3 order
	type algID struct {
		OID    asn1.ObjectIdentifier
		Params domain
	}
	x, err := asn1.Marshal(k.X)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		Version int
		Alg     algID
		Key     []byte
	}{0, algID{asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}, domain{k.P, k.G, k.Q}}, x})
	if err != nil {
		t.Fatal(err)
	}
	return k, tempFile(t, "dh.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// xmlsec1DHKeyData enables DH key agreement in xmlsec1.
const xmlsec1DHKeyData = "agreement-method,enc-key,key-value,key-name,dh"

// xmlsec1 decrypts our dh-es with ConcatKDF, for each wrap size. xmlsec1
// finds the recipient's DH key only by the ds:KeyName in RecipientKeyInfo,
// not by its xenc:DHKeyValue nor, even with --lax-key-search, by type.
func TestXmlsec1DecryptsOurDHES(t *testing.T) {
	for _, c := range []struct{ wrap, digest string }{
		{xmlsec.KeyWrapAES128, xmlsec.DigestSHA256},
		{xmlsec.KeyWrapAES256, xmlsec.DigestSHA512},
	} {
		t.Run(c.wrap, func(t *testing.T) {
			k, keyPEM := dhKeyPEM(t)
			opts := xenc.EncryptOptions{
				DataAlgorithm:         xmlsec.EncAES128GCM,
				KeyTransportAlgorithm: c.wrap,
				KeyAgreementAlgorithm: xmlsec.KeyAgreementDHES,
				DigestAlgorithm:       c.digest,
				RecipientDH:           &k.DHPublicKey,
				RecipientKeyName:      "recipient",
			}
			ek, err := xenc.GenerateEncryptedKey(opts)
			if err != nil {
				t.Fatal(err)
			}
			enc := tempFile(t, "enc.xml", encryptWithEK(t, envelope, "Payload", ek, opts))
			out := filepath.Join(t.TempDir(), "xmlsec1.xml")
			run(t, "--decrypt", "--enabled-key-data", xmlsec1DHKeyData, "--privkey-pem:recipient", keyPEM, "--output", out, enc)
			assertDecryptedEnvelope(t, readFile(t, out))
		})
	}
}

// We decrypt xmlsec1's dh-es. As for ECDH-ES, xmlsec1 takes the originator
// key from its keys manager by the template's ds:KeyName and writes the
// full xenc:DHKeyValue, group included, into the empty ds:KeyValue.
func TestWeDecryptXmlsec1DHES(t *testing.T) {
	recipient, recipientPEM := dhKeyPEM(t)
	_, originatorPEM := dhKeyPEM(t)
	tmpl := `<xenc:EncryptedData xmlns:xenc="` + xmlsec.NSXEnc + `" Type="` + xenc.TypeElement + `">` +
		`<xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128GCM + `"/>` +
		`<ds:KeyInfo xmlns:ds="` + xmlsec.NSDSig + `"><xenc:EncryptedKey>` +
		`<xenc:EncryptionMethod Algorithm="` + xmlsec.KeyWrapAES128 + `"/>` +
		`<ds:KeyInfo><xenc:AgreementMethod Algorithm="` + xmlsec.KeyAgreementDHES + `">` +
		`<xenc11:KeyDerivationMethod xmlns:xenc11="` + xmlsec.NSXEnc11 + `" Algorithm="` + xmlsec.KeyDerivationConcatKDF + `">` +
		`<xenc11:ConcatKDFParams AlgorithmID="0001" PartyUInfo="" PartyVInfo=""><ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"/></xenc11:ConcatKDFParams>` +
		`</xenc11:KeyDerivationMethod>` +
		`<xenc:OriginatorKeyInfo><ds:KeyName>originator</ds:KeyName><ds:KeyValue/></xenc:OriginatorKeyInfo>` +
		`<xenc:RecipientKeyInfo><ds:KeyName>recipient</ds:KeyName></xenc:RecipientKeyInfo>` +
		`</xenc:AgreementMethod></ds:KeyInfo>` +
		`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>` +
		`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>`
	out := filepath.Join(t.TempDir(), "out.xml")
	run(t, "--encrypt", "--enabled-key-data", xmlsec1DHKeyData, "--session-key", "aes-128",
		"--privkey-pem:originator", originatorPEM,
		"--privkey-pem:recipient", recipientPEM,
		"--xml-data", tempFile(t, "data.xml", []byte(envelope)),
		"--node-name", "urn:example:p:Payload",
		"--output", out, tempFile(t, "tmpl.xml", []byte(tmpl)))
	plain := weDecrypt(t, readFile(t, out), func(ek *xdm.Node) ([]byte, error) {
		return xenc.DecryptAgreedKeyDH(ek, recipient, xenc.DecryptOptions{AllowedKeyAgreementAlgorithms: []string{xmlsec.KeyAgreementDHES}})
	})
	if !bytes.Contains(plain, []byte(">hello</p:Payload>")) {
		t.Fatalf("plaintext %s", plain)
	}
}

// xmlsec1 unwraps our password-derived key: PBKDF2 with HMAC-SHA256 and
// the default iteration count. xmlsec1 takes the password as a pbkdf2 key.
func TestXmlsec1DecryptsOurPBKDF2(t *testing.T) {
	password := []byte("correct horse battery staple")
	for _, wrap := range []string{xmlsec.KeyWrapAES128, xmlsec.KeyWrapAES256} {
		t.Run(wrap, func(t *testing.T) {
			opts := xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: wrap, Password: password}
			ek, err := xenc.GenerateEncryptedKey(opts)
			if err != nil {
				t.Fatal(err)
			}
			enc := tempFile(t, "enc.xml", encryptWithEK(t, envelope, "Payload", ek, opts))
			out := filepath.Join(t.TempDir(), "xmlsec1.xml")
			run(t, "--decrypt", "--pbkdf2-key", tempFile(t, "pw.bin", password), "--output", out, enc)
			assertDecryptedEnvelope(t, readFile(t, out))
		})
	}
}

// We unwrap xmlsec1's password-derived key, found by the
// xenc11:MasterKeyName its template names.
func TestWeDecryptXmlsec1PBKDF2(t *testing.T) {
	password := []byte("correct horse battery staple")
	for _, c := range []struct{ wrap, prf, keyLength string }{
		{xmlsec.KeyWrapAES128, xmlsec.SigHMACSHA256, "16"},
		{xmlsec.KeyWrapAES256, xmlsec.SigHMACSHA512, "32"},
	} {
		t.Run(c.wrap, func(t *testing.T) {
			tmpl := `<xenc:EncryptedData xmlns:xenc="` + xmlsec.NSXEnc + `" Type="` + xenc.TypeElement + `">` +
				`<xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128GCM + `"/>` +
				`<ds:KeyInfo xmlns:ds="` + xmlsec.NSDSig + `"><xenc:EncryptedKey>` +
				`<xenc:EncryptionMethod Algorithm="` + c.wrap + `"/>` +
				`<ds:KeyInfo><xenc11:DerivedKey xmlns:xenc11="` + xmlsec.NSXEnc11 + `">` +
				`<xenc11:KeyDerivationMethod Algorithm="` + xmlsec.KeyDerivationPBKDF2 + `"><xenc11:PBKDF2-params>` +
				`<xenc11:Salt><xenc11:Specified>AAECAwQFBgcICQoLDA0ODw==</xenc11:Specified></xenc11:Salt>` +
				`<xenc11:IterationCount>2000</xenc11:IterationCount><xenc11:KeyLength>` + c.keyLength + `</xenc11:KeyLength>` +
				`<xenc11:PRF Algorithm="` + c.prf + `"/></xenc11:PBKDF2-params></xenc11:KeyDerivationMethod>` +
				`<xenc11:MasterKeyName>pw</xenc11:MasterKeyName></xenc11:DerivedKey></ds:KeyInfo>` +
				`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>` +
				`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>`
			out := filepath.Join(t.TempDir(), "out.xml")
			run(t, "--encrypt", "--session-key", "aes-128", "--pbkdf2-key:pw", tempFile(t, "pw.bin", password),
				"--xml-data", tempFile(t, "data.xml", []byte(envelope)),
				"--node-name", "urn:example:p:Payload",
				"--output", out, tempFile(t, "tmpl.xml", []byte(tmpl)))
			plain := weDecrypt(t, readFile(t, out), func(ek *xdm.Node) ([]byte, error) {
				return xenc.UnwrapEncryptedKeyPassword(ek, password, xenc.DecryptOptions{AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2}})
			})
			if !bytes.Contains(plain, []byte(">hello</p:Payload>")) {
				t.Fatalf("plaintext %s", plain)
			}
		})
	}
}

// PBKDF2 as the KDF of a key agreement takes the shared secret as its
// password. The W3C interop vector doing so (AGRMNT.9, Oracle) cannot be
// reproduced by any encoding of the secret tried, and xmlsec1's own suite
// leaves it out; xmlsec1's reading, the secret's octets as the password,
// is the one implemented, and checked here for ECDH-ES and dh-es.
func TestWeDecryptXmlsec1AgreementWithPBKDF2(t *testing.T) {
	pbkdf2 := `<xenc11:KeyDerivationMethod xmlns:xenc11="` + xmlsec.NSXEnc11 + `" Algorithm="` + xmlsec.KeyDerivationPBKDF2 + `"><xenc11:PBKDF2-params>` +
		`<xenc11:Salt><xenc11:Specified>AAECAwQFBgcICQoLDA0ODw==</xenc11:Specified></xenc11:Salt>` +
		`<xenc11:IterationCount>2000</xenc11:IterationCount><xenc11:KeyLength>32</xenc11:KeyLength>` +
		`<xenc11:PRF Algorithm="` + xmlsec.SigHMACSHA256 + `"/></xenc11:PBKDF2-params></xenc11:KeyDerivationMethod>`
	tmpl := func(agreement string) string {
		return `<xenc:EncryptedData xmlns:xenc="` + xmlsec.NSXEnc + `" Type="` + xenc.TypeElement + `">` +
			`<xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128GCM + `"/>` +
			`<ds:KeyInfo xmlns:ds="` + xmlsec.NSDSig + `"><xenc:EncryptedKey>` +
			`<xenc:EncryptionMethod Algorithm="` + xmlsec.KeyWrapAES256 + `"/>` +
			`<ds:KeyInfo><xenc:AgreementMethod Algorithm="` + agreement + `">` + pbkdf2 +
			`<xenc:OriginatorKeyInfo><ds:KeyName>originator</ds:KeyName><ds:KeyValue/></xenc:OriginatorKeyInfo>` +
			`<xenc:RecipientKeyInfo><ds:KeyName>recipient</ds:KeyName></xenc:RecipientKeyInfo>` +
			`</xenc:AgreementMethod></ds:KeyInfo>` +
			`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>` +
			`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>`
	}
	encrypt := func(t *testing.T, agreement, keyData string, keys ...string) []byte {
		t.Helper()
		out := filepath.Join(t.TempDir(), "out.xml")
		args := append([]string{"--encrypt", "--enabled-key-data", keyData, "--session-key", "aes-128"}, keys...)
		run(t, append(args, "--xml-data", tempFile(t, "data.xml", []byte(envelope)),
			"--node-name", "urn:example:p:Payload", "--output", out, tempFile(t, "tmpl.xml", []byte(tmpl(agreement))))...)
		return readFile(t, out)
	}
	check := func(t *testing.T, doc []byte, unwrap func(ek *xdm.Node) ([]byte, error)) {
		t.Helper()
		if plain := weDecrypt(t, doc, unwrap); !bytes.Contains(plain, []byte(">hello</p:Payload>")) {
			t.Fatalf("plaintext %s", plain)
		}
	}
	allow := func(agreement string) xenc.DecryptOptions {
		return xenc.DecryptOptions{AllowedKeyAgreementAlgorithms: []string{agreement}, AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2}}
	}

	t.Run("ECDH-ES", func(t *testing.T) {
		recipient, originator := newKeypair(t, ecKey(t)), newKeypair(t, ecKey(t))
		doc := encrypt(t, xmlsec.KeyAgreementECDHES, xmlsec1AgreementKeyData+",pbkdf2",
			"--privkey-pem:originator", originator.keyPEM, "--pubkey-cert-pem:recipient", recipient.certPEM)
		priv, err := recipient.provider.Signer.(*ecdsa.PrivateKey).ECDH()
		if err != nil {
			t.Fatal(err)
		}
		check(t, doc, func(ek *xdm.Node) ([]byte, error) {
			return xenc.DecryptAgreedKey(ek, priv, allow(xmlsec.KeyAgreementECDHES))
		})
	})
	t.Run("dh-es", func(t *testing.T) {
		recipient, recipientPEM := dhKeyPEM(t)
		_, originatorPEM := dhKeyPEM(t)
		doc := encrypt(t, xmlsec.KeyAgreementDHES, xmlsec1DHKeyData+",pbkdf2",
			"--privkey-pem:originator", originatorPEM, "--privkey-pem:recipient", recipientPEM)
		check(t, doc, func(ek *xdm.Node) ([]byte, error) {
			return xenc.DecryptAgreedKeyDH(ek, recipient, allow(xmlsec.KeyAgreementDHES))
		})
	})
}
