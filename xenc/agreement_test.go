package xenc_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

type ecRecipient struct {
	opts xenc.EncryptOptions
	priv *ecdh.PrivateKey
}

func newECRecipient(t *testing.T, curve elliptic.Curve, wrap string) ecRecipient {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := k.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	return ecRecipient{priv: priv, opts: xenc.EncryptOptions{
		DataAlgorithm:         xmlsec.EncAES128GCM,
		KeyTransportAlgorithm: wrap,
		KeyAgreementAlgorithm: xmlsec.KeyAgreementECDHES,
		DigestAlgorithm:       xmlsec.DigestSHA256,
		Recipient:             covCert(t, &k.PublicKey, k),
	}}
}

// ECDH-ES with ConcatKDF on each curve, each wrap size and each digest.
func TestKeyAgreementRoundTrip(t *testing.T) {
	for _, c := range []struct {
		curve  elliptic.Curve
		wrap   string
		digest string
	}{
		{elliptic.P256(), xmlsec.KeyWrapAES128, xmlsec.DigestSHA256},
		{elliptic.P384(), xmlsec.KeyWrapAES192, xmlsec.DigestSHA384},
		{elliptic.P521(), xmlsec.KeyWrapAES256, xmlsec.DigestSHA512},
	} {
		t.Run(c.curve.Params().Name, func(t *testing.T) {
			r := newECRecipient(t, c.curve, c.wrap)
			r.opts.DigestAlgorithm = c.digest
			ek, err := xenc.GenerateEncryptedKey(r.opts)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Exclusive10})
			for _, want := range []string{
				`<xenc:AgreementMethod Algorithm="` + xmlsec.KeyAgreementECDHES + `">`,
				`<xenc11:KeyDerivationMethod xmlns:xenc11="` + xmlsec.NSXEnc11 + `" Algorithm="` + xmlsec.KeyDerivationConcatKDF + `">`,
				`<ds:DigestMethod Algorithm="` + c.digest + `">`,
				`<xenc:OriginatorKeyInfo><ds:KeyValue><dsig11:ECKeyValue`,
				`<xenc:RecipientKeyInfo><ds:X509Data><ds:X509Certificate>`,
			} {
				if !strings.Contains(string(b), want) {
					t.Fatalf("no %s in\n%s", want, b)
				}
			}
			key, err := xenc.DecryptAgreedKey(reparse(t, ek.Element), r.priv, xenc.DecryptOptions{AllowedKeyWrapAlgorithms: []string{c.wrap}, AllowedKeyAgreementAlgorithms: []string{xmlsec.KeyAgreementECDHES}, AllowedDigestAlgorithms: []string{c.digest}})
			if err != nil || !bytes.Equal(key, ek.SessionKey) {
				t.Fatalf("agreed %x, %v", key, err)
			}
			// SetKeyInfo cannot add a second ds:KeyInfo.
			if err := ek.SetKeyInfo(covParse(t, `<x/>`)); err == nil {
				t.Fatal("second KeyInfo")
			}
		})
	}
}

func TestGenerateAgreedKeyErrors(t *testing.T) {
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*xenc.EncryptOptions){
		"no agreement algorithm": func(o *xenc.EncryptOptions) { o.KeyAgreementAlgorithm = "" },
		"P-224 recipient":        func(o *xenc.EncryptOptions) { o.Recipient = covCert(t, &p224.PublicKey, p224) },
		"unknown KDF digest":     func(o *xenc.EncryptOptions) { o.DigestAlgorithm = "urn:x" },
	} {
		t.Run(name, func(t *testing.T) {
			r := newECRecipient(t, elliptic.P256(), xmlsec.KeyWrapAES128)
			mod(&r.opts)
			if _, err := xenc.GenerateEncryptedKey(r.opts); !errors.Is(err, xmlsec.ErrUnsupportedAlgorithm) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestDecryptAgreedKeyErrors(t *testing.T) {
	r := newECRecipient(t, elliptic.P256(), xmlsec.KeyWrapAES128)
	ek, err := xenc.GenerateEncryptedKey(r.opts)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Exclusive10})
	good := string(b)
	edit := func(old, new string) string {
		if !strings.Contains(good, old) {
			t.Fatalf("no %s", old)
		}
		return strings.Replace(good, old, new, 1)
	}
	cut := func(from, to string) string { // removes from..to inclusive
		i, j := strings.Index(good, from), strings.Index(good, to)
		return good[:i] + good[j+len(to):]
	}
	other := newECRecipient(t, elliptic.P256(), xmlsec.KeyWrapAES128)
	p384 := newECRecipient(t, elliptic.P384(), xmlsec.KeyWrapAES128)
	kwOnly, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM,
		KeyTransportAlgorithm: xmlsec.KeyWrapAES128, KeyEncryptionKey: make([]byte, 16)})
	if err != nil {
		t.Fatal(err)
	}
	kwOnlyXML, _ := c14n.Bytes(kwOnly.Element, c14n.Options{Algorithm: c14n.Exclusive10})
	const am = `<xenc:AgreementMethod Algorithm="` + xmlsec.KeyAgreementECDHES + `">`
	const nc = `<dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"></dsig11:NamedCurve>`

	type lists struct{ wrap, agreement, digest []string }
	cases := []struct {
		name  string
		el    string
		priv  *ecdh.PrivateKey
		allow lists
		want  error // nil: any error
	}{
		{"not an EncryptedKey", covED(``, ``), r.priv, lists{}, xmlsec.ErrMalformed},
		{"no private key", good, nil, lists{}, nil},
		{"no KeyInfo", string(kwOnlyXML), r.priv, lists{}, xmlsec.ErrUnsupportedKeyInfo},
		{"wrap outside allow-list", good, r.priv, lists{wrap: []string{xmlsec.KeyWrapAES256}}, xmlsec.ErrAlgorithmNotAllowed},
		{"two KeyInfo children", edit(am, `<ds:KeyName>k</ds:KeyName>`+am), r.priv, lists{}, xmlsec.ErrMalformed},
		{"dh-es", edit(am, `<xenc:AgreementMethod Algorithm="http://www.w3.org/2009/xmlenc11#dh-es">`), r.priv, lists{}, xmlsec.ErrAlgorithmNotAllowed},
		{"allow-listed unimplemented agreement", edit(am, `<xenc:AgreementMethod Algorithm="urn:x">`), r.priv, lists{agreement: []string{"urn:x"}}, xmlsec.ErrUnsupportedAlgorithm},
		{"KA-Nonce", edit(am, am+`<xenc:KA-Nonce>Zm9v</xenc:KA-Nonce>`), r.priv, lists{}, xmlsec.ErrMalformed},
		{"no OriginatorKeyInfo", cut(`<xenc:OriginatorKeyInfo>`, `</xenc:OriginatorKeyInfo>`), r.priv, lists{}, xmlsec.ErrMalformed},
		{"PBKDF2", edit(`Algorithm="`+xmlsec.KeyDerivationConcatKDF+`"`, `Algorithm="http://www.w3.org/2009/xmlenc11#pbkdf2"`), r.priv, lists{}, xmlsec.ErrUnsupportedAlgorithm},
		{"no ConcatKDFParams", cut(`<xenc11:ConcatKDFParams`, `</xenc11:ConcatKDFParams>`), r.priv, lists{}, xmlsec.ErrMalformed},
		{"no DigestMethod", cut(`<ds:DigestMethod`, `</ds:DigestMethod>`), r.priv, lists{}, xmlsec.ErrMalformed},
		{"SHA-1 KDF", edit(`<ds:DigestMethod Algorithm="`+xmlsec.DigestSHA256, `<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1`), r.priv, lists{}, xmlsec.ErrAlgorithmNotAllowed},
		{"KDF digest outside allow-list", good, r.priv, lists{digest: []string{xmlsec.DigestSHA512}}, xmlsec.ErrAlgorithmNotAllowed},
		{"unimplemented KDF digest", edit(`<ds:DigestMethod Algorithm="`+xmlsec.DigestSHA256, `<ds:DigestMethod Algorithm="urn:x`), r.priv, lists{digest: []string{"urn:x"}}, xmlsec.ErrUnsupportedAlgorithm},
		{"padded bit string", edit(`PartyUInfo=""`, `PartyUInfo="03D8"`), r.priv, lists{}, xmlsec.ErrUnsupportedAlgorithm},
		{"not hex", edit(`PartyVInfo=""`, `PartyVInfo="0g"`), r.priv, lists{}, xmlsec.ErrUnsupportedAlgorithm},
		{"no KeyValue", cut(`<ds:KeyValue>`, `</ds:KeyValue>`), r.priv, lists{}, xmlsec.ErrMalformed},
		{"X509Data as originator", edit(`<xenc:OriginatorKeyInfo>`, `<xenc:OriginatorKeyInfo><ds:X509Data></ds:X509Data>`), r.priv, lists{}, xmlsec.ErrMalformed},
		{"two KeyValues", edit(`<xenc:OriginatorKeyInfo>`, `<xenc:OriginatorKeyInfo><ds:KeyValue></ds:KeyValue>`), r.priv, lists{}, xmlsec.ErrMalformed},
		{"RSAKeyValue", edit(`<dsig11:ECKeyValue`, `<ds:RSAKeyValue></ds:RSAKeyValue><dsig11:ECKeyValue`), r.priv, lists{}, xmlsec.ErrMalformed},
		{"explicit parameters", edit(nc, `<dsig11:ECParameters></dsig11:ECParameters>`), r.priv, lists{}, xmlsec.ErrMalformed},
		{"P-224", edit(nc, `<dsig11:NamedCurve URI="urn:oid:1.3.132.0.33"></dsig11:NamedCurve>`), r.priv, lists{}, xmlsec.ErrUnsupportedKeyInfo},
		{"PublicKey not base64", edit(`<dsig11:PublicKey>`, `<dsig11:PublicKey>!!`), r.priv, lists{}, xmlsec.ErrMalformed},
		{"point off the curve", edit(`<dsig11:PublicKey>`, `<dsig11:PublicKey>BAAA`), r.priv, lists{}, xmlsec.ErrMalformed},
		{"originator on another curve", good, p384.priv, lists{}, xmlsec.ErrUnsupportedKeyInfo},
		{"another recipient", good, other.priv, lists{}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, err := xenc.DecryptAgreedKey(covParse(t, c.el), c.priv, xenc.DecryptOptions{AllowedKeyWrapAlgorithms: c.allow.wrap, AllowedKeyAgreementAlgorithms: c.allow.agreement, AllowedDigestAlgorithms: c.allow.digest})
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if key != nil {
				t.Fatal("key returned with an error")
			}
		})
	}

	// A ds:KeyName beside the originator's ds:KeyValue is ignored.
	named := edit(`<xenc:OriginatorKeyInfo>`, `<xenc:OriginatorKeyInfo><ds:KeyName>originator</ds:KeyName>`)
	if key, err := xenc.DecryptAgreedKey(covParse(t, named), r.priv, xenc.DecryptOptions{}); err != nil || !bytes.Equal(key, ek.SessionKey) {
		t.Fatalf("KeyName beside KeyValue: %v", err)
	}

	// XML Encryption's own SHA-384 URI is accepted as the KDF digest.
	r.opts.DigestAlgorithm = xmlsec.DigestSHA384
	ek, err = xenc.GenerateEncryptedKey(r.opts)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Exclusive10})
	alias := strings.Replace(string(b), xmlsec.DigestSHA384, xmlsec.DigestSHA384XMLEnc, 1)
	if key, err := xenc.DecryptAgreedKey(covParse(t, alias), r.priv, xenc.DecryptOptions{}); err != nil || !bytes.Equal(key, ek.SessionKey) {
		t.Fatalf("xmlenc#sha384: %v", err)
	}
}
