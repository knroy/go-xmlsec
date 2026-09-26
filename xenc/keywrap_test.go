package xenc_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// cipherValueOf returns the decoded CipherValue of an EncryptedKey.
func cipherValueOf(t *testing.T, ek *xdm.Node) []byte {
	t.Helper()
	var cv *xdm.Node
	xmltree.Walk(ek, func(e *xdm.Node) {
		if e.IsElement(xmlsec.NSXEnc, "CipherValue") {
			cv = e
		}
	})
	b, err := base64.StdEncoding.DecodeString(cv.StringValue())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 3394 section 4 test vectors: 128-bit key data under a 128-bit KEK
// (4.1), 192-bit under 192-bit (4.4) and 256-bit under 256-bit (4.6).
func TestKeyWrapRFC3394(t *testing.T) {
	kek := unhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	for _, c := range []struct {
		wrap, data string
		kek        []byte
		key        string
		want       string
	}{
		{xmlsec.KeyWrapAES128, xmlsec.EncAES128GCM, kek[:16], "00112233445566778899AABBCCDDEEFF",
			"1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5"},
		{xmlsec.KeyWrapAES192, xmlsec.EncAES192GCM, kek[:24], "00112233445566778899AABBCCDDEEFF0001020304050607",
			"031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2"},
		{xmlsec.KeyWrapAES256, xmlsec.EncAES256GCM, kek, "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			"28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21"},
	} {
		t.Run(c.wrap, func(t *testing.T) {
			ek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{
				DataAlgorithm:         c.data,
				KeyTransportAlgorithm: c.wrap,
				KeyEncryptionKey:      c.kek,
				SessionKey:            unhex(c.key),
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := cipherValueOf(t, ek.Element); !bytes.Equal(got, unhex(c.want)) {
				t.Fatalf("wrapped %X", got)
			}
			key, err := xenc.UnwrapEncryptedKey(reparse(t, ek.Element), c.kek, xenc.DecryptOptions{AllowedKeyWrapAlgorithms: []string{c.wrap}})
			if err != nil || !bytes.Equal(key, unhex(c.key)) {
				t.Fatalf("unwrapped %X, %v", key, err)
			}
			// The default allow-list includes every key wrap algorithm.
			if _, err := xenc.UnwrapEncryptedKey(reparse(t, ek.Element), c.kek, xenc.DecryptOptions{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func kwEK(alg, method, rest string) string {
	return `<xenc:EncryptedKey xmlns:xenc="` + xmlsec.NSXEnc + `"><xenc:EncryptionMethod Algorithm="` + alg + `">` + method +
		`</xenc:EncryptionMethod>` + rest + `</xenc:EncryptedKey>`
}

func kwCV(b []byte) string {
	return `<xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(b) + `</xenc:CipherValue></xenc:CipherData>`
}

func TestUnwrapEncryptedKeyErrors(t *testing.T) {
	kek := bytes.Repeat([]byte{3}, 16)
	ek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM,
		KeyTransportAlgorithm: xmlsec.KeyWrapAES128, KeyEncryptionKey: kek})
	if err != nil {
		t.Fatal(err)
	}
	good := cipherValueOf(t, ek.Element)
	flipped := bytes.Clone(good)
	flipped[len(flipped)-1] ^= 1
	kw := xmlsec.KeyWrapAES128
	cases := []struct {
		name    string
		el      string
		kek     []byte
		allowed []string
		want    error // nil: any error
	}{
		{"not an EncryptedKey", covED(``, ``), kek, nil, xmlsec.ErrMalformed},
		{"no EncryptionMethod", `<xenc:EncryptedKey xmlns:xenc="` + xmlsec.NSXEnc + `"/>`, kek, nil, xmlsec.ErrMalformed},
		{"RSA-OAEP", kwEK(xmlsec.KeyTransportRSAOAEP, ``, kwCV(good)), kek, nil, xmlsec.ErrAlgorithmNotAllowed},
		{"triple DES wrap", kwEK("http://www.w3.org/2001/04/xmlenc#kw-tripledes", ``, kwCV(good)), kek, nil, xmlsec.ErrAlgorithmNotAllowed},
		{"outside allow-list", kwEK(kw, ``, kwCV(good)), kek, []string{xmlsec.KeyWrapAES256}, xmlsec.ErrAlgorithmNotAllowed},
		{"allow-listed but unimplemented", kwEK("urn:x", ``, kwCV(good)), kek, []string{"urn:x"}, xmlsec.ErrUnsupportedAlgorithm},
		{"inconsistent KeySize", kwEK(kw, `<xenc:KeySize>256</xenc:KeySize>`, kwCV(good)), kek, nil, xmlsec.ErrMalformed},
		{"parameter not permitted", kwEK(kw, `<xenc:OAEPparams>AA==</xenc:OAEPparams>`, kwCV(good)), kek, nil, xmlsec.ErrMalformed},
		{"KEK of another size", kwEK(kw, ``, kwCV(good)), make([]byte, 32), nil, nil},
		{"KEK no AES size", kwEK(kw, ``, kwCV(good)), make([]byte, 10), nil, nil},
		{"no CipherData", kwEK(kw, ``, ``), kek, nil, xmlsec.ErrMalformed},
		{"ciphertext not blocks", kwEK(kw, ``, kwCV(good[:23])), kek, nil, nil},
		{"ciphertext too short", kwEK(kw, ``, kwCV(good[:16])), kek, nil, nil},
		{"integrity check", kwEK(kw, ``, kwCV(flipped)), kek, nil, nil},
		{"wrong KEK", kwEK(kw, ``, kwCV(good)), bytes.Repeat([]byte{4}, 16), nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, err := xenc.UnwrapEncryptedKey(covParse(t, c.el), c.kek, xenc.DecryptOptions{AllowedKeyWrapAlgorithms: c.allowed})
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if key != nil {
				t.Fatal("key returned with an error")
			}
		})
	}
	// Every integrity failure reads the same.
	_, e1 := xenc.UnwrapEncryptedKey(covParse(t, kwEK(kw, ``, kwCV(flipped))), kek, xenc.DecryptOptions{})
	_, e2 := xenc.UnwrapEncryptedKey(covParse(t, kwEK(kw, ``, kwCV(good[:16]))), kek, xenc.DecryptOptions{})
	if e1.Error() != e2.Error() {
		t.Fatalf("distinguishable unwrap failures: %v / %v", e1, e2)
	}
	if _, err := xenc.UnwrapEncryptedKey(nil, kek, xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatal(err)
	}
	// KeySize consistent with the algorithm is permitted.
	if _, err := xenc.UnwrapEncryptedKey(covParse(t, kwEK(kw, `<xenc:KeySize>128</xenc:KeySize>`, kwCV(good))), kek, xenc.DecryptOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateWrappedKeyErrors(t *testing.T) {
	base := xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES256}
	for name, mod := range map[string]func(*xenc.EncryptOptions){
		"unknown wrap":        func(o *xenc.EncryptOptions) { o.KeyTransportAlgorithm = "urn:x"; o.KeyEncryptionKey = make([]byte, 32) },
		"no KEK":              func(o *xenc.EncryptOptions) {},
		"KEK of another size": func(o *xenc.EncryptOptions) { o.KeyEncryptionKey = make([]byte, 16) },
		"KEK and a recipient": func(o *xenc.EncryptOptions) { o.KeyEncryptionKey = make([]byte, 32); o.Recipient = recipient(t) },
		"RSA recipient for KW": func(o *xenc.EncryptOptions) {
			o.Recipient = recipient(t)
			o.KeyAgreementAlgorithm = xmlsec.KeyAgreementECDHES
		},
	} {
		t.Run(name, func(t *testing.T) {
			opts := base
			mod(&opts)
			if ek, err := xenc.GenerateEncryptedKey(opts); err == nil || ek != nil {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// A wrapped key composes as section 3.5 expects: CarriedKeyName last,
// ReferenceList before it, Recipient as an attribute.
func TestCarriedKeyNameAndRecipient(t *testing.T) {
	ek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM,
		KeyTransportAlgorithm: xmlsec.KeyWrapAES128, KeyEncryptionKey: make([]byte, 16),
		CarriedKeyName: " Sally Doe ", RecipientHint: "name:Sally"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ek.AddDataReference("ED-1"); err != nil {
		t.Fatal(err)
	}
	if err := ek.AddDataReference("ED-2"); err != nil {
		t.Fatal(err)
	}
	b, err := c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Exclusive10})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `Recipient="name:Sally"`) ||
		!strings.HasSuffix(s, `<xenc:ReferenceList><xenc:DataReference URI="#ED-1"></xenc:DataReference><xenc:DataReference URI="#ED-2"></xenc:DataReference></xenc:ReferenceList>`+
			`<xenc:CarriedKeyName> Sally Doe </xenc:CarriedKeyName></xenc:EncryptedKey>`) {
		t.Fatalf("composition:\n%s", s)
	}
	for _, id := range []string{"", "1ED", "a:b", "a b"} {
		if err := ek.AddDataReference(id); err == nil {
			t.Errorf("%q accepted", id)
		}
	}
}
