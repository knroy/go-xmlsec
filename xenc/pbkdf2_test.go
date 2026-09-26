package xenc_test

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

var pbkdf2Allowed = xenc.DecryptOptions{AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2}}

// pbkdf2Method is an xenc11:KeyDerivationMethod naming PBKDF2.
func pbkdf2Method(salt []byte, iter string, keyLen int, prf string) string {
	return `<xenc11:KeyDerivationMethod Algorithm="` + xmlsec.KeyDerivationPBKDF2 + `"><xenc11:PBKDF2-params>` +
		`<xenc11:Salt><xenc11:Specified>` + base64.StdEncoding.EncodeToString(salt) + `</xenc11:Specified></xenc11:Salt>` +
		`<xenc11:IterationCount>` + iter + `</xenc11:IterationCount><xenc11:KeyLength>` + strconv.Itoa(keyLen) + `</xenc11:KeyLength>` +
		`<xenc11:PRF Algorithm="` + prf + `"/></xenc11:PBKDF2-params></xenc11:KeyDerivationMethod>`
}

// wrappedWith returns an EncryptedKey wrapping a fresh session key under
// kek, with keyInfo as its ds:KeyInfo content, and the session key.
func wrappedWith(t *testing.T, wrap string, kek []byte, keyInfo string) (string, []byte) {
	t.Helper()
	ek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: wrap, KeyEncryptionKey: kek})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Exclusive10})
	s := strings.Replace(string(b), `<xenc:EncryptedKey `, `<xenc:EncryptedKey xmlns:ds="`+xmlsec.NSDSig+`" xmlns:xenc11="`+xmlsec.NSXEnc11+`" `, 1)
	return strings.Replace(s, `</xenc:EncryptionMethod>`, `</xenc:EncryptionMethod><ds:KeyInfo>`+keyInfo+`</ds:KeyInfo>`, 1), ek.SessionKey
}

func derivedKey(method string) string {
	return `<xenc11:DerivedKey>` + method + `<xenc11:MasterKeyName>pw</xenc11:MasterKeyName></xenc11:DerivedKey>`
}

// Known answers: PBKDF2-HMAC-SHA256 and PBKDF2-HMAC-SHA1 of password
// "passwordPASSWORDpassword", salt "saltSALTsaltSALTsaltSALTsaltSALTsalt",
// 4096 iterations. The SHA-1 value is RFC 6070 section 2's; the SHA-256
// value was computed with both OpenSSL 3 ("openssl kdf ... PBKDF2") and
// Python's hashlib. Each is the KEK a hand-built EncryptedKey is wrapped
// under.
func TestPBKDF2KnownAnswers(t *testing.T) {
	const password = "passwordPASSWORDpassword"
	salt := []byte("saltSALTsaltSALTsaltSALTsaltSALTsalt")
	for _, c := range []struct {
		prf, wrap, kek string
		opts           xenc.DecryptOptions
	}{
		{xmlsec.SigHMACSHA256, xmlsec.KeyWrapAES256, "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1", pbkdf2Allowed},
		{xmlsec.SigHMACSHA1, xmlsec.KeyWrapAES128, "3d2eec4fe41c849b80c8d83662c0e44a", xenc.DecryptOptions{
			AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2}, AllowedPRFAlgorithms: []string{xmlsec.SigHMACSHA1}}},
	} {
		t.Run(c.prf, func(t *testing.T) {
			kek, _ := hex.DecodeString(c.kek)
			doc, want := wrappedWith(t, c.wrap, kek, derivedKey(pbkdf2Method(salt, "4096", len(kek), c.prf)))
			key, err := xenc.UnwrapEncryptedKeyPassword(covParse(t, doc), []byte(password), c.opts)
			if err != nil || !bytes.Equal(key, want) {
				t.Fatalf("%x, %v", key, err)
			}
			if _, err := xenc.UnwrapEncryptedKeyPassword(covParse(t, doc), []byte("wrong"), c.opts); err == nil {
				t.Fatal("wrong password accepted")
			}
		})
	}
}

func TestPasswordRoundTrip(t *testing.T) {
	for _, c := range []struct {
		wrap string
		iter int
	}{
		{xmlsec.KeyWrapAES128, xenc.MinPBKDF2Iterations},
		{xmlsec.KeyWrapAES256, 0}, // DefaultPBKDF2Iterations
	} {
		t.Run(c.wrap, func(t *testing.T) {
			ek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES256GCM,
				KeyTransportAlgorithm: c.wrap, Password: []byte("correct horse"), PBKDF2Iterations: c.iter})
			if err != nil {
				t.Fatal(err)
			}
			b, _ := c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Exclusive10})
			iter := c.iter
			if iter == 0 {
				iter = xenc.DefaultPBKDF2Iterations
			}
			for _, want := range []string{
				`<ds:KeyInfo xmlns:ds="` + xmlsec.NSDSig + `"><xenc11:DerivedKey xmlns:xenc11="` + xmlsec.NSXEnc11 + `"><xenc11:KeyDerivationMethod Algorithm="` + xmlsec.KeyDerivationPBKDF2 + `"><xenc11:PBKDF2-params><xenc11:Salt><xenc11:Specified>`,
				`<xenc11:IterationCount>` + strconv.Itoa(iter) + `</xenc11:IterationCount>`,
				`<xenc11:PRF Algorithm="` + xmlsec.SigHMACSHA256 + `"></xenc11:PRF>`,
			} {
				if !strings.Contains(string(b), want) {
					t.Fatalf("no %s in\n%s", want, b)
				}
			}
			key, err := xenc.UnwrapEncryptedKeyPassword(reparse(t, ek.Element), []byte("correct horse"), pbkdf2Allowed)
			if err != nil || !bytes.Equal(key, ek.SessionKey) {
				t.Fatalf("%x, %v", key, err)
			}
		})
	}
}

func TestGeneratePasswordKeyErrors(t *testing.T) {
	for name, mod := range map[string]func(*xenc.EncryptOptions){
		"999 iterations":         func(o *xenc.EncryptOptions) { o.PBKDF2Iterations = 999 },
		"too many iterations":    func(o *xenc.EncryptOptions) { o.PBKDF2Iterations = xenc.MaxPBKDF2Iterations + 1 },
		"and a KeyEncryptionKey": func(o *xenc.EncryptOptions) { o.KeyEncryptionKey = make([]byte, 16) },
	} {
		t.Run(name, func(t *testing.T) {
			opts := xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES128, Password: []byte("pw")}
			mod(&opts)
			if _, err := xenc.GenerateEncryptedKey(opts); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestUnwrapEncryptedKeyPasswordErrors(t *testing.T) {
	salt := bytes.Repeat([]byte{7}, 16)
	kek := make([]byte, 16)
	method := func(salt []byte, iter string, keyLen int, prf string) string {
		doc, _ := wrappedWith(t, xmlsec.KeyWrapAES128, kek, derivedKey(pbkdf2Method(salt, iter, keyLen, prf)))
		return doc
	}
	good := method(salt, "1000", 16, xmlsec.SigHMACSHA256)
	edit := func(old, new string) string {
		if !strings.Contains(good, old) {
			t.Fatalf("no %s", old)
		}
		return strings.Replace(good, old, new, 1)
	}
	noKeyInfo, _ := wrappedWith(t, xmlsec.KeyWrapAES128, kek, ``)
	noKeyInfo = strings.Replace(noKeyInfo, `<ds:KeyInfo></ds:KeyInfo>`, ``, 1)
	kn, _ := wrappedWith(t, xmlsec.KeyWrapAES128, kek, `<ds:KeyName>k</ds:KeyName>`)
	sha512 := xenc.DecryptOptions{AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2}, AllowedPRFAlgorithms: []string{xmlsec.SigHMACSHA512}}
	concat := xenc.DecryptOptions{AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationConcatKDF}}
	unknownPRF := xenc.DecryptOptions{AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2}, AllowedPRFAlgorithms: []string{"urn:x"}}
	wrap256 := xenc.DecryptOptions{AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2}, AllowedKeyWrapAlgorithms: []string{xmlsec.KeyWrapAES256}}

	cases := []struct {
		name     string
		el       string
		password string
		opts     xenc.DecryptOptions
		want     error // nil: any error
	}{
		{"not an EncryptedKey", covED(``, ``), "pw", pbkdf2Allowed, xmlsec.ErrMalformed},
		{"wrap outside allow-list", good, "pw", wrap256, xmlsec.ErrAlgorithmNotAllowed},
		{"no password", good, "", pbkdf2Allowed, nil},
		{"no KeyInfo", noKeyInfo, "pw", pbkdf2Allowed, xmlsec.ErrUnsupportedKeyInfo},
		{"KeyName", kn, "pw", pbkdf2Allowed, xmlsec.ErrMalformed},
		{"unexpected child", edit(`<xenc11:MasterKeyName>`, `<xenc11:ReferenceList></xenc11:ReferenceList><xenc11:MasterKeyName>`), "pw", pbkdf2Allowed, xmlsec.ErrMalformed},
		{"no KeyDerivationMethod", edit(pbkdf2Method(salt, "1000", 16, xmlsec.SigHMACSHA256), ``), "pw", pbkdf2Allowed, xmlsec.ErrMalformed},
		{"PBKDF2 not named", good, "pw", xenc.DecryptOptions{}, xmlsec.ErrAlgorithmNotAllowed},
		{"ConcatKDF from a password", edit(`Algorithm="`+xmlsec.KeyDerivationPBKDF2+`"`, `Algorithm="`+xmlsec.KeyDerivationConcatKDF+`"`), "pw", concat, xmlsec.ErrUnsupportedAlgorithm},
		{"no PBKDF2-params", edit(`<xenc11:PBKDF2-params>`, `<xenc11:Other></xenc11:Other><xenc11:PBKDF2-params>`), "pw", pbkdf2Allowed, xmlsec.ErrMalformed},
		{"params out of order", edit(`<xenc11:IterationCount>1000</xenc11:IterationCount><xenc11:KeyLength>16</xenc11:KeyLength>`, `<xenc11:KeyLength>16</xenc11:KeyLength><xenc11:IterationCount>1000</xenc11:IterationCount>`), "pw", pbkdf2Allowed, xmlsec.ErrMalformed},
		{"HMAC-SHA1 not named", method(salt, "1000", 16, xmlsec.SigHMACSHA1), "pw", pbkdf2Allowed, xmlsec.ErrAlgorithmNotAllowed},
		{"PRF outside allow-list", good, "pw", sha512, xmlsec.ErrAlgorithmNotAllowed},
		{"unimplemented PRF", method(salt, "1000", 16, "urn:x"), "pw", unknownPRF, xmlsec.ErrUnsupportedAlgorithm},
		{"PRF Parameters", edit(`<xenc11:PRF Algorithm="`+xmlsec.SigHMACSHA256+`"/>`, `<xenc11:PRF Algorithm="`+xmlsec.SigHMACSHA256+`"><xenc11:Parameters/></xenc11:PRF>`), "pw", pbkdf2Allowed, xmlsec.ErrMalformed},
		{"OtherSource salt", edit(`<xenc11:Salt><xenc11:Specified>`+base64.StdEncoding.EncodeToString(salt)+`</xenc11:Specified>`, `<xenc11:Salt><xenc11:OtherSource Algorithm="urn:x"></xenc11:OtherSource>`), "pw", pbkdf2Allowed, xmlsec.ErrUnsupportedAlgorithm},
		{"salt not base64", edit(`<xenc11:Specified>`, `<xenc11:Specified>!!`), "pw", pbkdf2Allowed, xmlsec.ErrMalformed},
		{"7-octet salt", method(salt[:7], "1000", 16, xmlsec.SigHMACSHA256), "pw", pbkdf2Allowed, xmlsec.ErrAlgorithmNotAllowed},
		{"999 iterations", method(salt, "999", 16, xmlsec.SigHMACSHA256), "pw", pbkdf2Allowed, xmlsec.ErrAlgorithmNotAllowed},
		{"10,000,001 iterations", method(salt, "10000001", 16, xmlsec.SigHMACSHA256), "pw", pbkdf2Allowed, xmlsec.ErrLimitExceeded},
		{"iterations beyond int", method(salt, "99999999999999999999999", 16, xmlsec.SigHMACSHA256), "pw", pbkdf2Allowed, xmlsec.ErrLimitExceeded},
		{"iterations not a number", method(salt, "many", 16, xmlsec.SigHMACSHA256), "pw", pbkdf2Allowed, xmlsec.ErrMalformed},
		{"zero iterations", method(salt, "0", 16, xmlsec.SigHMACSHA256), "pw", pbkdf2Allowed, xmlsec.ErrMalformed},
		{"KeyLength of another wrap", method(salt, "1000", 32, xmlsec.SigHMACSHA256), "pw", pbkdf2Allowed, xmlsec.ErrMalformed},
		{"KeyLength not a number", edit(`<xenc11:KeyLength>16`, `<xenc11:KeyLength>x`), "pw", pbkdf2Allowed, xmlsec.ErrMalformed},
		{"wrong password", good, "pw", pbkdf2Allowed, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, err := xenc.UnwrapEncryptedKeyPassword(covParse(t, c.el), []byte(c.password), c.opts)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if key != nil {
				t.Fatal("key returned with an error")
			}
		})
	}

	// Whitespace around the integers collapses, as xs:positiveInteger's
	// does, and DerivedKeyName is ignored like MasterKeyName.
	spaced := method(salt, " 1000\n", 16, xmlsec.SigHMACSHA256)
	spaced = strings.Replace(spaced, `<xenc11:MasterKeyName>`, `<xenc11:DerivedKeyName>d</xenc11:DerivedKeyName><xenc11:MasterKeyName>`, 1)
	derived, _ := pbkdf2.Key(sha256.New, "pw", salt, 1000, 16)
	doc, want := wrappedWith(t, xmlsec.KeyWrapAES128, derived, derivedKey(pbkdf2Method(salt, " 1000\n", 16, xmlsec.SigHMACSHA256)))
	if key, err := xenc.UnwrapEncryptedKeyPassword(covParse(t, doc), []byte("pw"), pbkdf2Allowed); err != nil || !bytes.Equal(key, want) {
		t.Fatalf("spaced IterationCount: %v", err)
	}
	if _, err := xenc.UnwrapEncryptedKeyPassword(covParse(t, spaced), []byte("pw"), pbkdf2Allowed); errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("DerivedKeyName: %v", err)
	}
}

// PBKDF2 as the KDF of a key agreement, with the shared secret as its
// password, as the W3C interop vectors use it: named, it derives the KEK
// computed here independently from the two DH keys.
func TestPBKDF2AsAgreementKDF(t *testing.T) {
	recipient, originator := dhKey(t, ffdhe2048), dhKey(t, ffdhe2048)
	zz := new(big.Int).Exp(originator.Y, recipient.X, recipient.P).FillBytes(make([]byte, 256))
	salt := bytes.Repeat([]byte{9}, 16)
	kek, _ := pbkdf2.Key(sha256.New, string(zz), salt, 1000, 32)
	am := `<xenc:AgreementMethod Algorithm="` + xmlsec.KeyAgreementDHES + `">` + pbkdf2Method(salt, "1000", 32, xmlsec.SigHMACSHA256) +
		`<xenc:OriginatorKeyInfo><ds:KeyValue><xenc:DHKeyValue><xenc:Public>` + base64.StdEncoding.EncodeToString(originator.Y.Bytes()) +
		`</xenc:Public></xenc:DHKeyValue></ds:KeyValue></xenc:OriginatorKeyInfo></xenc:AgreementMethod>`
	doc, want := wrappedWith(t, xmlsec.KeyWrapAES256, kek, am)
	opts := dhAllow(xmlsec.KeyAgreementDHES)
	if _, err := xenc.DecryptAgreedKeyDH(covParse(t, doc), recipient, opts); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("PBKDF2 not named: %v", err)
	}
	opts.AllowedKeyDerivationAlgorithms = []string{xmlsec.KeyDerivationPBKDF2}
	if key, err := xenc.DecryptAgreedKeyDH(covParse(t, doc), recipient, opts); err != nil || !bytes.Equal(key, want) {
		t.Fatalf("%x, %v", key, err)
	}
}
