package xenc_test

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

var cbcAlgs = []string{xmlsec.EncAES128CBC, xmlsec.EncAES192CBC, xmlsec.EncAES256CBC, xmlsec.EncTripleDESCBC}

func cbcBlock(t *testing.T, alg string, key []byte) cipher.Block {
	t.Helper()
	var b cipher.Block
	var err error
	if alg == xmlsec.EncTripleDESCBC {
		b, err = des.NewTripleDESCipher(key)
	} else {
		b, err = aes.NewCipher(key)
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cbcKey(alg string) []byte {
	return bytes.Repeat([]byte{5}, map[string]int{
		xmlsec.EncAES128CBC: 16, xmlsec.EncAES192CBC: 24, xmlsec.EncAES256CBC: 32, xmlsec.EncTripleDESCBC: 24}[alg])
}

// cbcSeal is the sender of sections 5.2.1 to 5.2.3: IV || CBC(pt || pad),
// the pad N-1 random octets and N. last, if non-negative, replaces the
// final octet, to forge a bad padding.
func cbcSeal(t *testing.T, alg string, key, pt []byte, last int) []byte {
	t.Helper()
	b := cbcBlock(t, alg, key)
	bs := b.BlockSize()
	n := bs - len(pt)%bs
	pad := make([]byte, n)
	rand.Read(pad)
	pad[n-1] = byte(n)
	padded := append(slices.Clone(pt), pad...)
	if last >= 0 {
		padded[len(padded)-1] = byte(last)
	}
	out := make([]byte, bs+len(padded))
	rand.Read(out[:bs])
	cipher.NewCBCEncrypter(b, out[:bs]).CryptBlocks(out[bs:], padded)
	return out
}

func cvOf(b []byte) string {
	return `<xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(b) + `</xenc:CipherValue></xenc:CipherData>`
}

func cbcED(t *testing.T, alg, method string, ct []byte) *xdm.Node {
	t.Helper()
	return covParse(t, covED(`Type="`+xenc.TypeElement+`"`,
		`<xenc:EncryptionMethod Algorithm="`+alg+`">`+method+`</xenc:EncryptionMethod>`+cvOf(ct)))
}

// CBC data decrypts only when its algorithm is named, whatever the padding
// length, and only the last pad octet is checked.
func TestLegacyCBCDecrypt(t *testing.T) {
	for _, alg := range cbcAlgs {
		for _, pt := range []string{"", "a", "<a>0123456789abcdef</a>", "0123456789abcdef"} {
			key := cbcKey(alg)
			ed := cbcED(t, alg, ``, cbcSeal(t, alg, key, []byte(pt), -1))
			got, err := xenc.DecryptData(ed, key, []string{alg})
			if err != nil || string(got) != pt {
				t.Fatalf("%s %q: %q, %v", alg, pt, got, err)
			}
			for _, list := range [][]string{nil, {xmlsec.EncAES128GCM, xmlsec.EncAES192GCM, xmlsec.EncAES256GCM}} {
				if _, err := xenc.DecryptData(ed, key, list); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
					t.Fatalf("%s under %v: %v", alg, list, err)
				}
			}
		}
	}
	// KeySize is checked against the CBC key size.
	key := cbcKey(xmlsec.EncAES256CBC)
	ct := cbcSeal(t, xmlsec.EncAES256CBC, key, []byte("x"), -1)
	if got, err := xenc.DecryptData(cbcED(t, xmlsec.EncAES256CBC, `<xenc:KeySize>256</xenc:KeySize>`, ct), key, []string{xmlsec.EncAES256CBC}); err != nil || string(got) != "x" {
		t.Fatalf("KeySize 256: %q, %v", got, err)
	}
	if _, err := xenc.DecryptData(cbcED(t, xmlsec.EncAES256CBC, `<xenc:KeySize>128</xenc:KeySize>`, ct), key, []string{xmlsec.EncAES256CBC}); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("KeySize 128: %v", err)
	}
}

// Padding-oracle regression (section 6.1.1): every way CBC decryption can
// fail returns one error, identical in value and text, so no failure mode
// is distinguishable from another.
func TestLegacyCBCFailuresIndistinguishable(t *testing.T) {
	for _, alg := range cbcAlgs {
		t.Run(alg, func(t *testing.T) {
			key := cbcKey(alg)
			bs := cbcBlock(t, alg, key).BlockSize()
			good := cbcSeal(t, alg, key, []byte("<a>plaintext</a>"), -1)
			wrongKey := bytes.Repeat([]byte{6}, len(key))
			var zeroPad []byte // a wrong key that yields a bad pad
			for zeroPad == nil {
				ct := cbcSeal(t, alg, wrongKey, []byte("<a>plaintext</a>"), -1)
				pt := make([]byte, len(ct)-bs)
				cipher.NewCBCDecrypter(cbcBlock(t, alg, key), ct[:bs]).CryptBlocks(pt, ct[bs:])
				if n := int(pt[len(pt)-1]); n == 0 || n > bs {
					zeroPad = ct
				}
			}
			cases := map[string]struct {
				ct, key []byte
			}{
				"pad octet 0":             {cbcSeal(t, alg, key, []byte("abc"), 0), key},
				"pad octet over block":    {cbcSeal(t, alg, key, []byte("abc"), bs+1), key},
				"pad octet 255":           {cbcSeal(t, alg, key, []byte("abc"), 255), key},
				"wrong key, bad pad":      {zeroPad, key},
				"IV only":                 {good[:bs], key},
				"empty":                   {nil, key},
				"not whole blocks":        {good[:len(good)-1], key},
				"session key too short":   {good, key[:len(key)-8]},
				"session key of AES size": {good, make([]byte, 20)},
			}
			var first error
			for name, c := range cases {
				pt, err := xenc.DecryptData(cbcED(t, alg, ``, c.ct), c.key, []string{alg})
				if err == nil || pt != nil {
					t.Fatalf("%s: decrypted %q", name, pt)
				}
				if first == nil {
					first = err
				}
				if err != first || err.Error() != "xenc: decryption failed" {
					t.Fatalf("%s: %v differs from %v", name, err, first)
				}
				if errors.Is(err, xmlsec.ErrMalformed) || errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
					t.Fatalf("%s: classified as %v", name, err)
				}
			}
			// The same holds for an attachment.
			ed := covParse(t, covED(`Type="`+xmlsec.TransformAttachmentContentOnly+`"`, covEM(alg)+
				`<xenc:CipherData><xenc:CipherReference URI="cid:a"/></xenc:CipherData>`))
			if _, err := xenc.DecryptAttachment(ed, cases["pad octet 0"].ct, key, []string{alg}); err != first {
				t.Fatalf("attachment: %v", err)
			}
			att, err := xenc.DecryptAttachment(ed, cbcSeal(t, alg, key, []byte("body"), -1), key, []string{alg})
			if err != nil || string(att.Body) != "body" {
				t.Fatalf("attachment: %v", err)
			}
		})
	}
}

// No encryption function produces a legacy algorithm.
func TestLegacyNeverProduced(t *testing.T) {
	tree, err := xmlsec.Parse([]byte(`<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope"><S:Header>` +
		`<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"/><h/></S:Header>` +
		`<S:Body><p>x</p></S:Body></S:Envelope>`))
	if err != nil {
		t.Fatal(err)
	}
	env := xmltree.DocumentElement(tree.Root)
	hdr, body := env.ChildElements()[0], env.ChildElements()[1]
	for _, alg := range cbcAlgs {
		opts := as4Opts(t)
		opts.DataAlgorithm = alg
		key := cbcKey(alg)
		_, err1 := xenc.EncryptElement(tree.Root, body.ChildElements()[0], key, opts)
		_, err2 := xenc.EncryptContent(tree.Root, body, key, opts)
		_, err3 := xenc.EncryptHeader(tree.Root, hdr.ChildElements()[1], hdr.ChildElements()[0], key, opts)
		_, _, err4 := xenc.EncryptAttachment(&xmlsec.Attachment{ID: "a", Body: []byte("b")}, key, xmlsec.TransformAttachmentContentOnly, opts)
		for i, err := range []error{err1, err2, err3, err4} {
			if !errors.Is(err, xmlsec.ErrUnsupportedAlgorithm) || !strings.Contains(err.Error(), "decryption only") {
				t.Errorf("%s, function %d: %v", alg, i, err)
			}
		}
	}
	for _, c := range []struct {
		name string
		mod  func(*xenc.EncryptOptions, string)
		algs []string
	}{
		{"data", func(o *xenc.EncryptOptions, a string) { o.DataAlgorithm = a }, cbcAlgs},
		{"key transport", func(o *xenc.EncryptOptions, a string) { o.KeyTransportAlgorithm = a },
			[]string{xmlsec.KeyTransportRSAOAEPMGF1P, xmlsec.KeyTransportRSA15, xmlsec.KeyWrapTripleDES}},
		{"MGF", func(o *xenc.EncryptOptions, a string) { o.MGFAlgorithm = a }, []string{xmlsec.MGF1SHA1}},
		{"digest", func(o *xenc.EncryptOptions, a string) { o.DigestAlgorithm = a }, []string{xmlsec.DigestSHA1}},
	} {
		for _, alg := range c.algs {
			opts := as4Opts(t)
			c.mod(&opts, alg)
			if alg == xmlsec.KeyWrapTripleDES {
				opts.Recipient, opts.KeyEncryptionKey = nil, make([]byte, 24)
			}
			ek, err := xenc.GenerateEncryptedKey(opts)
			if ek != nil || !errors.Is(err, xmlsec.ErrUnsupportedAlgorithm) || !strings.Contains(err.Error(), "decryption only") {
				t.Errorf("%s %s: %v", c.name, alg, err)
			}
		}
	}
}

// oaepEK is an EncryptedKey carrying key under RSA-OAEP with the given
// hashes, and method as the EncryptionMethod content.
func oaepEK(t *testing.T, alg, method string, digest, mgf crypto.Hash, key []byte) *xdm.Node {
	t.Helper()
	ct, err := rsa.EncryptOAEPWithOptions(rand.Reader, &recipientKey.PublicKey, key, &rsa.OAEPOptions{Hash: digest, MGFHash: mgf})
	if err != nil {
		t.Fatal(err)
	}
	return covParse(t, covEK(alg, method, cvOf(ct)))
}

// rsa-oaep-mgf1p, and RSA-OAEP with an implicit or explicit SHA-1 MGF or
// digest, decrypt only when every SHA-1 part is named.
func TestLegacyOAEPSHA1(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 16)
	sha1DM := `<ds:DigestMethod Algorithm="` + xmlsec.DigestSHA1 + `"/>`
	sha256DM := `<ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"/>`
	sha1MGF := `<xenc11:MGF Algorithm="` + xmlsec.MGF1SHA1 + `"/>`
	mgf1p, oaep := xmlsec.KeyTransportRSAOAEPMGF1P, xmlsec.KeyTransportRSAOAEP
	all := [3][]string{{mgf1p, oaep}, {xmlsec.MGF1SHA1}, {xmlsec.DigestSHA1}}
	for _, c := range []struct {
		name   string
		el     *xdm.Node
		lists  [3][]string
		denied [][3][]string // each refused with ErrAlgorithmNotAllowed
	}{
		{"mgf1p, implicit SHA-1 digest", oaepEK(t, mgf1p, ``, crypto.SHA1, crypto.SHA1, key), all,
			[][3][]string{{}, {nil, {xmlsec.MGF1SHA1}, {xmlsec.DigestSHA1}}, {{mgf1p}, nil, {xmlsec.DigestSHA1}}, {{mgf1p}, {xmlsec.MGF1SHA1}, nil}}},
		{"mgf1p, explicit SHA-1 digest", oaepEK(t, mgf1p, sha1DM, crypto.SHA1, crypto.SHA1, key), all,
			[][3][]string{{{mgf1p}, {xmlsec.MGF1SHA1}, {xmlsec.DigestSHA256}}}},
		{"mgf1p, SHA-256 digest", oaepEK(t, mgf1p, sha256DM, crypto.SHA256, crypto.SHA1, key), [3][]string{{mgf1p}, {xmlsec.MGF1SHA1}},
			[][3][]string{{{mgf1p}, {xmlsec.MGF1SHA256}}}},
		{"rsa-oaep, both implicit", oaepEK(t, oaep, ``, crypto.SHA1, crypto.SHA1, key), [3][]string{nil, {xmlsec.MGF1SHA1}, {xmlsec.DigestSHA1}},
			[][3][]string{{}, {nil, {xmlsec.MGF1SHA1}}, {nil, nil, {xmlsec.DigestSHA1}}}},
		{"rsa-oaep, explicit SHA-1 MGF", oaepEK(t, oaep, sha256DM+sha1MGF, crypto.SHA256, crypto.SHA1, key), [3][]string{2: nil, 1: {xmlsec.MGF1SHA1}},
			[][3][]string{{}}},
		{"rsa-oaep, explicit SHA-1 digest", oaepEK(t, oaep, sha1DM+`<xenc11:MGF Algorithm="`+xmlsec.MGF1SHA256+`"/>`, crypto.SHA1, crypto.SHA256, key),
			[3][]string{2: {xmlsec.DigestSHA1}}, [][3][]string{{}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := xenc.DecryptEncryptedKey(c.el, recipientKey, c.lists[0], c.lists[1], c.lists[2])
			if err != nil || !bytes.Equal(got, key) {
				t.Fatalf("%x, %v", got, err)
			}
			for _, l := range c.denied {
				if _, err := xenc.DecryptEncryptedKey(c.el, recipientKey, l[0], l[1], l[2]); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
					t.Fatalf("under %v: %v", l, err)
				}
			}
		})
	}

	// Section 5.5.2: rsa-oaep-mgf1p MUST NOT carry xenc11:MGF.
	withMGF := oaepEK(t, mgf1p, sha1DM+sha1MGF, crypto.SHA1, crypto.SHA1, key)
	if _, err := xenc.DecryptEncryptedKey(withMGF, recipientKey, all[0], all[1], all[2]); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("mgf1p with MGF: %v", err)
	}
	// The implicit forms are reported as such.
	_, err := xenc.DecryptEncryptedKey(oaepEK(t, oaep, ``, crypto.SHA1, crypto.SHA1, key), recipientKey, nil, nil, nil)
	if !strings.Contains(err.Error(), "implicit MGF") {
		t.Fatalf("implicit MGF reported as %v", err)
	}
	_, err = xenc.DecryptEncryptedKey(oaepEK(t, oaep, ``, crypto.SHA1, crypto.SHA1, key), recipientKey, nil, []string{xmlsec.MGF1SHA1}, nil)
	if !strings.Contains(err.Error(), "implicit OAEP digest") {
		t.Fatalf("implicit digest reported as %v", err)
	}
	// rsa-1_5 is not DecryptEncryptedKey's even when allowed.
	v15 := covParse(t, covEK(xmlsec.KeyTransportRSA15, ``, cvOf(make([]byte, 256))))
	if _, err := xenc.DecryptEncryptedKey(v15, recipientKey, []string{xmlsec.KeyTransportRSA15}, nil, nil); !errors.Is(err, xmlsec.ErrUnsupportedAlgorithm) ||
		!strings.Contains(err.Error(), "DecryptEncryptedKeyPKCS1v15") {
		t.Fatalf("rsa-1_5: %v", err)
	}
}

// v15EK is an EncryptedKey carrying key under RSA PKCS#1 v1.5.
func v15EK(t *testing.T, method string, key []byte) *xdm.Node {
	t.Helper()
	//lint:ignore SA1019 the test sender of the decryption-only rsa-1_5
	ct, err := rsa.EncryptPKCS1v15(rand.Reader, &recipientKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return covParse(t, covEK(xmlsec.KeyTransportRSA15, method, cvOf(ct)))
}

// shortDecrypter answers every Decrypt with a key one octet short.
type shortDecrypter struct{ *rsa.PrivateKey }

func (d shortDecrypter) Decrypt(io.Reader, []byte, crypto.DecrypterOpts) ([]byte, error) {
	return make([]byte, 23), nil
}

// RSA v1.5 is decrypted only by DecryptEncryptedKeyPKCS1v15 and only when
// named, and rejects implicitly (section 6.1.2): a bad block yields a random
// key of the data algorithm's size and no error, and the failure surfaces
// only as the generic data decryption error.
func TestLegacyRSA15(t *testing.T) {
	v15 := []string{xmlsec.KeyTransportRSA15}
	tdes := []string{xmlsec.EncTripleDESCBC}
	key := bytes.Repeat([]byte{7}, 24)
	ed := cbcED(t, xmlsec.EncTripleDESCBC, ``, cbcSeal(t, xmlsec.EncTripleDESCBC, key, []byte("<a/>"), -1))
	ek := v15EK(t, ``, key)

	got, err := xenc.DecryptEncryptedKeyPKCS1v15(ek, ed, recipientKey, v15, tdes)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("%x, %v", got, err)
	}
	if pt, err := xenc.DecryptData(ed, got, tdes); err != nil || string(pt) != "<a/>" {
		t.Fatalf("data: %q, %v", pt, err)
	}
	// An AES-GCM key, and a KeySize equal to the modulus.
	gcmKey := bytes.Repeat([]byte{8}, 16)
	gcmED := covParse(t, covED(``, covEM(xmlsec.EncAES128GCM)+cvOf(sealGCM(gcmKey, "x"))))
	if got, err := xenc.DecryptEncryptedKeyPKCS1v15(v15EK(t, `<xenc:KeySize>2048</xenc:KeySize>`, gcmKey), gcmED, recipientKey, v15, nil); err != nil || !bytes.Equal(got, gcmKey) {
		t.Fatalf("GCM key: %x, %v", got, err)
	}

	// Implicit rejection: a key of another length inside valid padding, a
	// corrupted block, a ciphertext of the wrong length, and a Decrypter
	// that returns the wrong length all give a fresh random key.
	cv, _ := xmltree.Base64(ek.ChildElements()[1].ChildElements()[0])
	cv[len(cv)/2] ^= 1
	bad := map[string]struct {
		el  *xdm.Node
		dec crypto.Decrypter
	}{
		"16-octet key for 3DES": {v15EK(t, ``, key[:16]), recipientKey},
		"corrupted block":       {covParse(t, covEK(xmlsec.KeyTransportRSA15, ``, cvOf(cv))), recipientKey},
		"short ciphertext":      {covParse(t, covEK(xmlsec.KeyTransportRSA15, ``, cvOf(cv[1:]))), recipientKey},
		"short Decrypter":       {ek, shortDecrypter{recipientKey}},
	}
	for name, c := range bad {
		k1, err1 := xenc.DecryptEncryptedKeyPKCS1v15(c.el, ed, c.dec, v15, tdes)
		k2, err2 := xenc.DecryptEncryptedKeyPKCS1v15(c.el, ed, c.dec, v15, tdes)
		if err1 != nil || err2 != nil || len(k1) != 24 || len(k2) != 24 || bytes.Equal(k1, k2) || bytes.Equal(k1, key) {
			t.Fatalf("%s: %x %v, %x %v", name, k1, err1, k2, err2)
		}
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		el    *xdm.Node
		ed    *xdm.Node
		dec   crypto.Decrypter
		lists [2][]string
		want  error // nil: any error
	}{
		{"default key transport", ek, ed, recipientKey, [2][]string{nil, tdes}, xmlsec.ErrAlgorithmNotAllowed},
		{"default data", ek, ed, recipientKey, [2][]string{v15, nil}, xmlsec.ErrAlgorithmNotAllowed},
		{"OAEP key transport", covParse(t, covEK(xmlsec.KeyTransportRSAOAEP, ``, cvOf(make([]byte, 256)))), ed, recipientKey,
			[2][]string{{xmlsec.KeyTransportRSAOAEP}, tdes}, xmlsec.ErrUnsupportedAlgorithm},
		{"not an EncryptedKey", ed, ed, recipientKey, [2][]string{v15, tdes}, xmlsec.ErrMalformed},
		{"nil EncryptedKey", nil, ed, recipientKey, [2][]string{v15, tdes}, xmlsec.ErrMalformed},
		{"nil Decrypter", ek, ed, nil, [2][]string{v15, tdes}, nil},
		{"no EncryptionMethod", covParse(t, `<xenc:EncryptedKey xmlns:xenc="`+xenc.NSXEnc+`">`+cvOf(nil)+`</xenc:EncryptedKey>`), ed, recipientKey,
			[2][]string{v15, tdes}, xmlsec.ErrMalformed},
		{"nil EncryptedData", ek, nil, recipientKey, [2][]string{v15, tdes}, xmlsec.ErrMalformed},
		{"EC key", ek, ed, ecDecrypter{pub: &ecKey.PublicKey}, [2][]string{v15, tdes}, xmlsec.ErrUnsupportedAlgorithm},
		{"KeySize of the session key", v15EK(t, `<xenc:KeySize>192</xenc:KeySize>`, key), ed, recipientKey, [2][]string{v15, tdes}, xmlsec.ErrMalformed},
		{"DigestMethod", v15EK(t, `<ds:DigestMethod Algorithm="`+xmlsec.DigestSHA256+`"/>`, key), ed, recipientKey, [2][]string{v15, tdes}, xmlsec.ErrMalformed},
		{"CipherValue not base64", covParse(t, covEK(xmlsec.KeyTransportRSA15, ``, `<xenc:CipherData><xenc:CipherValue>!!</xenc:CipherValue></xenc:CipherData>`)), ed, recipientKey,
			[2][]string{v15, tdes}, xmlsec.ErrMalformed},
	} {
		t.Run(c.name, func(t *testing.T) {
			k, err := xenc.DecryptEncryptedKeyPKCS1v15(c.el, c.ed, c.dec, c.lists[0], c.lists[1])
			if k != nil || err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %x, %v, want %v", k, err, c.want)
			}
		})
	}

	// The data decryption that follows a rejected block fails like any
	// other wrong key.
	k, _ := xenc.DecryptEncryptedKeyPKCS1v15(bad["corrupted block"].el, gcmED, recipientKey, v15, nil)
	_, errGCM := xenc.DecryptData(gcmED, k, nil)
	_, errWrong := xenc.DecryptData(gcmED, bytes.Repeat([]byte{9}, 16), nil)
	if errGCM == nil || errGCM != errWrong {
		t.Fatalf("rejected key: %v, wrong key: %v", errGCM, errWrong)
	}
}

// cmsWrap is the RFC 3217 section 3.1 Triple-DES key wrap, without the
// parity adjustment, which unwrapping does not check.
func cmsWrap(t *testing.T, kek, key []byte) []byte {
	t.Helper()
	b := cbcBlock(t, xmlsec.EncTripleDESCBC, kek)
	sum := sha1.Sum(key)
	wkcks := append(slices.Clone(key), sum[:8]...)
	temp2 := make([]byte, 8+len(wkcks))
	rand.Read(temp2[:8])
	cipher.NewCBCEncrypter(b, temp2[:8]).CryptBlocks(temp2[8:], wkcks)
	slices.Reverse(temp2)
	out := make([]byte, len(temp2))
	cipher.NewCBCEncrypter(b, []byte{0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05}).CryptBlocks(out, temp2)
	return out
}

func kwTDES(t *testing.T, ct []byte) *xdm.Node {
	t.Helper()
	return covParse(t, covEK(xmlsec.KeyWrapTripleDES, ``, cvOf(ct)))
}

// kw-tripledes unwraps only when named.
func TestLegacyTripleDESKeyWrap(t *testing.T) {
	kek := bytes.Repeat([]byte{0x11, 0x22, 0x33}, 8)
	list := []string{xmlsec.KeyWrapTripleDES}
	for _, n := range []int{24, 16, 32} {
		key := bytes.Repeat([]byte{byte(n)}, n)
		el := kwTDES(t, cmsWrap(t, kek, key))
		if got, err := xenc.UnwrapEncryptedKey(el, kek, list); err != nil || !bytes.Equal(got, key) {
			t.Fatalf("%d-octet key: %x, %v", n, got, err)
		}
		if _, err := xenc.UnwrapEncryptedKey(el, kek, nil); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
			t.Fatalf("default set: %v", err)
		}
	}
	good := cmsWrap(t, kek, bytes.Repeat([]byte{1}, 24))
	flipped := slices.Clone(good)
	flipped[0] ^= 1
	var first error
	for name, ct := range map[string][]byte{
		"tampered":         flipped,
		"wrong KEK":        cmsWrap(t, bytes.Repeat([]byte{9}, 24), bytes.Repeat([]byte{1}, 24)),
		"not whole blocks": good[:39],
		"too short":        good[:16],
		"empty":            nil,
	} {
		got, err := xenc.UnwrapEncryptedKey(kwTDES(t, ct), kek, list)
		if got != nil || err == nil {
			t.Fatalf("%s: %x", name, got)
		}
		if first == nil {
			first = err
		}
		if err != first {
			t.Fatalf("%s: %v differs from %v", name, err, first)
		}
	}
	if _, err := xenc.UnwrapEncryptedKey(kwTDES(t, good), kek[:16], list); err == nil {
		t.Fatal("16-octet KEK accepted")
	}
	if _, err := xenc.UnwrapEncryptedKey(kwTDES(t, good), kek, []string{xmlsec.KeyWrapAES128}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("AES list: %v", err)
	}
	if _, err := xenc.UnwrapEncryptedKey(covParse(t, covEK(xmlsec.KeyWrapTripleDES, `<xenc:KeySize>128</xenc:KeySize>`, cvOf(good))), kek, list); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("KeySize: %v", err)
	}
}
