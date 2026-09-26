package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"slices"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

// The legacy XML Encryption algorithms, built here as a peer sends them.

func legacyParse(t *testing.T, s string) *xdm.Node {
	t.Helper()
	tree, err := xmlsec.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return xmltree.DocumentElement(tree.Root)
}

func legacyCV(b []byte) string {
	return `<xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(b) + `</xenc:CipherValue></xenc:CipherData>`
}

func legacyED(t *testing.T, alg string, ct []byte) *xdm.Node {
	t.Helper()
	return legacyParse(t, `<xenc:EncryptedData xmlns:xenc="`+xmlsec.NSXEnc+`"><xenc:EncryptionMethod Algorithm="`+alg+`"/>`+legacyCV(ct)+`</xenc:EncryptedData>`)
}

func legacyEK(t *testing.T, alg, method string, ct []byte) *xdm.Node {
	t.Helper()
	return legacyParse(t, `<xenc:EncryptedKey xmlns:xenc="`+xmlsec.NSXEnc+`" xmlns:ds="`+xmlsec.NSDSig+`">`+
		`<xenc:EncryptionMethod Algorithm="`+alg+`">`+method+`</xenc:EncryptionMethod>`+legacyCV(ct)+`</xenc:EncryptedKey>`)
}

func legacyBlock(t *testing.T, alg string, key []byte) cipher.Block {
	t.Helper()
	newCipher := aes.NewCipher
	if alg == xmlsec.EncTripleDESCBC || alg == xmlsec.KeyWrapTripleDES {
		newCipher = des.NewTripleDESCipher
	}
	b, err := newCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// cbcSeal pads per section 5.2.1 with the last octet forced to last, or
// correctly when last is negative.
func cbcSeal(t *testing.T, alg string, key, pt []byte, last int) []byte {
	t.Helper()
	b := legacyBlock(t, alg, key)
	n := b.BlockSize() - len(pt)%b.BlockSize()
	padded := append(slices.Clone(pt), make([]byte, n)...)
	rand.Read(padded[len(pt):])
	padded[len(padded)-1] = byte(n)
	if last >= 0 {
		padded[len(padded)-1] = byte(last)
	}
	out := make([]byte, b.BlockSize()+len(padded))
	rand.Read(out[:b.BlockSize()])
	cipher.NewCBCEncrypter(b, out[:b.BlockSize()]).CryptBlocks(out[b.BlockSize():], padded)
	return out
}

// Each legacy algorithm is refused with empty allow-lists, which mean the
// default set, and decrypts when, and only when, the caller names it.
func TestLegacyEncryptionAlgorithmsOnlyWhenNamed(t *testing.T) {
	priv := rsaKey(t)
	pt := []byte("<secret>s</secret>")

	t.Run("CBC data", func(t *testing.T) {
		for alg, size := range map[string]int{xmlsec.EncAES128CBC: 16, xmlsec.EncAES192CBC: 24, xmlsec.EncAES256CBC: 32, xmlsec.EncTripleDESCBC: 24} {
			key := bytes.Repeat([]byte{1}, size)
			ed := legacyED(t, alg, cbcSeal(t, alg, key, pt, -1))
			if _, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
				t.Fatalf("%s, empty list: %v", alg, err)
			}
			if got, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{AllowedDataAlgorithms: []string{alg}}); err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("%s, named: %q, %v", alg, got, err)
			}
		}
	})

	t.Run("rsa-oaep-mgf1p", func(t *testing.T) {
		key := bytes.Repeat([]byte{2}, 16)
		ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &priv.PublicKey, key, nil)
		if err != nil {
			t.Fatal(err)
		}
		ek := legacyEK(t, xmlsec.KeyTransportRSAOAEPMGF1P, `<ds:DigestMethod Algorithm="`+xmlsec.DigestSHA1+`"/>`, ct)
		if _, err := xenc.DecryptEncryptedKey(ek, priv, xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
			t.Fatalf("empty lists: %v", err)
		}
		got, err := xenc.DecryptEncryptedKey(ek, priv, xenc.DecryptOptions{AllowedKeyTransportAlgorithms: []string{xmlsec.KeyTransportRSAOAEPMGF1P}, AllowedMGFAlgorithms: []string{xmlsec.MGF1SHA1}, AllowedDigestAlgorithms: []string{xmlsec.DigestSHA1}})
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("named: %x, %v", got, err)
		}
	})

	t.Run("rsa-oaep with implicit SHA-1", func(t *testing.T) {
		key := bytes.Repeat([]byte{3}, 16)
		ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &priv.PublicKey, key, nil)
		if err != nil {
			t.Fatal(err)
		}
		ek := legacyEK(t, xmlsec.KeyTransportRSAOAEP, ``, ct)
		for _, l := range [][2][]string{{}, {{xmlsec.MGF1SHA1}}, {1: {xmlsec.DigestSHA1}}} {
			if _, err := xenc.DecryptEncryptedKey(ek, priv, xenc.DecryptOptions{AllowedMGFAlgorithms: l[0], AllowedDigestAlgorithms: l[1]}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
				t.Fatalf("%v: %v", l, err)
			}
		}
		got, err := xenc.DecryptEncryptedKey(ek, priv, xenc.DecryptOptions{AllowedMGFAlgorithms: []string{xmlsec.MGF1SHA1}, AllowedDigestAlgorithms: []string{xmlsec.DigestSHA1}})
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("named: %x, %v", got, err)
		}
	})

	t.Run("rsa-1_5", func(t *testing.T) {
		key := bytes.Repeat([]byte{4}, 24)
		//lint:ignore SA1019 the test sender of the decryption-only rsa-1_5
		ct, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		ek := legacyEK(t, xmlsec.KeyTransportRSA15, ``, ct)
		ed := legacyED(t, xmlsec.EncTripleDESCBC, cbcSeal(t, xmlsec.EncTripleDESCBC, key, pt, -1))
		if _, err := xenc.DecryptEncryptedKey(ek, priv, xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
			t.Fatalf("DecryptEncryptedKey, empty lists: %v", err)
		}
		if _, err := xenc.DecryptEncryptedKeyPKCS1v15(ek, ed, priv, xenc.DecryptOptions{AllowedDataAlgorithms: []string{xmlsec.EncTripleDESCBC}}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
			t.Fatalf("empty key transport list: %v", err)
		}
		got, err := xenc.DecryptEncryptedKeyPKCS1v15(ek, ed, priv, xenc.DecryptOptions{AllowedKeyTransportAlgorithms: []string{xmlsec.KeyTransportRSA15}, AllowedDataAlgorithms: []string{xmlsec.EncTripleDESCBC}})
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("named: %x, %v", got, err)
		}
	})

	t.Run("kw-tripledes", func(t *testing.T) {
		kek, key := bytes.Repeat([]byte{5}, 24), bytes.Repeat([]byte{6}, 24)
		b := legacyBlock(t, xmlsec.KeyWrapTripleDES, kek)
		sum := sha1.Sum(key)
		temp := make([]byte, 40)
		rand.Read(temp[:8])
		cipher.NewCBCEncrypter(b, temp[:8]).CryptBlocks(temp[8:], append(slices.Clone(key), sum[:8]...))
		slices.Reverse(temp)
		cipher.NewCBCEncrypter(b, []byte{0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05}).CryptBlocks(temp, temp)
		ek := legacyEK(t, xmlsec.KeyWrapTripleDES, ``, temp)
		if _, err := xenc.UnwrapEncryptedKey(ek, kek, xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
			t.Fatalf("empty list: %v", err)
		}
		got, err := xenc.UnwrapEncryptedKey(ek, kek, xenc.DecryptOptions{AllowedKeyWrapAlgorithms: []string{xmlsec.KeyWrapTripleDES}})
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("named: %x, %v", got, err)
		}
	})
}

// Padding-oracle regression (XML Encryption 1.1 section 6.1.1): whatever
// is wrong with CBC ciphertext, the error is one value with one message, so
// a peer's error response cannot tell a bad pad from a bad length or a
// wrong key. (Timing is addressed in the implementation: the whole
// ciphertext is always decrypted and the pad judged in constant time.)
func TestCBCPaddingOracle(t *testing.T) {
	alg, key := xmlsec.EncAES128CBC, bytes.Repeat([]byte{7}, 16)
	good := cbcSeal(t, alg, key, []byte("abc"), -1)
	var first error
	for name, c := range map[string]struct{ ct, key []byte }{
		"pad octet 0":        {cbcSeal(t, alg, key, []byte("abc"), 0), key},
		"pad octet 17":       {cbcSeal(t, alg, key, []byte("abc"), 17), key},
		"truncated":          {good[:len(good)-3], key},
		"IV only":            {good[:16], key},
		"wrong key length":   {good, key[:8]},
		"AES-256 key length": {good, bytes.Repeat([]byte{7}, 32)},
	} {
		_, err := xenc.DecryptData(legacyED(t, alg, c.ct), c.key, xenc.DecryptOptions{AllowedDataAlgorithms: []string{alg}})
		if err == nil {
			t.Fatalf("%s: decrypted", name)
		}
		if first == nil {
			first = err
		}
		if err != first || err.Error() != first.Error() {
			t.Fatalf("%s: %v, distinguishable from %v", name, err, first)
		}
	}
	// A failed RSA v1.5 unwrap does not show either: it yields a key, and
	// the data then fails with that same error.
	priv := rsaKey(t)
	ek := legacyEK(t, xmlsec.KeyTransportRSA15, ``, make([]byte, 256))
	ed := legacyED(t, alg, good)
	k, err := xenc.DecryptEncryptedKeyPKCS1v15(ek, ed, priv, xenc.DecryptOptions{AllowedKeyTransportAlgorithms: []string{xmlsec.KeyTransportRSA15}, AllowedDataAlgorithms: []string{alg}})
	if err != nil || len(k) != 16 {
		t.Fatalf("implicit rejection: %x, %v", k, err)
	}
	// A random key leaves a valid pad with probability about 1/16, when
	// the data decrypts to garbage: that is the Bleichenbacher limit
	// section 6.1.2 describes, not a failure of this test.
	if _, err := xenc.DecryptData(ed, k, xenc.DecryptOptions{AllowedDataAlgorithms: []string{alg}}); err != nil && err != first {
		t.Fatalf("after implicit rejection: %v", err)
	}
}
