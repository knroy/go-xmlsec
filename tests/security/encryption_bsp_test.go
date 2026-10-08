package security

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

// countingDecrypter records whether the private key was ever used.
type countingDecrypter struct {
	*rsa.PrivateKey
	calls int
}

func (d *countingDecrypter) Decrypt(r io.Reader, ct []byte, o crypto.DecrypterOpts) ([]byte, error) {
	d.calls++
	return d.PrivateKey.Decrypt(r, ct, o)
}

func bspRecipient(t *testing.T) (*rsa.PrivateKey, xenc.EncryptOptions) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "r"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return k, xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyTransportRSAOAEP,
		MGFAlgorithm: xmlsec.MGF1SHA256, DigestAlgorithm: xmlsec.DigestSHA256, Recipient: cert}
}

// reparseEl round-trips an element through its canonical octets.
func reparseEl(t *testing.T, el *xdm.Node) *xdm.Node {
	t.Helper()
	b, err := c14n.Bytes(el, c14n.Options{Algorithm: c14n.Exclusive10})
	if err != nil {
		t.Fatal(err)
	}
	return legacyParse(t, string(b))
}

// DecryptOptions.StrictBSP refuses an EncryptedKey the Basic Security
// Profile forbids (here a Recipient attribute, R5602) before the private
// key is touched; without it the same EncryptedKey decrypts.
func TestStrictBSPRefusesBeforeKeyTransport(t *testing.T) {
	k, opts := bspRecipient(t)
	opts.RecipientHint = "Bert"
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	el := reparseEl(t, ek.Element)
	dec := &countingDecrypter{PrivateKey: k}
	if _, err := xenc.DecryptEncryptedKey(el, dec, xenc.DecryptOptions{StrictBSP: true}); !errors.Is(err, xmlsec.ErrMalformed) || dec.calls != 0 {
		t.Fatalf("strict: %v, %d decryptions", err, dec.calls)
	}
	key, err := xenc.DecryptEncryptedKey(el, dec, xenc.DecryptOptions{})
	if err != nil || !bytes.Equal(key, ek.SessionKey) || dec.calls != 1 {
		t.Fatalf("lax: %v, %d decryptions", err, dec.calls)
	}
}

// SOAP Message Security 1.1.1 section 12: every decryption failure is the
// one xmlsec.ErrDecryptionFailed, with no detail, whatever failed: a wrong
// RSA key, a wrong key-wrap KEK, a wrong data key, a tampered tag, bad CBC
// padding, or a decrypted EncryptedHeader that is not one element.
func TestDecryptionFailureIsGeneric(t *testing.T) {
	_, opts := bspRecipient(t)
	other, _ := bspRecipient(t)
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	kw := opts
	kw.KeyTransportAlgorithm, kw.Recipient, kw.KeyEncryptionKey = xmlsec.KeyWrapAES128, nil, bytes.Repeat([]byte{1}, 16)
	kw.MGFAlgorithm, kw.DigestAlgorithm = "", ""
	wrapped, err := xenc.GenerateEncryptedKey(kw)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 16)
	b, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(b)
	iv := make([]byte, 12)
	gcmED := func(pt string, tamper bool) string {
		ct := a.Seal(iv, iv, []byte(pt), nil)
		if tamper {
			ct[len(ct)-1] ^= 1
		}
		return `<xenc:EncryptedData xmlns:xenc="` + xmlsec.NSXEnc + `" Type="` + xenc.TypeElement + `"><xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128GCM + `"/>` +
			legacyCV(ct) + `</xenc:EncryptedData>`
	}
	cbc := xmlsec.EncAES128CBC
	header := legacyParse(t, `<S:Envelope xmlns:S="`+xmlsec.NSSOAP12+`"><S:Header><wsse11:EncryptedHeader xmlns:wsse11="`+xmlsec.NSWSSE11+`">`+
		gcmED(`<a/><b/>`, false)+`</wsse11:EncryptedHeader></S:Header></S:Envelope>`)
	for name, run := range map[string]func() error{
		"wrong RSA key": func() error {
			_, err := xenc.DecryptEncryptedKey(reparseEl(t, ek.Element), other, xenc.DecryptOptions{})
			return err
		},
		"wrong KEK": func() error {
			_, err := xenc.UnwrapEncryptedKey(reparseEl(t, wrapped.Element), bytes.Repeat([]byte{2}, 16), xenc.DecryptOptions{})
			return err
		},
		"wrong data key": func() error {
			_, err := xenc.DecryptData(legacyParse(t, gcmED(`<a/>`, false)), bytes.Repeat([]byte{8}, 16), xenc.DecryptOptions{})
			return err
		},
		"data key of the wrong size": func() error {
			_, err := xenc.DecryptData(legacyParse(t, gcmED(`<a/>`, false)), bytes.Repeat([]byte{7}, 32), xenc.DecryptOptions{})
			return err
		},
		"tampered tag": func() error {
			_, err := xenc.DecryptData(legacyParse(t, gcmED(`<a/>`, true)), key, xenc.DecryptOptions{})
			return err
		},
		"bad CBC padding": func() error {
			_, err := xenc.DecryptData(legacyED(t, cbc, cbcSeal(t, cbc, key, []byte("abc"), 0)), key, xenc.DecryptOptions{AllowedDataAlgorithms: []string{cbc}})
			return err
		},
		"EncryptedHeader not one element": func() error {
			_, err := xenc.DecryptHeader(header, header.ChildElements()[0].ChildElements()[0], key, xenc.DecryptOptions{})
			return err
		},
	} {
		err := run()
		if !errors.Is(err, xmlsec.ErrDecryptionFailed) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if msg := err.Error(); msg != "xenc: decryption failed" && msg != "xenc: key unwrap failed" {
			t.Errorf("%s: detail in %q", name, msg)
		}
	}
}
