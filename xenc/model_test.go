package xenc_test

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- the test sender of the SHA-1 an implied rsa-oaep means
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

// Sections 3.1 and 3.2: without an EncryptionMethod the algorithm must be
// known to the recipient. DecryptOptions names it, and it passes the same
// allow-list an explicit one would.
func TestImpliedAlgorithms(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	ed := covParse(t, covED(``, cvOf(sealGCM(key, "x"))))
	implied := xenc.DecryptOptions{ImpliedDataAlgorithm: xmlsec.EncAES128GCM}
	if pt, err := xenc.DecryptData(ed, key, implied); err != nil || string(pt) != "x" {
		t.Fatalf("implied data: %q, %v", pt, err)
	}
	for _, c := range []struct {
		name string
		el   string
		opts xenc.DecryptOptions
		want error
	}{
		{"not implied", covED(``, cvOf(sealGCM(key, "x"))), xenc.DecryptOptions{}, xmlsec.ErrMalformed},
		{"implied outside allow-list", covED(``, cvOf(sealGCM(key, "x"))), xenc.DecryptOptions{ImpliedDataAlgorithm: xmlsec.EncAES128CBC}, xmlsec.ErrAlgorithmNotAllowed},
		{"EncryptionMethod out of place", covED(``, cvOf(sealGCM(key, "x"))+covEM(xmlsec.EncAES128GCM)), implied, xmlsec.ErrMalformed},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := xenc.DecryptData(covParse(t, c.el), key, c.opts); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}

	// A wrapped key.
	kek := bytes.Repeat([]byte{3}, 16)
	ek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES128, KeyEncryptionKey: kek})
	if err != nil {
		t.Fatal(err)
	}
	noMethod := strings.Replace(dkString(t, ek.Element), covEMCanon(xmlsec.KeyWrapAES128), ``, 1)
	if _, err := xenc.UnwrapEncryptedKey(covParse(t, noMethod), kek, xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("no implied wrap: %v", err)
	}
	if got, err := xenc.UnwrapEncryptedKey(covParse(t, noMethod), kek, xenc.DecryptOptions{ImpliedKeyWrapAlgorithm: xmlsec.KeyWrapAES128}); err != nil || !bytes.Equal(got, ek.SessionKey) {
		t.Fatalf("implied wrap: %v", err)
	}

	// RSA-OAEP without an EncryptionMethod has no DigestMethod or MGF
	// either: both are SHA-1, accepted only when named.
	ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &recipientKey.PublicKey, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	rsaEK := covParse(t, `<xenc:EncryptedKey xmlns:xenc="`+xmlsec.NSXEnc+`">`+cvOf(ct)+`</xenc:EncryptedKey>`)
	opts := xenc.DecryptOptions{ImpliedKeyTransportAlgorithm: xmlsec.KeyTransportRSAOAEP}
	if _, err := xenc.DecryptEncryptedKey(rsaEK, recipientKey, opts); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("implied SHA-1: %v", err)
	}
	opts.AllowedMGFAlgorithms, opts.AllowedDigestAlgorithms = []string{xmlsec.MGF1SHA1}, []string{xmlsec.DigestSHA1}
	if got, err := xenc.DecryptEncryptedKey(rsaEK, recipientKey, opts); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("implied rsa-oaep: %v", err)
	}
	if _, err := xenc.DecryptEncryptedKeyPKCS1v15(rsaEK, ed, recipientKey, xenc.DecryptOptions{ImpliedKeyTransportAlgorithm: xmlsec.KeyTransportRSA15}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("implied rsa-1_5 not named: %v", err)
	}
}

// covEMCanon is an EncryptionMethod as canonical XML writes it.
func covEMCanon(alg string) string {
	return `<xenc:EncryptionMethod Algorithm="` + alg + `"></xenc:EncryptionMethod>`
}

// Section 5.8.3: the SHA-384 identifier of XML Encryption is accepted as
// the RSA-OAEP, ConcatKDF and Legacy KDF digest on encryption too, and
// emitted as given.
func TestDigestSHA384XMLEnc(t *testing.T) {
	const sha384 = xmlsec.DigestSHA384XMLEnc
	oaep := as4Opts(t)
	oaep.DigestAlgorithm = sha384
	ek, err := xenc.GenerateEncryptedKey(oaep)
	if err != nil {
		t.Fatal(err)
	}
	if key, err := xenc.DecryptEncryptedKey(reparse(t, ek.Element), recipientKey, xenc.DecryptOptions{}); err != nil || !bytes.Equal(key, ek.SessionKey) {
		t.Fatalf("RSA-OAEP: %v", err)
	}

	r := newECRecipient(t, elliptic.P256(), xmlsec.KeyWrapAES128)
	r.opts.DigestAlgorithm = sha384
	ek, err = xenc.GenerateEncryptedKey(r.opts)
	if err != nil {
		t.Fatal(err)
	}
	if key, err := xenc.DecryptAgreedKey(reparse(t, ek.Element), r.priv, xenc.DecryptOptions{}); err != nil || !bytes.Equal(key, ek.SessionKey) {
		t.Fatalf("ECDH-ES: %v", err)
	}

	dh := dhKey(t, modp2048)
	ek, err = xenc.GenerateEncryptedKey(dhOpts(dh, xmlsec.KeyAgreementDH, xmlsec.KeyWrapAES128, sha384))
	if err != nil {
		t.Fatal(err)
	}
	if key, err := xenc.DecryptAgreedKeyDH(reparse(t, ek.Element), dh, dhAllow(xmlsec.KeyAgreementDH)); err != nil || !bytes.Equal(key, ek.SessionKey) {
		t.Fatalf("DH: %v", err)
	}

	master := bytes.Repeat([]byte{9}, 32)
	ed := dkEncrypt(t, xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, DigestAlgorithm: sha384, MasterKey: master})
	if !strings.Contains(dkString(t, ed), `Algorithm="`+sha384+`"`) {
		t.Fatal("digest not emitted as given")
	}
	dk, err := xenc.FindDerivedKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	key, err := xenc.DeriveKey(dk, ed, master, xenc.DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{}); err != nil {
		t.Fatal(err)
	}
}
