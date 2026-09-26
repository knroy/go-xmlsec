package security

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// resignWith replaces SignatureMethod, adding ds:HMACOutputLength when
// outputLength is not "", and sets SignatureValue to sign over the canonical
// SignedInfo: an authentic value, so only the algorithm policy decides.
func resignWith(t *testing.T, doc *xdm.Node, method, outputLength string, sign func(canonical []byte) []byte) *xdm.Node {
	t.Helper()
	sig, si, _, value := elements(doc)
	sm := si.ChildElements()[1]
	sm.Attr("", "Algorithm").Value = method
	if outputLength != "" {
		xmltree.Text(xmltree.Element(sm, "ds", xmlsec.NSDSig, "HMACOutputLength"), outputLength)
	}
	b, err := c14n.Bytes(si, c14n.Options{Algorithm: c14n.Exclusive10})
	if err != nil {
		t.Fatal(err)
	}
	value.Children[0].Value = base64.StdEncoding.EncodeToString(sign(b))
	return sig
}

func macOf(h crypto.Hash, key []byte, octets int) func([]byte) []byte {
	return func(b []byte) []byte {
		m := hmac.New(h.New, key)
		m.Write(b)
		return m.Sum(nil)[:octets]
	}
}

var hmacSecret = []byte("a shared secret of 32 octets....")

// RSA-SHA1 and HMAC stay refused under the default set an empty allow-list
// means (TestAlgorithmConfusion), and verify only when the caller names them.
func TestLegacyAlgorithmsOnlyWhenNamed(t *testing.T) {
	rk := rsaKey(t)
	kp := keyPair(t, rk)
	rsaSHA1 := func(b []byte) []byte {
		d := crypto.SHA1.New()
		d.Write(b)
		v, err := rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA1, d.Sum(nil))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	cases := []struct {
		name   string
		method string
		sign   func([]byte) []byte
		opts   dsig.VerifyOptions
	}{
		{"RSA-SHA1", xmlsec.SigRSASHA1, rsaSHA1, dsig.VerifyOptions{Certificate: kp.Certificate}},
		{"HMAC-SHA1", xmlsec.SigHMACSHA1, macOf(crypto.SHA1, hmacSecret, 20), dsig.VerifyOptions{HMACKey: hmacSecret}},
		{"HMAC-SHA256", xmlsec.SigHMACSHA256, macOf(crypto.SHA256, hmacSecret, 32), dsig.VerifyOptions{HMACKey: hmacSecret}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := signEnveloped(t, `<r>x</r>`, kp, xmlsec.SigRSASHA256)
			sig := resignWith(t, doc, c.method, "", c.sign)
			if _, err := dsig.Verify(doc, sig, c.opts); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
				t.Fatalf("empty allow-list: got %v", err)
			}
			opts := c.opts
			opts.AllowedSignatureAlgorithms = []string{xmlsec.SigRSASHA256, xmlsec.SigECDSASHA256}
			if _, err := dsig.Verify(doc, sig, opts); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
				t.Fatalf("list without it: got %v", err)
			}
			opts.AllowedSignatureAlgorithms = []string{c.method}
			if cov, err := dsig.Verify(doc, sig, opts); err != nil || !cov.WholeDocumentSigned {
				t.Fatalf("named: %v", err)
			}
		})
	}
}

// Algorithm confusion: an HMAC is never keyed with the public key or
// certificate. An attacker who MACs with the certificate's octets, which
// they can read from the message, is refused whether the certificate is
// pinned or in ds:KeyInfo, even with HMAC allowed; and a caller holding a
// shared secret never accepts a public-key signature in its place.
func TestHMACNeverKeyedByCertificate(t *testing.T) {
	kp := keyPair(t, rsaKey(t))
	pub := kp.Certificate.RawSubjectPublicKeyInfo
	for _, c := range []struct {
		name string
		key  []byte
		opts dsig.VerifyOptions
	}{
		{"certificate pinned, key = certificate", kp.Certificate.Raw, dsig.VerifyOptions{Certificate: kp.Certificate}},
		{"certificate pinned, key = public key", pub, dsig.VerifyOptions{Certificate: kp.Certificate}},
		{"certificate in KeyInfo", kp.Certificate.Raw, dsig.VerifyOptions{}},
		{"raw key pinned", pub, dsig.VerifyOptions{PublicKey: kp.Certificate.PublicKey}},
	} {
		t.Run(c.name, func(t *testing.T) {
			doc := signEnveloped(t, `<r>x</r>`, kp, xmlsec.SigRSASHA256)
			sig := resignWith(t, doc, xmlsec.SigHMACSHA256, "", macOf(crypto.SHA256, c.key, 32))
			c.opts.AllowedSignatureAlgorithms = []string{xmlsec.SigHMACSHA256}
			if _, err := dsig.Verify(doc, sig, c.opts); !errors.Is(err, xmlsec.ErrUnsupportedKeyInfo) {
				t.Fatalf("got %v", err)
			}
		})
	}

	// The reverse: an authentic RSA signature offered to a caller that holds
	// a shared secret.
	doc := signEnveloped(t, `<r>x</r>`, kp, xmlsec.SigRSASHA256)
	sig, _, _, _ := elements(doc)
	_, err := dsig.Verify(doc, sig, dsig.VerifyOptions{HMACKey: hmacSecret,
		AllowedSignatureAlgorithms: []string{xmlsec.SigHMACSHA256, xmlsec.SigRSASHA256}})
	if !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("RSA signature with HMACKey: got %v", err)
	}
}

// CVE-2009-0217: an attacker-chosen HMACOutputLength truncates the MAC to
// something forgeable. XML-DSig 4.4.2: "Signatures MUST be deemed invalid if
// the truncation length is below the larger of (a) half the underlying hash
// algorithm's output length, and (b) 80 bits"; 6.3.1: a multiple of 8. Each
// value below is the correctly truncated MAC, so only that rule refuses it.
func TestCVE20090217HMACTruncation(t *testing.T) {
	kp := keyPair(t, rsaKey(t))
	cases := []struct {
		method string
		h      crypto.Hash
		bits   int
		ok     bool
	}{
		{xmlsec.SigHMACSHA1, crypto.SHA1, 0, false},
		{xmlsec.SigHMACSHA1, crypto.SHA1, 8, false},
		{xmlsec.SigHMACSHA1, crypto.SHA1, 72, false},
		{xmlsec.SigHMACSHA1, crypto.SHA1, 79, false},
		{xmlsec.SigHMACSHA1, crypto.SHA1, 81, false}, // not a multiple of 8
		{xmlsec.SigHMACSHA1, crypto.SHA1, 80, true},  // the floor for SHA-1
		{xmlsec.SigHMACSHA256, crypto.SHA256, 0, false},
		{xmlsec.SigHMACSHA256, crypto.SHA256, 80, false},  // 80 bits, but below half of 256
		{xmlsec.SigHMACSHA256, crypto.SHA256, 120, false}, // below half
		{xmlsec.SigHMACSHA256, crypto.SHA256, 132, false}, // not a multiple of 8
		{xmlsec.SigHMACSHA256, crypto.SHA256, 128, true},  // half
		{xmlsec.SigHMACSHA512, crypto.SHA512, 248, false},
		{xmlsec.SigHMACSHA512, crypto.SHA512, 512, true},
	}
	for _, c := range cases {
		t.Run(c.method[strings.LastIndex(c.method, "#")+1:]+"/"+strconv.Itoa(c.bits), func(t *testing.T) {
			doc := signEnveloped(t, `<r>x</r>`, kp, xmlsec.SigRSASHA256)
			sig := resignWith(t, doc, c.method, strconv.Itoa(c.bits), macOf(c.h, hmacSecret, c.bits/8))
			_, err := dsig.Verify(doc, sig, dsig.VerifyOptions{HMACKey: hmacSecret, AllowedSignatureAlgorithms: []string{c.method}})
			switch {
			case c.ok && err != nil:
				t.Fatalf("permitted truncation refused: %v", err)
			case !c.ok && (!errors.Is(err, xmlsec.ErrSignatureInvalid) || !strings.Contains(err.Error(), "HMACOutputLength")):
				t.Fatalf("got %v", err)
			}
		})
	}
}
