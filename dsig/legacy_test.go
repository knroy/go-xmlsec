//lint:file-ignore SA1019 the tests sign with crypto/dsa to exercise dsa-sha1 verification.

package dsig_test

import (
	"crypto"
	"crypto/dsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"strconv"
	"sync"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
)

var dsaKey = sync.OnceValue(func() *dsa.PrivateKey {
	k := new(dsa.PrivateKey)
	if err := dsa.GenerateParameters(&k.Parameters, rand.Reader, dsa.L1024N160); err != nil {
		panic(err)
	}
	if err := dsa.GenerateKey(k, rand.Reader); err != nil {
		panic(err)
	}
	return k
})

var b64 = base64.StdEncoding.EncodeToString

func sigMethod(alg, children string) string {
	return `<ds:SignatureMethod Algorithm="` + alg + `">` + children + `</ds:SignatureMethod>`
}

func hmacLen(bits int) string {
	return `<ds:HMACOutputLength>` + strconv.Itoa(bits) + `</ds:HMACOutputLength>`
}

// legacyDoc builds a signature over #a with the given SignatureMethod
// element, DigestMethod and ds:KeyInfo content ("" for none), computing a
// correct DigestValue and taking SignatureValue from sign over the canonical
// SignedInfo.
func legacyDoc(t *testing.T, sm, digestAlg, keyInfo string, sign func(si []byte) []byte) (*xdm.Node, *xdm.Node) {
	t.Helper()
	if keyInfo != "" {
		keyInfo = `<ds:KeyInfo>` + keyInfo + `</ds:KeyInfo>`
	}
	ref := `<ds:Reference URI="#a">` + covTr + `<ds:DigestMethod Algorithm="` + digestAlg + `"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>`
	doc := parse(t, []byte(covDoc(covSI(covCM+sm+ref)+covSV+keyInfo)))
	sig := findSignature(doc)
	si := sig.ChildElements()[0]

	dh := crypto.SHA256
	if digestAlg == xmlsec.DigestSHA1 {
		dh = crypto.SHA1
	}
	h := dh.New()
	if _, err := c14n.Digest(h, doc.ChildElements()[0].ChildElements()[0], c14n.Options{Algorithm: c14n.Exclusive10}); err != nil {
		t.Fatal(err)
	}
	si.ChildElements()[2].ChildElements()[2].Children[0].Value = b64(h.Sum(nil))
	b, err := c14n.Bytes(si, c14n.Options{Algorithm: c14n.Exclusive10})
	if err != nil {
		t.Fatal(err)
	}
	sig.ChildElements()[1].Children[0].Value = b64(sign(b))
	return doc, sig
}

func rsaSigner(h crypto.Hash) func([]byte) []byte {
	return func(b []byte) []byte {
		d := h.New()
		d.Write(b)
		v, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, h, d.Sum(nil))
		if err != nil {
			panic(err)
		}
		return v
	}
}

func dsaSigner(b []byte) []byte {
	d := sha1.Sum(b)
	r, s, err := dsa.Sign(rand.Reader, dsaKey(), d[:])
	if err != nil {
		panic(err)
	}
	out := make([]byte, 40)
	r.FillBytes(out[:20])
	s.FillBytes(out[20:])
	return out
}

func hmacSigner(h crypto.Hash, key []byte, octets int) func([]byte) []byte {
	return func(b []byte) []byte {
		m := hmac.New(h.New, key)
		m.Write(b)
		return m.Sum(nil)[:octets]
	}
}

func dsaKeyValue(k *dsa.PublicKey, extra string) string {
	return `<ds:KeyValue><ds:DSAKeyValue><ds:P>` + b64(k.P.Bytes()) + `</ds:P><ds:Q>` + b64(k.Q.Bytes()) +
		`</ds:Q><ds:G>` + b64(k.G.Bytes()) + `</ds:G><ds:Y>` + b64(k.Y.Bytes()) + `</ds:Y>` + extra + `</ds:DSAKeyValue></ds:KeyValue>`
}

var hmacSecret = []byte("0123456789abcdef0123456789abcdef")

// Each legacy algorithm is refused under the default set an empty
// allow-list means, and verifies only when the caller names it.
func TestLegacyAlgorithmsOptIn(t *testing.T) {
	rsaCert := newKey(t, rsaKey).Certificate
	dsaPub := &dsaKey().PublicKey
	cases := []struct {
		name, sigAlg, digestAlg, keyInfo string
		sign                             func([]byte) []byte
		opts                             dsig.VerifyOptions
	}{
		{"rsa-sha1", xmlsec.SigRSASHA1, xmlsec.DigestSHA256, "", rsaSigner(crypto.SHA1), dsig.VerifyOptions{Certificate: rsaCert}},
		{"sha1 digest", xmlsec.SigRSASHA256, xmlsec.DigestSHA1, "", rsaSigner(crypto.SHA256), dsig.VerifyOptions{Certificate: rsaCert}},
		{"dsa-sha1 with DSAKeyValue", xmlsec.SigDSASHA1, xmlsec.DigestSHA256, dsaKeyValue(dsaPub, ""), dsaSigner, dsig.VerifyOptions{}},
		{"dsa-sha1 pinned", xmlsec.SigDSASHA1, xmlsec.DigestSHA256, "", dsaSigner, dsig.VerifyOptions{PublicKey: dsaPub}},
		{"hmac-sha1", xmlsec.SigHMACSHA1, xmlsec.DigestSHA256, "", hmacSigner(crypto.SHA1, hmacSecret, 20), dsig.VerifyOptions{HMACKey: hmacSecret}},
		{"hmac-sha256", xmlsec.SigHMACSHA256, xmlsec.DigestSHA256, "", hmacSigner(crypto.SHA256, hmacSecret, 32), dsig.VerifyOptions{HMACKey: hmacSecret}},
		{"hmac-sha384", xmlsec.SigHMACSHA384, xmlsec.DigestSHA256, "", hmacSigner(crypto.SHA384, hmacSecret, 48), dsig.VerifyOptions{HMACKey: hmacSecret}},
		{"hmac-sha512", xmlsec.SigHMACSHA512, xmlsec.DigestSHA256, "", hmacSigner(crypto.SHA512, hmacSecret, 64), dsig.VerifyOptions{HMACKey: hmacSecret}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, sig := legacyDoc(t, sigMethod(c.sigAlg, ""), c.digestAlg, c.keyInfo, c.sign)
			if _, err := dsig.Verify(doc, sig, c.opts); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
				t.Fatalf("default set: got %v", err)
			}
			opts := c.opts
			opts.AllowedSignatureAlgorithms = []string{c.sigAlg}
			opts.AllowedDigestAlgorithms = []string{c.digestAlg}
			cov, err := dsig.Verify(doc, sig, opts)
			if err != nil || !cov.Covers("a") {
				t.Fatalf("named: %v", err)
			}
		})
	}
}

// HMAC is keyed only by VerifyOptions.HMACKey, with its truncation bounded
// as XML-DSig 4.4.2 requires (CVE-2009-0217).
func TestHMAC(t *testing.T) {
	rsaCert := newKey(t, rsaKey).Certificate
	allow := []string{xmlsec.SigHMACSHA256, xmlsec.SigRSASHA256}
	full := hmacSigner(crypto.SHA256, hmacSecret, 32)
	certKI := `<ds:X509Data><ds:X509Certificate>` + b64(rsaCert.Raw) + `</ds:X509Certificate></ds:X509Data>`
	trustCalled := false
	cases := []struct {
		name     string
		sm       string
		keyInfo  string
		sign     func([]byte) []byte
		opts     dsig.VerifyOptions
		want     error
		wantForm dsig.KeyInfoForm
	}{
		{"full length", sigMethod(xmlsec.SigHMACSHA256, ""), "", full, dsig.VerifyOptions{HMACKey: hmacSecret}, nil, dsig.KeyInfoNone},
		{"HMACOutputLength 256", sigMethod(xmlsec.SigHMACSHA256, hmacLen(256)), "", full, dsig.VerifyOptions{HMACKey: hmacSecret}, nil, dsig.KeyInfoNone},
		{"truncated to half", sigMethod(xmlsec.SigHMACSHA256, hmacLen(128)), "", hmacSigner(crypto.SHA256, hmacSecret, 16), dsig.VerifyOptions{HMACKey: hmacSecret}, nil, dsig.KeyInfoNone},
		{"certificate in KeyInfo is not the key", sigMethod(xmlsec.SigHMACSHA256, ""), certKI, full, dsig.VerifyOptions{HMACKey: hmacSecret}, nil, dsig.KeyInfoX509Data},
		{"KeyName is ignored", sigMethod(xmlsec.SigHMACSHA256, ""), `<ds:KeyName>k</ds:KeyName>`, full, dsig.VerifyOptions{HMACKey: hmacSecret}, nil, dsig.KeyInfoNone},
		{"TrustKey is not called", sigMethod(xmlsec.SigHMACSHA256, ""), "", full, dsig.VerifyOptions{HMACKey: hmacSecret,
			TrustKey: func(*x509.Certificate, crypto.PublicKey) error { trustCalled = true; return nil }}, nil, dsig.KeyInfoNone},

		{"wrong key", sigMethod(xmlsec.SigHMACSHA256, ""), "", full, dsig.VerifyOptions{HMACKey: []byte("other")}, xmlsec.ErrSignatureInvalid, 0},
		{"truncated value, full length declared", sigMethod(xmlsec.SigHMACSHA256, ""), "", hmacSigner(crypto.SHA256, hmacSecret, 16), dsig.VerifyOptions{HMACKey: hmacSecret}, xmlsec.ErrSignatureInvalid, 0},
		{"malformed KeyInfo", sigMethod(xmlsec.SigHMACSHA256, ""), `<dsig11:KeyInfoReference xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"/>`, full, dsig.VerifyOptions{HMACKey: hmacSecret}, xmlsec.ErrMalformed, 0},
		{"no HMACKey, certificate pinned", sigMethod(xmlsec.SigHMACSHA256, ""), "", full, dsig.VerifyOptions{Certificate: rsaCert}, xmlsec.ErrUnsupportedKeyInfo, 0},
		{"no HMACKey, certificate in KeyInfo", sigMethod(xmlsec.SigHMACSHA256, ""), certKI, full, dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo, 0},
		{"HMACKey with an RSA method", sigMethod(xmlsec.SigRSASHA256, ""), certKI, rsaSigner(crypto.SHA256), dsig.VerifyOptions{HMACKey: hmacSecret}, xmlsec.ErrAlgorithmNotAllowed, 0},
		{"HMACOutputLength not an integer", sigMethod(xmlsec.SigHMACSHA256, `<ds:HMACOutputLength>x</ds:HMACOutputLength>`), "", full, dsig.VerifyOptions{HMACKey: hmacSecret}, xmlsec.ErrMalformed, 0},
		{"other child", sigMethod(xmlsec.SigHMACSHA256, `<ds:X/>`), "", full, dsig.VerifyOptions{HMACKey: hmacSecret}, xmlsec.ErrMalformed, 0},
		{"two HMACOutputLength", sigMethod(xmlsec.SigHMACSHA256, hmacLen(256)+hmacLen(256)), "", full, dsig.VerifyOptions{HMACKey: hmacSecret}, xmlsec.ErrMalformed, 0},
		{"HMACOutputLength above the hash", sigMethod(xmlsec.SigHMACSHA256, hmacLen(264)), "", full, dsig.VerifyOptions{HMACKey: hmacSecret}, xmlsec.ErrSignatureInvalid, 0},
	}
	// CVE-2009-0217: each truncation below max(half the hash, 80 bits), or
	// not a multiple of 8, is invalid whatever the value; the value given is
	// the correctly truncated MAC, so only the length check stands in the way.
	for _, c := range []struct {
		alg  string
		h    crypto.Hash
		bits int
	}{
		{xmlsec.SigHMACSHA1, crypto.SHA1, 0}, {xmlsec.SigHMACSHA1, crypto.SHA1, 8}, {xmlsec.SigHMACSHA1, crypto.SHA1, 72},
		{xmlsec.SigHMACSHA1, crypto.SHA1, 79}, {xmlsec.SigHMACSHA1, crypto.SHA1, 84}, {xmlsec.SigHMACSHA1, crypto.SHA1, -8},
		{xmlsec.SigHMACSHA256, crypto.SHA256, 80}, {xmlsec.SigHMACSHA256, crypto.SHA256, 120}, {xmlsec.SigHMACSHA256, crypto.SHA256, 132},
		{xmlsec.SigHMACSHA512, crypto.SHA512, 248},
	} {
		octets := max(c.bits/8, 0)
		cases = append(cases, struct {
			name     string
			sm       string
			keyInfo  string
			sign     func([]byte) []byte
			opts     dsig.VerifyOptions
			want     error
			wantForm dsig.KeyInfoForm
		}{"CVE-2009-0217 " + c.alg + " " + strconv.Itoa(c.bits), sigMethod(c.alg, hmacLen(c.bits)), "", hmacSigner(c.h, hmacSecret, octets),
			dsig.VerifyOptions{HMACKey: hmacSecret, AllowedSignatureAlgorithms: []string{c.alg}}, xmlsec.ErrSignatureInvalid, 0})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, sig := legacyDoc(t, c.sm, xmlsec.DigestSHA256, c.keyInfo, c.sign)
			opts := c.opts
			if opts.AllowedSignatureAlgorithms == nil {
				opts.AllowedSignatureAlgorithms = allow
			}
			cov, err := dsig.Verify(doc, sig, opts)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if err == nil && (cov.Certificate != nil || cov.PublicKey != nil || cov.KeyInfoForm != c.wantForm) {
				t.Fatalf("coverage %+v", cov)
			}
		})
	}
	if trustCalled {
		t.Error("TrustKey called for an HMAC")
	}
	doc, sig := legacyDoc(t, sigMethod(xmlsec.SigHMACSHA256, ""), xmlsec.DigestSHA256, "", full)
	for _, o := range []dsig.VerifyOptions{{Certificate: rsaCert}, {PublicKey: &rsaKey.PublicKey}} {
		o.HMACKey, o.AllowedSignatureAlgorithms = hmacSecret, allow
		if _, err := dsig.Verify(doc, sig, o); err == nil {
			t.Error("HMACKey accepted beside a pinned key")
		}
	}
}

func TestDSA(t *testing.T) {
	k := dsaKey()
	pub := &k.PublicKey
	j := new(big.Int).Quo(new(big.Int).Sub(pub.P, big.NewInt(1)), pub.Q)
	el := func(name string, v *big.Int) string {
		return `<ds:` + name + `>` + b64(v.Bytes()) + `</ds:` + name + `>`
	}
	kv := func(inner string) string {
		return `<ds:KeyValue><ds:DSAKeyValue>` + inner + `</ds:DSAKeyValue></ds:KeyValue>`
	}
	pqgy := el("P", pub.P) + el("Q", pub.Q) + el("G", pub.G) + el("Y", pub.Y)
	with := func(f func(p *dsa.PublicKey)) *dsa.PublicKey {
		c := &dsa.PublicKey{Parameters: dsa.Parameters{P: pub.P, Q: pub.Q, G: pub.G}, Y: pub.Y}
		f(c)
		return c
	}
	one := big.NewInt(1)
	composite := new(big.Int).Add(pub.P, big.NewInt(2)) // odd and 1024 bits
	for composite.ProbablyPrime(20) {
		composite.Add(composite, big.NewInt(2))
	}
	allow := dsig.VerifyOptions{AllowedSignatureAlgorithms: []string{xmlsec.SigDSASHA1}}
	pinned := func(p crypto.PublicKey) dsig.VerifyOptions {
		o := allow
		o.PublicKey = p
		return o
	}
	cases := []struct {
		name    string
		sm      string
		keyInfo string
		sign    func([]byte) []byte
		opts    dsig.VerifyOptions
		want    error
	}{
		{"J, Seed and PgenCounter", xmlsec.SigDSASHA1, kv(pqgy + el("J", j) + el("Seed", one) + el("PgenCounter", one)), dsaSigner, allow, nil},
		{"wrong J", xmlsec.SigDSASHA1, kv(pqgy + el("J", one)), dsaSigner, allow, xmlsec.ErrMalformed},
		{"Seed without PgenCounter", xmlsec.SigDSASHA1, kv(pqgy + el("Seed", one)), dsaSigner, allow, xmlsec.ErrMalformed},
		{"no Y", xmlsec.SigDSASHA1, kv(el("P", pub.P) + el("Q", pub.Q) + el("G", pub.G)), dsaSigner, allow, xmlsec.ErrMalformed},
		{"P without Q", xmlsec.SigDSASHA1, kv(el("P", pub.P) + el("G", pub.G) + el("Y", pub.Y)), dsaSigner, allow, xmlsec.ErrMalformed},
		{"only Y", xmlsec.SigDSASHA1, kv(el("Y", pub.Y)), dsaSigner, allow, xmlsec.ErrUnsupportedKeyInfo},
		{"no G", xmlsec.SigDSASHA1, kv(el("P", pub.P) + el("Q", pub.Q) + el("Y", pub.Y)), dsaSigner, allow, xmlsec.ErrUnsupportedKeyInfo},
		{"out of order", xmlsec.SigDSASHA1, kv(el("Y", pub.Y) + el("P", pub.P) + el("Q", pub.Q) + el("G", pub.G)), dsaSigner, allow, xmlsec.ErrMalformed},
		{"unknown child", xmlsec.SigDSASHA1, kv(pqgy + `<ds:X>AA==</ds:X>`), dsaSigner, allow, xmlsec.ErrMalformed},
		{"not base64", xmlsec.SigDSASHA1, kv(`<ds:P>!!</ds:P>`), dsaSigner, allow, xmlsec.ErrMalformed},
		{"DSAKeyValue with an RSA method", xmlsec.SigRSASHA256, dsaKeyValue(pub, ""), rsaSigner(crypto.SHA256), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"DSAKeyValue ignored when an RSA key is pinned", xmlsec.SigRSASHA256, dsaKeyValue(pub, ""), rsaSigner(crypto.SHA256), dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey}, nil},

		{"RSA key", xmlsec.SigDSASHA1, "", dsaSigner, pinned(&rsaKey.PublicKey), xmlsec.ErrUnsupportedAlgorithm},
		{"DSA key with rsa-sha1", xmlsec.SigRSASHA1, "", dsaSigner, dsig.VerifyOptions{PublicKey: pub, AllowedSignatureAlgorithms: []string{xmlsec.SigRSASHA1}}, xmlsec.ErrUnsupportedAlgorithm},
		{"short value", xmlsec.SigDSASHA1, "", func(b []byte) []byte { return dsaSigner(b)[:39] }, pinned(pub), xmlsec.ErrSignatureInvalid},
		{"zero value", xmlsec.SigDSASHA1, "", func([]byte) []byte { return make([]byte, 40) }, pinned(pub), xmlsec.ErrSignatureInvalid},
		{"missing parameters", xmlsec.SigDSASHA1, "", dsaSigner, pinned(&dsa.PublicKey{}), xmlsec.ErrMalformed},
		{"160-bit Q, 1023-bit P", xmlsec.SigDSASHA1, "", dsaSigner, pinned(with(func(p *dsa.PublicKey) { p.P = new(big.Int).Rsh(pub.P, 1) })), xmlsec.ErrUnsupportedKeyInfo},
		{"159-bit Q", xmlsec.SigDSASHA1, "", dsaSigner, pinned(with(func(p *dsa.PublicKey) { p.Q = new(big.Int).Rsh(pub.Q, 1) })), xmlsec.ErrUnsupportedKeyInfo},
		{"composite P", xmlsec.SigDSASHA1, "", dsaSigner, pinned(with(func(p *dsa.PublicKey) { p.P = composite })), xmlsec.ErrMalformed},
		{"G = 1", xmlsec.SigDSASHA1, "", dsaSigner, pinned(with(func(p *dsa.PublicKey) { p.G = one })), xmlsec.ErrMalformed},
		{"Y = 1", xmlsec.SigDSASHA1, "", dsaSigner, pinned(with(func(p *dsa.PublicKey) { p.Y = one })), xmlsec.ErrMalformed},
		{"Y = P-1", xmlsec.SigDSASHA1, "", dsaSigner, pinned(with(func(p *dsa.PublicKey) { p.Y = new(big.Int).Sub(pub.P, one) })), xmlsec.ErrMalformed},
		{"Y = P", xmlsec.SigDSASHA1, "", dsaSigner, pinned(with(func(p *dsa.PublicKey) { p.Y = pub.P })), xmlsec.ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, sig := legacyDoc(t, sigMethod(c.sm, ""), xmlsec.DigestSHA256, c.keyInfo, c.sign)
			cov, err := dsig.Verify(doc, sig, c.opts)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if err == nil && c.sm == xmlsec.SigDSASHA1 && (cov.KeyInfoForm != dsig.KeyInfoKeyValue || pub.Y.Cmp(cov.PublicKey.(*dsa.PublicKey).Y) != 0) {
				t.Fatalf("coverage %+v", cov)
			}
		})
	}
}

// An allow-list may name an algorithm this library does not implement; it
// is then refused as unsupported.
func TestAllowedButUnimplemented(t *testing.T) {
	cert := newKey(t, rsaKey).Certificate
	doc, sig := legacyDoc(t, sigMethod("urn:x", ""), xmlsec.DigestSHA256, "", rsaSigner(crypto.SHA256))
	if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{Certificate: cert, AllowedSignatureAlgorithms: []string{"urn:x"}}); !errors.Is(err, xmlsec.ErrUnsupportedAlgorithm) {
		t.Fatalf("signature: got %v", err)
	}
	doc = parse(t, []byte(covDoc(covSI(covCM+covSM+`<ds:Reference URI="#a">`+covTr+`<ds:DigestMethod Algorithm="urn:x"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>`)+covSV)))
	if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{Certificate: cert, AllowedDigestAlgorithms: []string{"urn:x"}}); !errors.Is(err, xmlsec.ErrUnsupportedAlgorithm) {
		t.Fatalf("digest: got %v", err)
	}
}
