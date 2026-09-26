package dsig_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

var (
	p384Key = mustEC(elliptic.P384())
	p521Key = mustEC(elliptic.P521())
)

func mustEC(c elliptic.Curve) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

// signRaw signs the metadata document enveloped, with ds:KeyInfo in form.
func signRaw(t *testing.T, doc string, signer crypto.Signer, sigAlg string, form dsig.KeyInfoForm) ([]byte, error) {
	t.Helper()
	return dsig.SignEnveloped(parse(t, []byte(doc)), newKey(t, signer), dsig.SignOptions{
		SignatureAlgorithm:        sigAlg,
		CanonicalizationAlgorithm: string(c14n.Inclusive10),
		References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
			{Algorithm: xmlsec.TransformEnvelopedSignature}, {Algorithm: string(c14n.Inclusive10)}}}},
		KeyInfo: form,
	})
}

func equalKey(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}

// Each raw-key form, for RSA and each named curve, signs and verifies both
// self-described and against a pinned key; Coverage reports the key, and no
// certificate.
func TestRawKeyRoundTrip(t *testing.T) {
	otherRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signers := []struct {
		name   string
		signer crypto.Signer
		alg    string
		other  crypto.PublicKey // same kind, different key
	}{
		{"RSA", rsaKey, xmlsec.SigRSASHA256, &otherRSA.PublicKey},
		{"P-256", covECKey, xmlsec.SigECDSASHA256, &mustEC(elliptic.P256()).PublicKey},
		{"P-384", p384Key, xmlsec.SigECDSASHA384, &mustEC(elliptic.P384()).PublicKey},
		{"P-521", p521Key, xmlsec.SigECDSASHA512, &mustEC(elliptic.P521()).PublicKey},
	}
	forms := []struct {
		name string
		form dsig.KeyInfoForm
		elem string
	}{
		{"KeyValue", dsig.KeyInfoKeyValue, "<ds:KeyValue>"},
		{"DEREncodedKeyValue", dsig.KeyInfoDEREncodedKeyValue, "<dsig11:DEREncodedKeyValue"},
	}
	for _, s := range signers {
		for _, f := range forms {
			t.Run(s.name+"/"+f.name, func(t *testing.T) {
				signed, err := signRaw(t, metadata, s.signer, s.alg, f.form)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(signed), f.elem) || strings.Contains(string(signed), "X509") {
					t.Fatalf("emitted %s", signed)
				}
				for _, pin := range []crypto.PublicKey{nil, s.signer.Public()} {
					doc := parse(t, signed)
					cov, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{PublicKey: pin})
					if err != nil {
						t.Fatalf("pinned %v: %v", pin != nil, err)
					}
					if cov.KeyInfoForm != f.form || cov.Certificate != nil || !equalKey(cov.PublicKey, s.signer.Public()) || !cov.WholeDocumentSigned {
						t.Fatalf("coverage %+v", cov)
					}
				}
				doc := parse(t, signed)
				if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{PublicKey: s.other}); !errors.Is(err, xmlsec.ErrSignatureInvalid) {
					t.Fatalf("another pinned key: got %v", err)
				}
			})
		}
	}
}

// Coverage.PublicKey is the certificate's key when there is a certificate,
// and a pinned PublicKey replaces an embedded certificate, which Coverage
// then does not report.
func TestCoveragePublicKey(t *testing.T) {
	key := newKey(t, rsaKey)
	signed := signEnveloped(t, key, xmlsec.SigRSASHA256, xmlsec.DigestSHA256)
	cases := []struct {
		name     string
		opts     dsig.VerifyOptions
		wantCert bool
	}{
		{"embedded certificate", dsig.VerifyOptions{}, true},
		{"pinned certificate", dsig.VerifyOptions{Certificate: key.Certificate}, true},
		{"pinned key", dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse(t, signed)
			cov, err := dsig.Verify(doc, findSignature(doc), c.opts)
			if err != nil {
				t.Fatal(err)
			}
			if !equalKey(cov.PublicKey, &rsaKey.PublicKey) || (cov.Certificate != nil) != c.wantCert || cov.KeyInfoForm != dsig.KeyInfoX509Data {
				t.Fatalf("coverage %+v", cov)
			}
		})
	}

	doc := parse(t, signed)
	_, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{Certificate: key.Certificate, PublicKey: &rsaKey.PublicKey})
	if err == nil || !strings.Contains(err.Error(), "both set") {
		t.Fatalf("Certificate and PublicKey: got %v", err)
	}
}

func TestRawKeyInfoStructure(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	rsaKV := func(n, e string) string {
		return `<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>` + n + `</ds:Modulus><ds:Exponent>` + e + `</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>`
	}
	ecKV := func(inner string) string {
		return `<ds:KeyValue><dsig11:ECKeyValue xmlns:dsig11="` + xmlsec.NSDSig11 + `">` + inner + `</dsig11:ECKeyValue></ds:KeyValue>`
	}
	p256URI := `<dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/>`
	point := func(b []byte) string { return `<dsig11:PublicKey>` + b64(b) + `</dsig11:PublicKey>` }
	der := func(s string) string {
		return `<dsig11:DEREncodedKeyValue xmlns:dsig11="` + xmlsec.NSDSig11 + `">` + s + `</dsig11:DEREncodedKeyValue>`
	}
	spki := func(pub crypto.PublicKey) string {
		b, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		return der(b64(b))
	}

	n, e := b64(rsaKey.N.Bytes()), b64(big.NewInt(int64(rsaKey.E)).Bytes())
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	even := b64(new(big.Int).Add(rsaKey.N, big.NewInt(1)).Bytes())
	pt, err := covECKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	offCurve := append([]byte{}, pt...)
	offCurve[len(offCurve)-1] ^= 1
	compressed := append([]byte{2 | pt[64]&1}, pt[1:33]...)
	p224 := mustEC(elliptic.P224())
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		ki   string
		opts dsig.VerifyOptions
		want error
	}{
		// ds:KeyValue
		{"empty KeyValue", `<ds:KeyValue/>`, dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"empty KeyValue with a pinned key", `<ds:KeyValue/>`, dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey}, xmlsec.ErrMalformed},
		{"KeyValue with two keys", `<ds:KeyValue><ds:RSAKeyValue/><ds:RSAKeyValue/></ds:KeyValue>`, dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"DSAKeyValue", `<ds:KeyValue><ds:DSAKeyValue/></ds:KeyValue>`, dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"RFC 4050 ECDSAKeyValue", `<ds:KeyValue><ECDSAKeyValue xmlns="http://www.w3.org/2001/04/xmldsig-more#"/></ds:KeyValue>`, dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"KeyValue beside X509Data", `<ds:KeyValue/><ds:X509Data/>`, dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},

		// ds:RSAKeyValue
		{"RSAKeyValue without Exponent", `<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>` + n + `</ds:Modulus></ds:RSAKeyValue></ds:KeyValue>`, dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"Exponent before Modulus", `<ds:KeyValue><ds:RSAKeyValue><ds:Exponent>` + e + `</ds:Exponent><ds:Modulus>` + n + `</ds:Modulus></ds:RSAKeyValue></ds:KeyValue>`, dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"Modulus not base64", rsaKV("!!", e), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"Modulus empty", rsaKV("", e), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"Exponent not base64", rsaKV(n, "!!"), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"Exponent over 31 bits", rsaKV(n, b64([]byte{1, 0, 0, 0, 1})), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"Exponent even", rsaKV(n, b64([]byte{1, 0, 0})), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"Exponent 1", rsaKV(n, b64([]byte{1})), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"Modulus even", rsaKV(even, e), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"1024-bit RSA", rsaKV(b64(small.N.Bytes()), e), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"1024-bit RSA ignored beside a pinned key", rsaKV(b64(small.N.Bytes()), e), dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey}, xmlsec.ErrSignatureInvalid},
		{"valid RSAKeyValue reaches the signature check", rsaKV(n, e), dsig.VerifyOptions{}, xmlsec.ErrSignatureInvalid},
		{"Modulus with a leading zero octet", rsaKV(b64(append([]byte{0}, rsaKey.N.Bytes()...)), e), dsig.VerifyOptions{}, xmlsec.ErrSignatureInvalid},

		// dsig11:ECKeyValue
		{"ECKeyValue without PublicKey", ecKV(p256URI), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"ECParameters", ecKV(`<dsig11:ECParameters/>` + point(pt)), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"unknown curve", ecKV(`<dsig11:NamedCurve URI="urn:oid:1.3.132.0.33"/>` + point(pt)), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"NamedCurve without URI", ecKV(`<dsig11:NamedCurve/>` + point(pt)), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"PublicKey not base64", ecKV(p256URI + `<dsig11:PublicKey>!!</dsig11:PublicKey>`), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"point off the curve", ecKV(p256URI + point(offCurve)), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"compressed point", ecKV(p256URI + point(compressed)), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"point on another curve", ecKV(p256URI + point(must(p384Key.PublicKey.Bytes()))), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"valid ECKeyValue reaches the signature check", ecKV(p256URI + point(pt)), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedAlgorithm},

		// dsig11:DEREncodedKeyValue
		{"DER not base64", der("!!"), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"DER not a SubjectPublicKeyInfo", der("AAAA"), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"DER with trailing data", der(b64(append(must(x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)), 0))), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"DER P-224", spki(&p224.PublicKey), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"DER Ed25519", spki(edPub), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"DER 1024-bit RSA", spki(&small.PublicKey), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"DER RSA exponent over 31 bits", spki(&rsa.PublicKey{N: rsaKey.N, E: 1<<32 + 1}), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"valid DER reaches the signature check", spki(&rsaKey.PublicKey), dsig.VerifyOptions{}, xmlsec.ErrSignatureInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse(t, []byte(covDoc(covKI(c.ki))))
			if _, err := dsig.Verify(doc, findSignature(doc), c.opts); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestSignRawKeyRefusals(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		doc    string
		signer crypto.Signer
		alg    string
		form   dsig.KeyInfoForm
		want   error // nil: any error
	}{
		{"1024-bit RSA KeyValue", metadata, small, xmlsec.SigRSASHA256, dsig.KeyInfoKeyValue, xmlsec.ErrUnsupportedKeyInfo},
		{"1024-bit RSA DEREncodedKeyValue", metadata, small, xmlsec.SigRSASHA256, dsig.KeyInfoDEREncodedKeyValue, xmlsec.ErrUnsupportedKeyInfo},
		{"P-224 KeyValue", metadata, mustEC(elliptic.P224()), xmlsec.SigECDSASHA256, dsig.KeyInfoKeyValue, xmlsec.ErrUnsupportedKeyInfo},
		{"dsig11 prefix bound elsewhere, ECKeyValue", `<r xmlns:dsig11="urn:other"/>`, covECKey, xmlsec.SigECDSASHA256, dsig.KeyInfoKeyValue, nil},
		{"dsig11 prefix bound elsewhere, DEREncodedKeyValue", `<r xmlns:dsig11="urn:other"/>`, rsaKey, xmlsec.SigRSASHA256, dsig.KeyInfoDEREncodedKeyValue, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := signRaw(t, c.doc, c.signer, c.alg, c.form); err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

// signedCovDoc is covDoc with sigContent, whose first Reference is covRef,
// made authentic: that Reference's digest is correct and SignedInfo is
// signed with rsaKey. Only ds:KeyInfo then decides the outcome.
func signedCovDoc(t *testing.T, sigContent string) (doc, sig *xdm.Node) {
	t.Helper()
	doc = parse(t, []byte(covDoc(sigContent)))
	sig = findSignature(doc)
	h := sha256.New()
	if _, err := c14n.Digest(h, xmltree.DocumentElement(doc).ChildElements()[0], c14n.Options{Algorithm: c14n.Exclusive10}); err != nil {
		t.Fatal(err)
	}
	sig.ChildElements()[0].ChildElements()[2].ChildElements()[2].Children[0].Value = base64.StdEncoding.EncodeToString(h.Sum(nil))
	resignSI(t, sig, c14n.Exclusive10)
	return doc, sig
}

// XML-DSig 4.5.10: a dsig11:KeyInfoReference names a ds:KeyInfo in the same
// document by ID, refusing duplicates; a reference to a reference is not
// followed.
func TestKeyInfoReference(t *testing.T) {
	cert := newKey(t, rsaKey).Certificate
	b64 := base64.StdEncoding.EncodeToString
	kv := `<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>` + b64(rsaKey.N.Bytes()) + `</ds:Modulus><ds:Exponent>` +
		b64(big.NewInt(int64(rsaKey.E)).Bytes()) + `</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>`
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallKV := strings.Replace(kv, b64(rsaKey.N.Bytes()), b64(small.N.Bytes()), 1)
	x509Data := `<ds:X509Data><ds:X509Certificate>` + b64(cert.Raw) + `</ds:X509Certificate></ds:X509Data>`
	kir := func(uri string) string {
		return `<dsig11:KeyInfoReference xmlns:dsig11="` + xmlsec.NSDSig11 + `" URI="` + uri + `"/>`
	}
	target := func(id, inner string) string {
		return `<ds:Object><ds:KeyInfo Id="` + id + `">` + inner + `</ds:KeyInfo></ds:Object>`
	}
	ids := dsig.VerifyOptions{IDAttributes: []xdm.QName{dsig.IDAttrDSig}}
	pinned := ids
	pinned.Certificate = cert

	cases := []struct {
		name    string
		ki      string // the ds:KeyInfo content
		objects string
		opts    dsig.VerifyOptions
		want    error
		form    dsig.KeyInfoForm
	}{
		{"to a KeyValue", kir("#k"), target("k", kv), ids, nil, dsig.KeyInfoKeyValue},
		{"to X509Data", kir("#k"), target("k", x509Data), ids, nil, dsig.KeyInfoX509Data},
		{"by XPointer", kir("#xpointer(id('k'))"), target("k", kv), ids, nil, dsig.KeyInfoKeyValue},
		{"Id not an ID attribute", kir("#k"), target("k", kv), dsig.VerifyOptions{}, xmlsec.ErrIDNotFound, 0},
		{"duplicate ID", kir("#k"), target("k", kv) + target("k", kv), ids, xmlsec.ErrAmbiguousID, 0},
		{"duplicate ID with a pinned key", kir("#k"), target("k", kv) + target("k", kv), pinned, xmlsec.ErrAmbiguousID, 0},
		{"to an element that is not ds:KeyInfo", kir("#a"), "", ids, xmlsec.ErrMalformed, 0},
		{"to a KeyInfoReference", kir("#k"), target("k", kir("#k2")) + target("k2", kv), ids, xmlsec.ErrUnsupportedKeyInfo, 0},
		{"to a KeyInfoReference with a pinned key", kir("#k"), target("k", kir("#k2")) + target("k2", kv), pinned, nil, dsig.KeyInfoNone},
		{"to a 1024-bit key", kir("#k"), target("k", smallKV), ids, xmlsec.ErrUnsupportedKeyInfo, 0},
		{"to another document", kir("http://example.com/k"), "", ids, xmlsec.ErrUnsupportedKeyInfo, 0},
		{"to the whole document", kir("#xpointer(/)"), "", ids, xmlsec.ErrUnsupportedKeyInfo, 0},
		{"XPointer expression", kir("#xpointer(//k)"), "", ids, xmlsec.ErrMalformed, 0},
		{"without URI", `<dsig11:KeyInfoReference xmlns:dsig11="` + xmlsec.NSDSig11 + `"/>`, "", ids, xmlsec.ErrMalformed, 0},
		{"with a child", `<dsig11:KeyInfoReference xmlns:dsig11="` + xmlsec.NSDSig11 + `" URI="#k"><x/></dsig11:KeyInfoReference>`, target("k", kv), ids, xmlsec.ErrMalformed, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, sig := signedCovDoc(t, covKI(c.ki)+c.objects)
			cov, err := dsig.Verify(doc, sig, c.opts)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if err == nil && (cov.KeyInfoForm != c.form || !equalKey(cov.PublicKey, &rsaKey.PublicKey)) {
				t.Fatalf("coverage %+v", cov)
			}
		})
	}
}

// XML-DSig 3.2.2: the key comes "from KeyInfo or from an external source".
// With the key pinned, a ds:KeyInfo form this library does not accept is
// ignored; a malformed one is still refused.
func TestPinnedKeyIgnoresUnsupportedKeyInfo(t *testing.T) {
	cert := newKey(t, rsaKey).Certificate
	cases := []struct {
		name string
		ki   string
		opts dsig.VerifyOptions
		want error
	}{
		{"KeyName, pinned certificate", `<ds:KeyName>k</ds:KeyName>`, dsig.VerifyOptions{Certificate: cert}, nil},
		{"KeyName, pinned key", `<ds:KeyName>k</ds:KeyName>`, dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey}, nil},
		{"foreign element, pinned certificate", `<x:Key xmlns:x="urn:x"/>`, dsig.VerifyOptions{Certificate: cert}, nil},
		{"KeyName, nothing pinned", `<ds:KeyName>k</ds:KeyName>`, dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"malformed X509Certificate, pinned certificate", `<ds:X509Data><ds:X509Certificate>!!</ds:X509Certificate></ds:X509Data>`, dsig.VerifyOptions{Certificate: cert}, xmlsec.ErrMalformed},
		{"STR to a missing token, pinned certificate", `<wsse:SecurityTokenReference><wsse:Reference URI="#missing"/></wsse:SecurityTokenReference>`, dsig.VerifyOptions{Certificate: cert}, xmlsec.ErrIDNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, sig := signedCovDoc(t, covKI(c.ki))
			cov, err := dsig.Verify(doc, sig, c.opts)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if err == nil && (cov.KeyInfoForm != dsig.KeyInfoNone || !equalKey(cov.PublicKey, &rsaKey.PublicKey)) {
				t.Fatalf("coverage %+v", cov)
			}
		})
	}
}
