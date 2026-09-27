package dsig_test

import (
	"errors"
	"math/big"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// graft appends the element fragment, parsed on its own, to the document
// element of doc: outside ds:SignedInfo, so the signature stays valid.
func graft(t *testing.T, doc *xdm.Node, fragment string) {
	t.Helper()
	if fragment != "" {
		xmltree.DocumentElement(doc).AppendChild(xmltree.DocumentElement(parse(t, []byte(fragment))))
	}
}

// target is a ds or dsig11 element with wsu:Id "k" holding inner.
func target(ns, local, inner string) string {
	return `<t:` + local + ` xmlns:t="` + ns + `" xmlns:ds="` + xmlsec.NSDSig + `" xmlns:dsig11="` + xmlsec.NSDSig11 +
		`" xmlns:wsu="` + xmlsec.NSWSU + `" wsu:Id="k">` + inner + `</t:` + local + `>`
}

func retrievalMethod(uri, typ, inner string) string {
	return `<ds:RetrievalMethod URI="` + uri + `" Type="` + typ + `">` + inner + `</ds:RetrievalMethod>`
}

// XML-DSig 4.5.3: a ds:RetrievalMethod is followed one hop, to an element of
// its Type in the same document, or for a raw certificate through
// ResolveKeyInfoURI; transforms are refused.
func TestRetrievalMethod(t *testing.T) {
	p := newPKI(t)
	const (
		typX509 = xmlsec.NSDSig + "X509Data"
		typRSA  = xmlsec.NSDSig + "RSAKeyValue"
		typDSA  = xmlsec.NSDSig + "DSAKeyValue"
		typEC   = xmlsec.NSDSig11 + "ECKeyValue"
		typDER  = xmlsec.NSDSig11 + "DEREncodedKeyValue"
		typRaw  = xmlsec.NSDSig + "rawX509Certificate"
		rawURI  = "https://keys.example.com/signer.cer"
	)
	rsaKV := `<ds:Modulus>` + b64(rsaKey.N.Bytes()) + `</ds:Modulus><ds:Exponent>` + b64(big.NewInt(int64(rsaKey.E)).Bytes()) + `</ds:Exponent>`
	ecPoint, _ := covECKey.PublicKey.Bytes()
	ecKV := `<dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><dsig11:PublicKey>` + b64(ecPoint) + `</dsig11:PublicKey>`
	serve := func(b []byte) dsig.VerifyOptions {
		return dsig.VerifyOptions{ResolveKeyInfoURI: func(uri string) ([]byte, error) {
			if uri != rawURI {
				t.Errorf("fetched %q", uri)
			}
			return b, nil
		}}
	}
	kir := `<dsig11:KeyInfoReference xmlns:dsig11="` + xmlsec.NSDSig11 + `" URI="#k"/>`
	cases := []struct {
		name   string
		ki     string
		target string
		opts   dsig.VerifyOptions
		want   error
		form   dsig.KeyInfoForm
	}{
		{"X509Data", retrievalMethod("#k", typX509, ""), target(xmlsec.NSDSig, "X509Data", x509Cert(p.leaf)), dsig.VerifyOptions{}, nil, dsig.KeyInfoX509Data},
		{"RSAKeyValue", retrievalMethod("#k", typRSA, ""), target(xmlsec.NSDSig, "RSAKeyValue", rsaKV), dsig.VerifyOptions{}, nil, dsig.KeyInfoKeyValue},
		{"DEREncodedKeyValue", retrievalMethod("#k", typDER, ""), target(xmlsec.NSDSig11, "DEREncodedKeyValue", b64(p.leaf.RawSubjectPublicKeyInfo)), dsig.VerifyOptions{}, nil, dsig.KeyInfoDEREncodedKeyValue},
		{"ECKeyValue, read and used", retrievalMethod("#k", typEC, ""), target(xmlsec.NSDSig11, "ECKeyValue", ecKV), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedAlgorithm, 0},
		{"by XPointer", retrievalMethod("#xpointer(id('k'))", typX509, ""), target(xmlsec.NSDSig, "X509Data", x509Cert(p.leaf)), dsig.VerifyOptions{}, nil, dsig.KeyInfoX509Data},
		{"raw certificate", retrievalMethod(rawURI, typRaw, ""), "", serve(p.leaf.Raw), nil, dsig.KeyInfoX509Data},

		{"DSAKeyValue for an RSA signature", retrievalMethod("#k", typDSA, ""), target(xmlsec.NSDSig, "DSAKeyValue", ""), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo, 0},
		{"Type and target differ", retrievalMethod("#k", typX509, ""), target(xmlsec.NSDSig, "RSAKeyValue", rsaKV), dsig.VerifyOptions{}, xmlsec.ErrMalformed, 0},
		{"unknown Type", retrievalMethod("#k", xmlsec.NSDSig+"PGPData", ""), target(xmlsec.NSDSig, "PGPData", ""), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo, 0},
		{"no Type", `<ds:RetrievalMethod URI="#k"/>`, target(xmlsec.NSDSig, "X509Data", x509Cert(p.leaf)), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo, 0},
		{"no URI", `<ds:RetrievalMethod Type="` + typX509 + `"/>`, "", dsig.VerifyOptions{}, xmlsec.ErrMalformed, 0},
		{"transforms", retrievalMethod("#k", typX509, `<ds:Transforms><ds:Transform Algorithm="`+xmlsec.TransformBase64+`"/></ds:Transforms>`),
			target(xmlsec.NSDSig, "X509Data", x509Cert(p.leaf)), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo, 0},
		{"the whole document", retrievalMethod("#xpointer(/)", typX509, ""), "", dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo, 0},
		{"an XPointer expression", retrievalMethod("#xpointer(//k)", typX509, ""), "", dsig.VerifyOptions{}, xmlsec.ErrMalformed, 0},
		{"a missing ID", retrievalMethod("#missing", typX509, ""), "", dsig.VerifyOptions{}, xmlsec.ErrIDNotFound, 0},
		{"another document without a resolver", retrievalMethod(rawURI, typRaw, ""), "", dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo, 0},
		{"another document, not a raw certificate", retrievalMethod(rawURI, typX509, ""), "", serve(p.leaf.Raw), xmlsec.ErrUnsupportedKeyInfo, 0},
		{"an empty URI", retrievalMethod("", typRaw, ""), "", serve(p.leaf.Raw), xmlsec.ErrUnsupportedKeyInfo, 0},
		{"a raw certificate that is not one", retrievalMethod(rawURI, typRaw, ""), "", serve([]byte("x")), xmlsec.ErrMalformed, 0},
		{"inside a referenced ds:KeyInfo", kir, target(xmlsec.NSDSig, "KeyInfo", retrievalMethod("#x", typX509, "")), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, sig := signedCovDoc(t, covKI(c.ki))
			graft(t, doc, c.target)
			cov, err := dsig.Verify(doc, sig, c.opts)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if err == nil && (cov.KeyInfoForm != c.form || !equalKey(cov.PublicKey, &rsaKey.PublicKey)) {
				t.Fatalf("coverage %+v", cov)
			}
		})
	}

	// DSAKeyValue, for a DSA signature.
	k := &dsaKey().PublicKey
	doc, sig := legacyDoc(t, sigMethod(xmlsec.SigDSASHA1, ""), xmlsec.DigestSHA256, retrievalMethod("#k", typDSA, ""), dsaSigner)
	graft(t, doc, target(xmlsec.NSDSig, "DSAKeyValue", `<ds:P>`+b64(k.P.Bytes())+`</ds:P><ds:Q>`+b64(k.Q.Bytes())+`</ds:Q><ds:G>`+
		b64(k.G.Bytes())+`</ds:G><ds:Y>`+b64(k.Y.Bytes())+`</ds:Y>`))
	cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{AllowedSignatureAlgorithms: []string{xmlsec.SigDSASHA1}})
	if err != nil || cov.KeyInfoForm != dsig.KeyInfoKeyValue {
		t.Fatalf("DSA: %v, %+v", err, cov)
	}
}
