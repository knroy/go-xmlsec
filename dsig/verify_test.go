package dsig_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

var covECKey = func() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}()

// --- Hand-built signatures for the structural checks ------------------------

const (
	covExc    = string(c14n.Exclusive10)
	covCM     = `<ds:CanonicalizationMethod Algorithm="` + covExc + `"/>`
	covSM     = `<ds:SignatureMethod Algorithm="` + xmlsec.SigRSASHA256 + `"/>`
	covTr     = `<ds:Transforms><ds:Transform Algorithm="` + covExc + `"/></ds:Transforms>`
	covDigest = `<ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"/><ds:DigestValue>AAAA</ds:DigestValue>`
	covRef    = `<ds:Reference URI="#a">` + covTr + covDigest + `</ds:Reference>`
	covSV     = `<ds:SignatureValue>AAAA</ds:SignatureValue>`
	covIN     = `<ec:InclusiveNamespaces xmlns:ec="` + dsig.NSExcC14N + `" PrefixList="p"/>`
)

func covSI(inner string) string { return `<ds:SignedInfo>` + inner + `</ds:SignedInfo>` }

func covKI(inner string) string {
	return covSI(covCM+covSM+covRef) + covSV + `<ds:KeyInfo>` + inner + `</ds:KeyInfo>`
}

func covTransforms(algs ...string) string {
	var b strings.Builder
	for _, a := range algs {
		b.WriteString(`<ds:Transform Algorithm="` + a + `"/>`)
	}
	return b.String()
}

// covDoc places a ds:Signature with the given content in a document that
// has an element with wsu:Id "a" and one, not a token, with wsu:Id "nb".
func covDoc(sigContent string) string {
	return `<r xmlns:wsu="` + wss.NSWSU + `" xmlns:wsse="` + wss.NSWSSE + `" xmlns:p="urn:p">` +
		`<a wsu:Id="a">x</a><z wsu:Id="nb"/>` +
		`<ds:Signature xmlns:ds="` + dsig.NSDSig + `">` + sigContent + `</ds:Signature></r>`
}

func TestVerifyStructure(t *testing.T) {
	rsaCert := newKey(t, rsaKey).Certificate
	ecCert := newKey(t, covECKey).Certificate
	withCert := dsig.VerifyOptions{Certificate: rsaCert}
	zeros64 := base64.StdEncoding.EncodeToString(make([]byte, 64))
	ecSM := `<ds:SignatureMethod Algorithm="` + xmlsec.SigECDSASHA256 + `"/>`

	cases := []struct {
		name string
		sig  string
		opts dsig.VerifyOptions
		want error // nil: any error
	}{
		// ds:Signature
		{"empty signature", ``, withCert, xmlsec.ErrMalformed},
		{"missing SignedInfo", covSV, withCert, xmlsec.ErrMalformed},
		{"SignatureValue first", covSV + covSI(covCM+covSM+covRef), withCert, xmlsec.ErrMalformed},
		{"SignatureValue not base64", covSI(covCM+covSM+covRef) + `<ds:SignatureValue>!!</ds:SignatureValue>`, withCert, xmlsec.ErrMalformed},
		{"unexpected element", covSI(covCM+covSM+covRef) + covSV + `<ds:Manifest/>`, withCert, xmlsec.ErrMalformed},
		{"KeyInfo after Object", covSI(covCM+covSM+covRef) + covSV + `<ds:Object/><ds:KeyInfo/>`, withCert, xmlsec.ErrMalformed},
		{"two KeyInfo", covSI(covCM+covSM+covRef) + covSV + `<ds:KeyInfo/><ds:KeyInfo/>`, withCert, xmlsec.ErrMalformed},

		// ds:SignedInfo
		{"no Reference", covSI(covCM + covSM), withCert, xmlsec.ErrMalformed},
		{"SignatureMethod first", covSI(covSM+covCM+covRef) + covSV, withCert, xmlsec.ErrMalformed},
		{"SignatureMethod with children", covSI(covCM+`<ds:SignatureMethod Algorithm="`+xmlsec.SigRSASHA256+`"><ds:HMACOutputLength>8</ds:HMACOutputLength></ds:SignatureMethod>`+covRef) + covSV, withCert, xmlsec.ErrMalformed},
		{"CanonicalizationMethod with unknown child", covSI(`<ds:CanonicalizationMethod Algorithm="`+covExc+`"><x/></ds:CanonicalizationMethod>`+covSM+covRef) + covSV, withCert, xmlsec.ErrMalformed},
		{"InclusiveNamespaces under inclusive CanonicalizationMethod", covSI(`<ds:CanonicalizationMethod Algorithm="`+string(c14n.Inclusive10)+`">`+covIN+`</ds:CanonicalizationMethod>`+covSM+covRef) + covSV, withCert, xmlsec.ErrMalformed},
		{"non-Reference in SignedInfo", covSI(covCM+covSM+`<ds:Object/>`) + covSV, withCert, xmlsec.ErrMalformed},

		// ds:Reference
		{"Reference without URI", covSI(covCM+covSM+`<ds:Reference>`+covTr+covDigest+`</ds:Reference>`) + covSV, withCert, xmlsec.ErrMalformed},
		{"too many transforms", covSI(covCM+covSM+`<ds:Reference URI="#a"><ds:Transforms>`+strings.Repeat(`<ds:Transform Algorithm="`+covExc+`"/>`, dsig.MaxTransformsPerReference+1)+`</ds:Transforms>`+covDigest+`</ds:Reference>`) + covSV, withCert, xmlsec.ErrLimitExceeded},
		{"non-Transform in Transforms", covSI(covCM+covSM+`<ds:Reference URI="#a"><ds:Transforms><ds:XPath/></ds:Transforms>`+covDigest+`</ds:Reference>`) + covSV, withCert, xmlsec.ErrMalformed},
		{"Transform with XPath child", covSI(covCM+covSM+`<ds:Reference URI="#a"><ds:Transforms><ds:Transform Algorithm="`+xmlsec.TransformXPath+`"><ds:XPath>1</ds:XPath></ds:Transform></ds:Transforms>`+covDigest+`</ds:Reference>`) + covSV, withCert, xmlsec.ErrMalformed},
		{"InclusiveNamespaces under inclusive Transform", covSI(covCM+covSM+`<ds:Reference URI="#a"><ds:Transforms><ds:Transform Algorithm="`+string(c14n.Inclusive10)+`">`+covIN+`</ds:Transform></ds:Transforms>`+covDigest+`</ds:Reference>`) + covSV, withCert, xmlsec.ErrMalformed},
		{"two InclusiveNamespaces", covSI(covCM+covSM+`<ds:Reference URI="#a"><ds:Transforms><ds:Transform Algorithm="`+covExc+`">`+covIN+covIN+`</ds:Transform></ds:Transforms>`+covDigest+`</ds:Reference>`) + covSV, withCert, xmlsec.ErrMalformed},
		{"missing DigestValue", covSI(covCM+covSM+`<ds:Reference URI="#a">`+covTr+`<ds:DigestMethod Algorithm="`+xmlsec.DigestSHA256+`"/></ds:Reference>`) + covSV, withCert, xmlsec.ErrMalformed},
		{"extra element in Reference", covSI(covCM+covSM+`<ds:Reference URI="#a">`+covTr+covDigest+`<ds:Object/></ds:Reference>`) + covSV, withCert, xmlsec.ErrMalformed},
		{"DigestValue not base64", covSI(covCM+covSM+`<ds:Reference URI="#a">`+covTr+`<ds:DigestMethod Algorithm="`+xmlsec.DigestSHA256+`"/><ds:DigestValue>!!</ds:DigestValue></ds:Reference>`) + covSV, withCert, xmlsec.ErrMalformed},

		// Allow-lists, checked before any cryptographic work.
		{"unknown signature algorithm", covSI(covCM+`<ds:SignatureMethod Algorithm="urn:x"/>`+covRef) + covSV, withCert, xmlsec.ErrAlgorithmNotAllowed},
		{"unknown canonicalization", covSI(`<ds:CanonicalizationMethod Algorithm="urn:x"/>`+covSM+covRef) + covSV, withCert, xmlsec.ErrAlgorithmNotAllowed},
		{"unknown digest", covSI(covCM+covSM+`<ds:Reference URI="#a">`+covTr+`<ds:DigestMethod Algorithm="urn:x"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>`) + covSV, withCert, xmlsec.ErrAlgorithmNotAllowed},
		{"transform canonicalization outside allow-list", covSI(covCM+covSM+`<ds:Reference URI="#a"><ds:Transforms>`+covTransforms(string(c14n.Inclusive10))+`</ds:Transforms>`+covDigest+`</ds:Reference>`) + covSV,
			dsig.VerifyOptions{Certificate: rsaCert, AllowedCanonicalizationAlgorithms: []string{covExc}}, xmlsec.ErrAlgorithmNotAllowed},

		// ds:KeyInfo
		{"empty KeyInfo", covKI(``), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"KeyInfo with two children", covKI(`<ds:KeyName>a</ds:KeyName><ds:KeyName>b</ds:KeyName>`), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"KeyValue", covKI(`<ds:KeyValue/>`), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"X509Data with two certificates", covKI(`<ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data>`), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"X509Data with issuer serial", covKI(`<ds:X509Data><ds:X509IssuerSerial/></ds:X509Data>`), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"X509Certificate not base64", covKI(`<ds:X509Data><ds:X509Certificate>!!</ds:X509Certificate></ds:X509Data>`), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"X509Certificate not DER", covKI(`<ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data>`), dsig.VerifyOptions{}, nil},
		{"STR to missing token", covKI(`<wsse:SecurityTokenReference><wsse:Reference URI="#missing"/></wsse:SecurityTokenReference>`), dsig.VerifyOptions{}, xmlsec.ErrIDNotFound},
		{"STR to non-token", covKI(`<wsse:SecurityTokenReference><wsse:Reference URI="#nb"/></wsse:SecurityTokenReference>`), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"no KeyInfo and no certificate", covSI(covCM+covSM+covRef) + covSV, dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},

		// Signature value against the key.
		{"empty PrefixList reaches the signature check", covSI(`<ds:CanonicalizationMethod Algorithm="`+covExc+`"><ec:InclusiveNamespaces xmlns:ec="`+dsig.NSExcC14N+`" PrefixList=""/></ds:CanonicalizationMethod>`+covSM+covRef) + covSV, withCert, xmlsec.ErrSignatureInvalid},
		{"RSA key with an ECDSA algorithm", covSI(covCM+ecSM+covRef) + covSV, withCert, xmlsec.ErrUnsupportedAlgorithm},
		{"ECDSA key with an RSA algorithm", covSI(covCM+covSM+covRef) + covSV, dsig.VerifyOptions{Certificate: ecCert}, xmlsec.ErrUnsupportedAlgorithm},
		{"ECDSA value of the wrong length", covSI(covCM+ecSM+covRef) + covSV, dsig.VerifyOptions{Certificate: ecCert}, xmlsec.ErrSignatureInvalid},
		{"ECDSA value of zeros", covSI(covCM+ecSM+covRef) + `<ds:SignatureValue>` + zeros64 + `</ds:SignatureValue>`, dsig.VerifyOptions{Certificate: ecCert}, xmlsec.ErrSignatureInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse(t, []byte(covDoc(c.sig)))
			_, err := dsig.Verify(doc, findSignature(doc), c.opts)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestVerifyArguments(t *testing.T) {
	doc := parse(t, []byte(covDoc(covSI(covCM+covSM+covRef)+covSV)))
	other := parse(t, []byte(covDoc(covSI(covCM+covSM+covRef)+covSV)))
	cases := []struct {
		name     string
		doc, sig *xdm.Node
		want     error // nil: any error
	}{
		{"nil doc", nil, findSignature(doc), xmlsec.ErrMalformed},
		{"nil signature", doc, nil, xmlsec.ErrMalformed},
		{"not a signature", doc, xmltree.DocumentElement(doc), xmlsec.ErrMalformed},
		{"signature from another document", doc, findSignature(other), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := dsig.Verify(c.doc, c.sig, dsig.VerifyOptions{})
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestCoverage(t *testing.T) {
	c := &dsig.Coverage{SignedElementIDs: []string{"a", "b"}, SignedAttachmentIDs: []string{"x"}}
	cases := []struct {
		name string
		got  bool
		want bool
	}{
		{"all elements", c.Covers("a", "b"), true},
		{"no elements asked", c.Covers(), true},
		{"one element missing", c.Covers("a", "c"), false},
		{"attachment", c.CoversAttachments("x"), true},
		{"attachment missing", c.CoversAttachments("x", "y"), false},
		{"element ID is not an attachment ID", c.CoversAttachments("a"), false},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s: got %v", tc.name, tc.got)
		}
	}
}

// --- Signing ---------------------------------------------------------------

func (s covSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return s.out, s.err }

func (covOpaqueSigner) Public() crypto.PublicKey { return struct{}{} }

func TestKeyInfoNone(t *testing.T) {
	key := newKey(t, rsaKey)
	signed := covSignAndPlace(t, key, dsig.KeyInfoNone, nil, func(id string) []dsig.Reference {
		return []dsig.Reference{{URI: "#" + id, ID: "ref-1", Type: "urn:type", Transforms: excC14N, DigestAlgorithm: xmlsec.DigestSHA256}}
	})
	if strings.Contains(string(signed), "KeyInfo") {
		t.Fatal("KeyInfoNone emitted ds:KeyInfo")
	}
	cases := []struct {
		name string
		cert bool
		want error
	}{
		{"with VerifyOptions.Certificate", true, nil},
		{"without VerifyOptions.Certificate", false, xmlsec.ErrUnsupportedKeyInfo},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse(t, signed)
			var opts dsig.VerifyOptions
			if c.cert {
				opts.Certificate = key.Certificate
			}
			cov, err := dsig.Verify(doc, findSignature(doc), opts)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if err == nil && (cov.KeyInfoForm != dsig.KeyInfoNone || cov.References[0].Type != "urn:type") {
				t.Fatalf("form %d, references %+v", cov.KeyInfoForm, cov.References)
			}
		})
	}
}
