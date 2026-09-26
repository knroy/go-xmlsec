package wss

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// certFrom self-signs tmpl, given a serial number and validity if it has
// none.
func certFrom(t *testing.T, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(1)
	}
	tmpl.NotBefore, tmpl.NotAfter = time.Unix(0, 0), time.Unix(1<<32, 0)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// acmeCert has a SubjectKeyIdentifier, a three-RDN issuer with a comma in a
// value, and a large serial number.
func acmeCert(t *testing.T, ski []byte) *x509.Certificate {
	t.Helper()
	serial, _ := new(big.Int).SetString("123456789012345678901234567890", 10)
	return certFrom(t, &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Country: []string{"NO"}, Organization: []string{"Acme, Inc."}, CommonName: "Test CA"},
		SubjectKeyId: ski,
	})
}

func sha1Of(b []byte) []byte {
	h := crypto.SHA1.New()
	h.Write(b)
	return h.Sum(nil)
}

func TestNewKeyIdentifierReference(t *testing.T) {
	for name, c := range map[string]*x509.Certificate{"nil": nil, "unparsed": {}} {
		if _, err := NewKeyIdentifierReference(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	withSKI, noSKI := acmeCert(t, []byte{1, 2, 3, 4}), testCert(t, "no SKI")
	if len(noSKI.SubjectKeyId) != 0 {
		t.Fatal("testCert has an SKI")
	}
	for _, c := range []struct {
		name      string
		cert      *x509.Certificate
		valueType string
		value     []byte
	}{
		{"SKI (R5206, R5208)", withSKI, valueTypeSKI, []byte{1, 2, 3, 4}},
		{"no SKI: ThumbprintSHA1 (R5210)", noSKI, valueTypeThumbprintSHA1, sha1Of(noSKI.Raw)},
	} {
		t.Run(c.name, func(t *testing.T) {
			str, err := NewKeyIdentifierReference(c.cert)
			if err != nil {
				t.Fatal(err)
			}
			ki := str.ChildElements()[0]
			if !ki.IsElement(xmlsec.NSWSSE, "KeyIdentifier") || ki.AttrValue("ValueType") != c.valueType ||
				ki.AttrValue("EncodingType") != xmlsec.BSTEncodingBase64 ||
				ki.StringValue() != base64.StdEncoding.EncodeToString(c.value) {
				t.Fatalf("%v ValueType %q EncodingType %q value %q", ki.Name, ki.AttrValue("ValueType"), ki.AttrValue("EncodingType"), ki.StringValue())
			}
			if !MatchSecurityTokenReference(str, c.cert) {
				t.Error("does not match its own certificate")
			}
			if MatchSecurityTokenReference(str, acmeCert(t, []byte{9})) {
				t.Error("matches another certificate")
			}
		})
	}
}

func TestNewIssuerSerialReference(t *testing.T) {
	for name, c := range map[string]*x509.Certificate{
		"nil":       nil,
		"no serial": {},
	} {
		if _, err := NewIssuerSerialReference(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := NewIssuerSerialReference(&x509.Certificate{SerialNumber: big.NewInt(1)}); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Errorf("no RawIssuer: %v", err)
	}

	cert := acmeCert(t, nil)
	str, err := NewIssuerSerialReference(cert)
	if err != nil {
		t.Fatal(err)
	}
	xd := str.ChildElements()[0]
	is := xd.ChildElements()[0].ChildElements()
	if !xd.IsElement(xmlsec.NSDSig, "X509Data") || len(is) != 2 {
		t.Fatalf("structure %v", xd.Name)
	}
	if got := is[0].StringValue(); got != `CN=Test CA,O=Acme\, Inc.,C=NO` {
		t.Errorf("issuer %q", got)
	}
	if got := is[1].StringValue(); got != "123456789012345678901234567890" {
		t.Errorf("serial %q", got)
	}
	if !MatchSecurityTokenReference(str, cert) {
		t.Error("does not match its own certificate")
	}
	if MatchSecurityTokenReference(str, testCert(t, "Test CA")) {
		t.Error("matches another certificate")
	}
}

func TestMatchSecurityTokenReference(t *testing.T) {
	cert := acmeCert(t, []byte{1, 2, 3, 4})
	ski := base64.StdEncoding.EncodeToString(cert.SubjectKeyId)
	thumb := base64.StdEncoding.EncodeToString(sha1Of(cert.Raw))
	ki := func(attrs, v string) string {
		return `<wsse:KeyIdentifier ` + attrs + `>` + v + `</wsse:KeyIdentifier>`
	}
	vt := func(v string) string { return `ValueType="` + v + `" ` }
	enc := `EncodingType="` + xmlsec.BSTEncodingBase64 + `" `
	is := func(inner string) string {
		return `<ds:X509Data><ds:X509IssuerSerial>` + inner + `</ds:X509IssuerSerial></ds:X509Data>`
	}
	name := func(n string) string { return `<ds:X509IssuerName>` + n + `</ds:X509IssuerName>` }
	serial := func(s string) string { return `<ds:X509SerialNumber>` + s + `</ds:X509SerialNumber>` }
	const issuer, number = `CN=Test CA,O=Acme\, Inc.,C=NO`, "123456789012345678901234567890"

	for _, c := range []struct {
		name, inner string
		want        bool
	}{
		{"SKI", ki(vt(valueTypeSKI)+enc, ski), true},
		{"SKI without EncodingType", ki(vt(valueTypeSKI), ski), true},
		{"ThumbprintSHA1", ki(vt(valueTypeThumbprintSHA1)+enc, thumb), true},
		{"IssuerSerial", is(name(issuer) + serial(number)), true},
		{"IssuerSerial as .NET writes it", is(name(`CN=Test CA, O="Acme, Inc.", C=NO`) + serial(" "+number+" ")), true},
		{"wrong SKI", ki(vt(valueTypeSKI)+enc, thumb), false},
		{"wrong thumbprint", ki(vt(valueTypeThumbprintSHA1)+enc, ski), false},
		{"hex EncodingType", ki(vt(valueTypeSKI)+`EncodingType="urn:hex" `, ski), false},
		{"bad base64", ki(vt(valueTypeSKI)+enc, "!!"), false},
		{"empty identifier", ki(vt(valueTypeSKI)+enc, ""), false},
		{"unknown ValueType", ki(vt("urn:x")+enc, ski), false},
		{"X509Data with two children", `<ds:X509Data>` + name(issuer) + serial(number) + `</ds:X509Data>`, false},
		{"X509Data with an SKI", `<ds:X509Data><ds:X509SKI>` + ski + `</ds:X509SKI></ds:X509Data>`, false},
		{"IssuerSerial without serial", is(name(issuer)), false},
		{"IssuerSerial reversed", is(serial(number) + name(issuer)), false},
		{"serial not a number", is(name(issuer) + serial("0x1")), false},
		{"wrong serial", is(name(issuer) + serial("1")), false},
		{"wrong issuer", is(name(`CN=Test CA,O=Acme,C=NO`) + serial(number)), false},
		{"direct reference", `<wsse:Reference URI="#t"/>`, false},
		{"two references", ki(vt(valueTypeSKI)+enc, ski) + ki(vt(valueTypeSKI)+enc, ski), false},
	} {
		doc := parseDoc(t, `<wsse:SecurityTokenReference xmlns:wsse="`+xmlsec.NSWSSE+`" xmlns:ds="`+xmlsec.NSDSig+`">`+c.inner+`</wsse:SecurityTokenReference>`)
		str := xmltree.DocumentElement(doc)
		if got := MatchSecurityTokenReference(str, cert); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
		if c.want && (MatchSecurityTokenReference(str, nil) || MatchSecurityTokenReference(str.ChildElements()[0], cert)) {
			t.Errorf("%s: matched a nil certificate or a non-STR", c.name)
		}
	}
	if MatchSecurityTokenReference(nil, cert) {
		t.Error("nil STR matched")
	}
	// A certificate without a serial number matches no issuer-serial.
	str, err := NewIssuerSerialReference(cert)
	if err != nil {
		t.Fatal(err)
	}
	if MatchSecurityTokenReference(str, &x509.Certificate{RawIssuer: cert.RawIssuer}) {
		t.Error("matched a certificate without a serial number")
	}
}

// strictFixture is a header holding an X509v3 token and a PKIPath token,
// plus a second header for another actor holding a third.
type strictFixture struct {
	doc, body       *xdm.Node
	h               *Header
	v3, pki, other  string
	cert, otherCert *x509.Certificate
}

func newStrictFixture(t *testing.T) strictFixture {
	t.Helper()
	f := strictFixture{doc: parseDoc(t, env11), cert: testCert(t, "c"), otherCert: testCert(t, "o")}
	var err error
	if f.h, err = NewHeader(f.doc, xmlsec.NSSOAP11, "", false); err != nil {
		t.Fatal(err)
	}
	if f.v3, err = f.h.AddBinarySecurityToken(f.cert, nil, xmlsec.BSTValueTypeX509v3); err != nil {
		t.Fatal(err)
	}
	if f.pki, err = f.h.AddBinarySecurityToken(f.cert, nil, xmlsec.BSTValueTypeX509PKIPath); err != nil {
		t.Fatal(err)
	}
	h2, err := NewHeader(f.doc, xmlsec.NSSOAP11, "urn:other", false)
	if err != nil {
		t.Fatal(err)
	}
	if f.other, err = h2.AddBinarySecurityToken(f.otherCert, nil, xmlsec.BSTValueTypeX509v3); err != nil {
		t.Fatal(err)
	}
	f.body = xmltree.DocumentElement(f.doc).ChildElements()[1]
	return f
}

// strTo builds a ds:KeyInfo holding an STR to id, with the given Reference
// ValueType and wsse11:TokenType, each omitted when empty.
func strTo(id, valueType, tokenType string) *xdm.Node {
	ki := xmltree.Element(nil, "ds", xmlsec.NSDSig, "KeyInfo")
	ki.AddNamespace("ds", xmlsec.NSDSig)
	str := newSTR()
	ki.AppendChild(str)
	if tokenType != "" {
		str.AddNamespace("wsse11", xmlsec.NSWSSE11)
		xmltree.SetAttr(str, "wsse11", xmlsec.NSWSSE11, "TokenType", tokenType)
	}
	ref := xmltree.Element(str, "wsse", xmlsec.NSWSSE, "Reference")
	xmltree.SetAttr(ref, "", "", "URI", "#"+id)
	if valueType != "" {
		xmltree.SetAttr(ref, "", "", "ValueType", valueType)
	}
	return ki
}

func TestResolveSecurityTokenReferenceStrict(t *testing.T) {
	v3, pki := xmlsec.BSTValueTypeX509v3, xmlsec.BSTValueTypeX509PKIPath
	type place int
	const (
		after  place = iota // appended to the token's header
		before              // first in the token's header
		body                // in the SOAP Body
	)
	for _, c := range []struct {
		name                 string
		id                   func(strictFixture) string
		valueType, tokenType string
		where                place
		want                 error // nil: resolves
	}{
		{"X509v3", func(f strictFixture) string { return f.v3 }, v3, "", after, nil},
		{"X509v3 with TokenType", func(f strictFixture) string { return f.v3 }, v3, v3, after, nil},
		{"PKIPath with TokenType (R5215)", func(f strictFixture) string { return f.pki }, pki, pki, after, nil},
		{"no ValueType (R3059)", func(f strictFixture) string { return f.v3 }, "", "", after, xmlsec.ErrMalformed},
		{"wrong ValueType (R3058)", func(f strictFixture) string { return f.v3 }, pki, "", after, xmlsec.ErrMalformed},
		{"PKIPath without TokenType (R5215)", func(f strictFixture) string { return f.pki }, pki, "", after, xmlsec.ErrMalformed},
		{"inconsistent TokenType", func(f strictFixture) string { return f.v3 }, v3, pki, after, xmlsec.ErrMalformed},
		{"reference before the token (R5205)", func(f strictFixture) string { return f.v3 }, v3, "", before, xmlsec.ErrMalformed},
		{"reference outside the header (R3066)", func(f strictFixture) string { return f.v3 }, v3, "", body, xmlsec.ErrMalformed},
		{"token in another header (R3066)", func(f strictFixture) string { return f.other }, v3, "", after, xmlsec.ErrMalformed},
		{"token not in a header", func(strictFixture) string { return "bodytoken" }, v3, "", after, xmlsec.ErrMalformed},
		{"missing token", func(strictFixture) string { return "nope" }, v3, "", after, xmlsec.ErrIDNotFound},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newStrictFixture(t)
			tok := xmltree.Element(f.body, "wsse", xmlsec.NSWSSE, "BinarySecurityToken")
			xmltree.SetAttr(tok, "wsu", xmlsec.NSWSU, "Id", "bodytoken")
			xmltree.SetAttr(tok, "", "", "ValueType", v3)

			ki := strTo(c.id(f), c.valueType, c.tokenType)
			switch c.where {
			case after:
				if err := f.h.Append(ki); err != nil {
					t.Fatal(err)
				}
			case before:
				f.h.insert(0, ki)
			case body:
				f.body.AppendChild(ki)
			}
			str := ki.ChildElements()[0]
			got, err := ResolveSecurityTokenReferenceStrict(f.doc, str)
			if !errors.Is(err, c.want) || c.want == nil && !got.Equal(f.cert) {
				t.Fatalf("got %v, %v; want %v", got, err, c.want)
			}
			// The lenient resolution accepts every well-formed reference to a
			// certificate.
			if c.want == xmlsec.ErrMalformed && c.id(f) != "bodytoken" {
				if _, err := ResolveSecurityTokenReference(f.doc, str); err != nil {
					t.Errorf("lenient: %v", err)
				}
			}
		})
	}
	if _, err := ResolveSecurityTokenReferenceStrict(nil, nil); !errors.Is(err, xmlsec.ErrUnsupportedKeyInfo) {
		t.Errorf("nil: %v", err)
	}
}

func TestNewSecurityTokenReference(t *testing.T) {
	if _, err := NewSecurityTokenReference(nil, "", xmlsec.BSTValueTypeX509v3); err == nil {
		t.Fatal("empty token ID accepted")
	}
	// No ValueType and no token to read it from (BSP R3059).
	if _, err := NewSecurityTokenReference(nil, "tok", ""); !errors.Is(err, xmlsec.ErrIDNotFound) {
		t.Fatalf("no ValueType, no document: %v", err)
	}
	doc := parseDoc(t, `<r xmlns:wsse="`+xmlsec.NSWSSE+`" xmlns:wsu="`+xmlsec.NSWSU+`">`+
		`<wsse:BinarySecurityToken wsu:Id="pki" ValueType="`+xmlsec.BSTValueTypeX509PKIPath+`"/>`+
		`<wsse:BinarySecurityToken wsu:Id="none"/></r>`)
	if _, err := NewSecurityTokenReference(doc, "none", ""); !errors.Is(err, xmlsec.ErrUnsupportedKeyInfo) {
		t.Fatalf("token without ValueType: %v", err)
	}

	for _, c := range []struct {
		name, id, valueType, wantVT, wantTT string
	}{
		{"X509v3: no TokenType", "tok", xmlsec.BSTValueTypeX509v3, xmlsec.BSTValueTypeX509v3, ""},
		{"PKIPath read from the token (R5215)", "pki", "", xmlsec.BSTValueTypeX509PKIPath, xmlsec.BSTValueTypeX509PKIPath},
		{"PKCS7 (R5212)", "p7", valueTypePKCS7, valueTypePKCS7, valueTypePKCS7},
	} {
		t.Run(c.name, func(t *testing.T) {
			str, err := NewSecurityTokenReference(doc, c.id, c.valueType)
			if err != nil {
				t.Fatal(err)
			}
			ref := str.ChildElements()[0]
			if ref.AttrValue("URI") != "#"+c.id || ref.AttrValue("ValueType") != c.wantVT {
				t.Errorf("URI %q, ValueType %q", ref.AttrValue("URI"), ref.AttrValue("ValueType"))
			}
			if got := xmltree.AttrValue(str, xmlsec.NSWSSE11, "TokenType"); got != c.wantTT {
				t.Errorf("TokenType %q, want %q", got, c.wantTT)
			}
			// The wsse11 prefix is declared on the element itself.
			if tt := str.Attr(xmlsec.NSWSSE11, "TokenType"); tt != nil {
				if uri, _ := str.LookupPrefix(tt.Name.Prefix); uri != xmlsec.NSWSSE11 {
					t.Errorf("prefix %q bound to %q", tt.Name.Prefix, uri)
				}
			}
		})
	}
}

func TestResolveSecurityTokenReferenceErrors(t *testing.T) {
	str := func(inner string) string {
		return `<soap:Envelope xmlns:soap="` + xmlsec.NSSOAP11 + `" xmlns:wsse="` + xmlsec.NSWSSE + `" xmlns:wsu="` + xmlsec.NSWSU + `">` +
			`<soap:Body><wsse:SecurityTokenReference>` + inner + `</wsse:SecurityTokenReference>` +
			`<x wsu:Id="dup"/><y wsu:Id="dup"/><z wsu:Id="notbst"/></soap:Body></soap:Envelope>`
	}
	cases := []struct {
		name   string
		doc    string
		notSTR bool
		want   error
	}{
		{"not an STR", str(`<wsse:Reference URI="#notbst"/>`), true, xmlsec.ErrUnsupportedKeyInfo},
		{"no children", str(``), false, xmlsec.ErrUnsupportedKeyInfo},
		{"multiple children", str(`<wsse:Reference URI="#a"/><wsse:Reference URI="#b"/>`), false, xmlsec.ErrUnsupportedKeyInfo},
		{"KeyIdentifier", str(`<wsse:KeyIdentifier>AAAA</wsse:KeyIdentifier>`), false, xmlsec.ErrUnsupportedKeyInfo},
		{"non-local URI", str(`<wsse:Reference URI="http://example.com/tok"/>`), false, xmlsec.ErrUnsupportedKeyInfo},
		{"empty fragment", str(`<wsse:Reference URI="#"/>`), false, xmlsec.ErrUnsupportedKeyInfo},
		{"missing URI", str(`<wsse:Reference/>`), false, xmlsec.ErrUnsupportedKeyInfo},
		{"missing token", str(`<wsse:Reference URI="#nope"/>`), false, xmlsec.ErrIDNotFound},
		{"ambiguous token", str(`<wsse:Reference URI="#dup"/>`), false, xmlsec.ErrAmbiguousID},
		{"target not a BST", str(`<wsse:Reference URI="#notbst"/>`), false, xmlsec.ErrUnsupportedKeyInfo},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parseDoc(t, c.doc)
			el := xmltree.DocumentElement(doc).ChildElements()[0].ChildElements()[0]
			if c.notSTR {
				el = el.ChildElements()[0]
			}
			if _, err := ResolveSecurityTokenReference(doc, el); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}
