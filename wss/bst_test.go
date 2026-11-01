package wss

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
)

func testCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<32, 0),
	}
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

func TestBinarySecurityTokenRoundTrip(t *testing.T) {
	leaf, ca := testCert(t, "leaf"), testCert(t, "ca")
	cases := []struct {
		name      string
		chain     []*x509.Certificate
		valueType string
	}{
		{"X509v3", nil, xmlsec.BSTValueTypeX509v3},
		{"PKIPath leaf only", nil, xmlsec.BSTValueTypeX509PKIPath},
		{"PKIPath with chain", []*x509.Certificate{ca}, xmlsec.BSTValueTypeX509PKIPath},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := newDoc(t, env11)
			h, err := NewHeader(doc, xmlsec.NSSOAP11, "", false)
			if err != nil {
				t.Fatal(err)
			}
			id, err := h.AddBinarySecurityToken(leaf, c.chain, c.valueType)
			if err != nil {
				t.Fatal(err)
			}
			str, err := NewSecurityTokenReference(doc.Root(), id, c.valueType)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ResolveSecurityTokenReference(doc.Root(), str)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(leaf) {
				t.Fatalf("resolved %s, want the leaf", got.Subject.CommonName)
			}
		})
	}
}

func TestAddBinarySecurityTokenErrors(t *testing.T) {
	cert := testCert(t, "c")
	h, err := NewHeader(newDoc(t, env11), xmlsec.NSSOAP11, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.AddBinarySecurityToken(cert, nil, "urn:bad"); !errors.Is(err, xmlsec.ErrUnsupportedAlgorithm) {
		t.Errorf("bad ValueType: %v", err)
	}
	if _, err := h.AddBinarySecurityToken(nil, nil, xmlsec.BSTValueTypeX509v3); err == nil {
		t.Error("nil certificate accepted")
	}
	if _, err := h.AddBinarySecurityToken(cert, []*x509.Certificate{nil}, xmlsec.BSTValueTypePKCS7); err == nil {
		t.Error("nil in chain accepted")
	}

}

// A token without an EncodingType is Base64Binary, the default of SOAP
// Message Security 1.1.1 section 6.3; the strict resolver refuses it, as
// BSP requires the attribute (R3029).
func TestBinarySecurityTokenDefaultEncoding(t *testing.T) {
	f := newStrictFixture(t)
	str, err := NewSecurityTokenReference(f.doc.Root(), f.v3, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.h.Append(str); err != nil {
		t.Fatal(err)
	}
	// A parsed tree cannot lose an attribute: drop it from the octets.
	out, err := c14n.Bytes(f.doc.Root(), c14n.Options{Algorithm: c14n.Inclusive10})
	if err != nil {
		t.Fatal(err)
	}
	doc := parseDoc(t, regexp.MustCompile(` EncodingType="[^"]*"`).ReplaceAllString(string(out), ""))
	tok, err := FindByID(doc, f.v3)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Attr("", "EncodingType") != nil {
		t.Fatal("EncodingType still there")
	}
	if got, err := ParseBinarySecurityToken(tok); err != nil || !got.Equal(f.cert) {
		t.Fatalf("no EncodingType: %v", err)
	}
	str = nil
	xmltree.Walk(doc, func(e *xdm.Node) {
		if e.IsElement(xmlsec.NSWSSE, "SecurityTokenReference") {
			str = e
		}
	})
	if _, err := ResolveSecurityTokenReference(doc, str); err != nil {
		t.Fatalf("lenient: %v", err)
	}
	if _, err := ResolveSecurityTokenReferenceStrict(doc, str); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("strict: %v", err)
	}
}

func bst(attrs, content string) string {
	return `<wsse:BinarySecurityToken xmlns:wsse="` + xmlsec.NSWSSE + `" ` + attrs + `>` + content + `</wsse:BinarySecurityToken>`
}

func TestParseBinarySecurityTokenErrors(t *testing.T) {
	enc := `EncodingType="` + xmlsec.BSTEncodingBase64 + `" `
	v3 := `ValueType="` + xmlsec.BSTValueTypeX509v3 + `"`
	pki := `ValueType="` + xmlsec.BSTValueTypeX509PKIPath + `"`
	cases := []struct {
		name string
		doc  string
		want error // nil: any error
	}{
		{"not a BST", `<wsse:Other xmlns:wsse="` + xmlsec.NSWSSE + `"/>`, xmlsec.ErrUnsupportedKeyInfo},
		{"bad EncodingType", bst(`EncodingType="urn:hex" `+v3, "AAAA"), xmlsec.ErrUnsupportedKeyInfo},
		{"bad base64", bst(enc+v3, "!!!"), xmlsec.ErrMalformed},
		{"bad ValueType", bst(enc+`ValueType="urn:x"`, "AAAA"), xmlsec.ErrUnsupportedKeyInfo},
		{"X509v3 not a certificate", bst(enc+v3, "AAAA"), nil},
		{"PkiPath not DER", bst(enc+pki, "AAAA"), xmlsec.ErrMalformed},
		{"PkiPath empty sequence", bst(enc+pki, "MAA="), xmlsec.ErrMalformed},
		{"PkiPath trailing data", bst(enc+pki, "MAAA"), xmlsec.ErrMalformed},
		{"PkiPath a SET", bst(enc+pki, "MQA="), xmlsec.ErrMalformed},
		{"PkiPath element truncated", bst(enc+pki, "MAIwBQ=="), xmlsec.ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			el := xmltree.DocumentElement(parseDoc(t, c.doc))
			_, err := ParseBinarySecurityToken(el)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			// A token that is not what it says is wsse:InvalidSecurityToken;
			// one this library does not read is only unsupported.
			if unsupported := errors.Is(err, xmlsec.ErrUnsupportedKeyInfo); unsupported == errors.Is(err, xmlsec.ErrInvalidSecurityToken) {
				t.Fatalf("%v: unsupported %v, invalid %v", err, unsupported, !unsupported)
			}
		})
	}
}

// A PkiPath carries at most 16 certificates, the target last, as a PKCS7
// token; the sender refuses to build a longer one.
func TestPKIPathBound(t *testing.T) {
	leaf, ca := testCert(t, "leaf"), testCert(t, "ca")
	path := func(n int) []byte {
		return der(asn1.ClassUniversal, asn1.TagSequence, bytes.Repeat(ca.Raw, n-1), leaf.Raw)
	}
	if got, err := parsePKIPath(path(maxPKCS7Certificates)); err != nil || !got.Equal(leaf) {
		t.Fatalf("16: got %v, %v", got, err)
	}
	if _, err := parsePKIPath(path(maxPKCS7Certificates + 1)); !errors.Is(err, xmlsec.ErrUnsupportedKeyInfo) {
		t.Fatalf("17: got %v", err)
	}
	h, err := NewHeader(newDoc(t, env11), xmlsec.NSSOAP11, "", false)
	if err != nil {
		t.Fatal(err)
	}
	chain := slices.Repeat([]*x509.Certificate{ca}, maxPKCS7Certificates-1)
	if _, err := h.AddBinarySecurityToken(leaf, chain, xmlsec.BSTValueTypeX509PKIPath); err != nil {
		t.Fatalf("15 in chain: %v", err)
	}
	if _, err := h.AddBinarySecurityToken(leaf, append(chain, ca), xmlsec.BSTValueTypeX509PKIPath); !errors.Is(err, xmlsec.ErrUnsupportedKeyInfo) {
		t.Fatalf("16 in chain: got %v", err)
	}
}
