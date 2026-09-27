package wss

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
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
			doc := parseDoc(t, env11)
			h, err := NewHeader(doc, xmlsec.NSSOAP11, "", false)
			if err != nil {
				t.Fatal(err)
			}
			id, err := h.AddBinarySecurityToken(leaf, c.chain, c.valueType)
			if err != nil {
				t.Fatal(err)
			}
			str, err := NewSecurityTokenReference(doc, id, c.valueType)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ResolveSecurityTokenReference(doc, str)
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
	h, err := NewHeader(parseDoc(t, env11), xmlsec.NSSOAP11, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.AddBinarySecurityToken(cert, nil, "urn:bad"); !errors.Is(err, xmlsec.ErrUnsupportedAlgorithm) {
		t.Errorf("bad ValueType: %v", err)
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
		{"missing EncodingType", bst(v3, "AAAA"), xmlsec.ErrUnsupportedKeyInfo},
		{"bad EncodingType", bst(`EncodingType="urn:hex" `+v3, "AAAA"), xmlsec.ErrUnsupportedKeyInfo},
		{"bad base64", bst(enc+v3, "!!!"), xmlsec.ErrMalformed},
		{"bad ValueType", bst(enc+`ValueType="urn:x"`, "AAAA"), xmlsec.ErrUnsupportedKeyInfo},
		{"X509v3 not a certificate", bst(enc+v3, "AAAA"), nil},
		{"PkiPath not DER", bst(enc+pki, "AAAA"), xmlsec.ErrMalformed},
		{"PkiPath empty sequence", bst(enc+pki, "MAA="), xmlsec.ErrMalformed},
		{"PkiPath trailing data", bst(enc+pki, "MAAA"), xmlsec.ErrMalformed},
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
