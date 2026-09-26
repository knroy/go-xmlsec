package wss

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
)

// issue returns a certificate for cn signed by parent (self-signed when nil),
// and its key. A CA certificate gets a SubjectKeyId, and every certificate
// its issuer's as AuthorityKeyId, as crypto/x509 sets them.
func issue(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(1<<32, 0),
		IsCA:                  isCA,
		BasicConstraintsValid: isCA,
	}
	if parent == nil {
		parent, parentKey = tmpl, k
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

// chain3 returns a leaf, its intermediate CA and the root CA.
func chain3(t *testing.T) (leaf, inter, root *x509.Certificate) {
	root, rootKey := issue(t, "root", true, nil, nil)
	inter, interKey := issue(t, "intermediate", true, root, rootKey)
	leaf, _ = issue(t, "leaf", false, inter, interKey)
	return leaf, inter, root
}

func TestPKCS7RoundTrip(t *testing.T) {
	leaf, inter, root := chain3(t)
	for _, c := range []struct {
		name  string
		chain []*x509.Certificate
	}{
		{"leaf only", nil},
		{"issuers in path order", []*x509.Certificate{inter, root}},
		{"issuers reversed", []*x509.Certificate{root, inter}},
		{"issuer without the root", []*x509.Certificate{inter}},
	} {
		t.Run(c.name, func(t *testing.T) {
			doc := parseDoc(t, env11)
			h, err := NewHeader(doc, xmlsec.NSSOAP11, "", false)
			if err != nil {
				t.Fatal(err)
			}
			id, err := h.AddBinarySecurityToken(leaf, c.chain, xmlsec.BSTValueTypePKCS7)
			if err != nil {
				t.Fatal(err)
			}
			str, err := NewSecurityTokenReference(doc, id, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := h.Append(str); err != nil {
				t.Fatal(err)
			}
			for name, resolve := range map[string]func(doc, str *xdm.Node) (*x509.Certificate, error){
				"lenient": ResolveSecurityTokenReference,
				"strict":  ResolveSecurityTokenReferenceStrict,
			} {
				got, err := resolve(doc, str)
				if err != nil || !got.Equal(leaf) {
					t.Fatalf("%s: got %v, %v; want the leaf", name, got, err)
				}
			}
		})
	}
}

// The encoding is DER: the SET OF certificates is sorted, so the input order
// does not change it.
func TestMarshalPKCS7IsDER(t *testing.T) {
	leaf, inter, root := chain3(t)
	a := marshalPKCS7([]*x509.Certificate{leaf, inter, root})
	b := marshalPKCS7([]*x509.Certificate{root, leaf, inter})
	if !bytes.Equal(a, b) {
		t.Fatal("the certificate order changed the encoding")
	}
}

// pkcs7Certs returns the certificates of a certs-only SignedData, in
// encoded order.
func pkcs7Certs(t *testing.T, der []byte) []*x509.Certificate {
	t.Helper()
	var ci struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}
	var sd struct {
		Version       int
		Digests, Info asn1.RawValue
		Certs         asn1.RawValue
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatal(err)
	}
	var certs []*x509.Certificate
	for b := sd.Certs.Bytes; len(b) > 0; {
		var v asn1.RawValue
		var err error
		if b, err = asn1.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(v.FullBytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, c)
	}
	return certs
}

// An independent encoder, OpenSSL 3.6, wrote the fixtures, from a root, an
// intermediate and a leaf certificate (P-256, CA certificates with key
// identifiers):
//
//	openssl crl2pkcs7 -nocrl -certfile chain.pem -outform DER -out openssl.p7b
//
// chain.pem holds root, leaf, intermediate, in that order, for openssl.p7b,
// and leaf, intermediate, root, which is DER order, for openssl-sorted.p7b.
// OpenSSL keeps the input order. Both parse to the leaf, and this library
// encodes the same three certificates to exactly the bytes of the sorted
// one. The converse, that OpenSSL reads this library's encoding, was checked
// with openssl pkcs7 -inform DER -print_certs.
func TestPKCS7OpenSSLFixtures(t *testing.T) {
	for _, name := range []string{"openssl.p7b", "openssl-sorted.p7b"} {
		der, err := os.ReadFile("testdata/pkcs7/" + name)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := parsePKCS7(der)
		if err != nil || leaf.Subject.CommonName != "p7 leaf" {
			t.Fatalf("%s: got %v, %v", name, leaf, err)
		}
		certs := pkcs7Certs(t, der)
		if len(certs) != 3 {
			t.Fatalf("%s: %d certificates", name, len(certs))
		}
		if name == "openssl-sorted.p7b" && !bytes.Equal(marshalPKCS7(certs), der) {
			t.Errorf("our encoding differs from OpenSSL's")
		}
	}
}

func TestAddBinarySecurityTokenPKCS7Errors(t *testing.T) {
	leaf, inter, root := chain3(t)
	other, _ := issue(t, "other", false, nil, nil)
	many := make([]*x509.Certificate, maxPKCS7Certificates)
	for i := range many {
		many[i], _ = issue(t, "extra", false, nil, nil)
	}
	for _, c := range []struct {
		name  string
		cert  *x509.Certificate
		chain []*x509.Certificate
	}{
		{"cert issued a certificate in chain", inter, []*x509.Certificate{leaf, root}},
		{"two leaves", leaf, []*x509.Certificate{other}},
		{"too many certificates", leaf, many},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, err := NewHeader(parseDoc(t, env11), xmlsec.NSSOAP11, "", false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.AddBinarySecurityToken(c.cert, c.chain, xmlsec.BSTValueTypePKCS7); !errors.Is(err, xmlsec.ErrUnsupportedKeyInfo) {
				t.Fatalf("got %v", err)
			}
			if len(h.Element().ChildElements()) != 0 {
				t.Fatal("a failed call changed the header")
			}
		})
	}
}

// der builds a constructed element of the given class and tag.
func der(class, tag int, parts ...[]byte) []byte {
	b, _ := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: bytes.Join(parts, nil)})
	return b
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestParsePKCS7Errors(t *testing.T) {
	leaf, inter, root := chain3(t)
	// A root whose subject names the intermediate's issuer, but whose key
	// identifier is not the one the intermediate names.
	impostor, _ := issue(t, "root", true, nil, nil)
	// A self-signed certificate with no key identifiers, by name alone.
	noSKI, noSKIKey := issue(t, "plain", false, nil, nil)
	underNoSKI, _ := issue(t, "under plain", false, noSKI, noSKIKey)

	seq := func(parts ...[]byte) []byte { return der(asn1.ClassUniversal, asn1.TagSequence, parts...) }
	set := func(parts ...[]byte) []byte { return der(asn1.ClassUniversal, asn1.TagSet, parts...) }
	ctx := func(tag int, parts ...[]byte) []byte { return der(asn1.ClassContextSpecific, tag, parts...) }
	v1, v3 := mustMarshal(1), mustMarshal(3)
	data := seq(mustMarshal(oidData))
	certs := func(cs ...*x509.Certificate) []byte {
		var b [][]byte
		for _, c := range cs {
			b = append(b, c.Raw)
		}
		return ctx(0, b...)
	}
	// signed wraps SignedData fields in a signedData ContentInfo.
	signed := func(fields ...[]byte) []byte {
		return seq(mustMarshal(oidSignedData), ctx(0, seq(fields...)))
	}
	valid := signed(v1, set(), data, certs(leaf, inter, root), set())

	for _, c := range []struct {
		name string
		der  []byte
		want error // nil: parses to leaf, or to c.leaf when set
		leaf *x509.Certificate
	}{
		{"valid", valid, nil, nil},
		{"leaf last", signed(v1, set(), data, certs(root, inter, leaf), set()), nil, nil},
		{"CRLs and signer infos, both ignored", signed(v1, set(seq()), seq(mustMarshal(oidData), ctx(0, []byte{4, 0})), certs(leaf, inter), ctx(1, seq()), set(seq())), nil, nil},
		{"issuer by name without key identifiers", signed(v1, set(), data, certs(noSKI, underNoSKI), set()), nil, underNoSKI},
		{"not DER", []byte("AAAA"), xmlsec.ErrMalformed, nil},
		{"truncated", valid[:len(valid)-1], xmlsec.ErrMalformed, nil},
		{"trailing bytes", append(append([]byte{}, valid...), 0), xmlsec.ErrMalformed, nil},
		{"ContentInfo of type data", seq(mustMarshal(oidData), ctx(0, seq(v1))), xmlsec.ErrMalformed, nil},
		{"content not [0]", seq(mustMarshal(oidSignedData), ctx(1, seq(v1))), xmlsec.ErrMalformed, nil},
		{"SignedData not a SEQUENCE", seq(mustMarshal(oidSignedData), ctx(0, set())), xmlsec.ErrMalformed, nil},
		{"SignedData not DER", seq(mustMarshal(oidSignedData), ctx(0, []byte{0x30, 3, 2, 1})), xmlsec.ErrMalformed, nil},
		{"SignedData field not DER", signed(v1, []byte{0x31}), xmlsec.ErrMalformed, nil},
		{"too few fields", signed(v1, set(), data), xmlsec.ErrMalformed, nil},
		{"version not an INTEGER", signed(set(), set(), data, certs(leaf), set()), xmlsec.ErrMalformed, nil},
		{"version 3", signed(v3, set(), data, certs(leaf), set()), xmlsec.ErrUnsupportedKeyInfo, nil},
		{"digestAlgorithms not a SET", signed(v1, seq(), data, certs(leaf), set()), xmlsec.ErrMalformed, nil},
		{"contentInfo not a SEQUENCE", signed(v1, set(), set(), certs(leaf), set()), xmlsec.ErrMalformed, nil},
		{"contentInfo without a type", signed(v1, set(), seq(), certs(leaf), set()), xmlsec.ErrMalformed, nil},
		{"contentInfo of type signedData", signed(v1, set(), seq(mustMarshal(oidSignedData)), certs(leaf), set()), xmlsec.ErrMalformed, nil},
		{"signerInfos not a SET", signed(v1, set(), data, certs(leaf), seq()), xmlsec.ErrMalformed, nil},
		{"a field after signerInfos", signed(v1, set(), data, certs(leaf), set(), set()), xmlsec.ErrMalformed, nil},
		{"no certificates", signed(v1, set(), data, set()), xmlsec.ErrMalformed, nil},
		{"empty certificates", signed(v1, set(), data, certs(), set()), xmlsec.ErrMalformed, nil},
		{"certificates not DER", signed(v1, set(), data, ctx(0, []byte{0x30}), set()), xmlsec.ErrMalformed, nil},
		{"a certificate that is not one", signed(v1, set(), data, ctx(0, seq()), set()), xmlsec.ErrMalformed, nil},
		{"an attribute certificate", signed(v1, set(), data, ctx(0, ctx(2)), set()), xmlsec.ErrUnsupportedKeyInfo, nil},
		{"two leaves", signed(v1, set(), data, certs(leaf, underNoSKI), set()), xmlsec.ErrUnsupportedKeyInfo, nil},
		{"the leaf twice", signed(v1, set(), data, certs(leaf, leaf, inter), set()), xmlsec.ErrUnsupportedKeyInfo, nil},
		{"issuer name without its key identifier", signed(v1, set(), data, certs(inter, impostor), set()), xmlsec.ErrUnsupportedKeyInfo, nil},
		{"a self-signed certificate twice: no leaf", signed(v1, set(), data, certs(root, root), set()), xmlsec.ErrUnsupportedKeyInfo, nil},
		{"too many certificates", signed(v1, set(), data, ctx(0, bytes.Repeat(leaf.Raw, maxPKCS7Certificates+1)), set()), xmlsec.ErrUnsupportedKeyInfo, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			want := c.leaf
			if want == nil {
				want = leaf
			}
			got, err := parsePKCS7(c.der)
			if !errors.Is(err, c.want) || c.want == nil && !got.Equal(want) {
				t.Fatalf("got %v, %v; want %v", got, err, c.want)
			}
		})
	}
	if len(noSKI.SubjectKeyId) != 0 || len(underNoSKI.AuthorityKeyId) != 0 {
		t.Error("the certificates meant to have no key identifiers have them")
	}
}
