package security

import (
	"errors"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/xenc"
)

// An XPath transform on an xenc:CipherReference is the sender's program
// too: an expression the caller did not allow, or the allowed text with
// its prefix bound elsewhere, is refused before ResolveURI is called and
// before any decryption (the key given would fail it otherwise).
func TestCipherReferenceXPathRefusedBeforeFetch(t *testing.T) {
	const rep = "http://www.example.org/repository"
	const expr = `self::text()[parent::rep:CipherValue[@Id="example1"]]`
	ed := func(bind, e string) *xdm.Node {
		tree, err := xmlsec.Parse([]byte(`<xenc:EncryptedData xmlns:xenc="` + xmlsec.NSXEnc + `" xmlns:ds="` + xmlsec.NSDSig + `">` +
			`<xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128GCM + `"/><xenc:CipherData>` +
			`<xenc:CipherReference URI="http://example.invalid/CipherValues.xml"><xenc:Transforms>` +
			`<ds:Transform Algorithm="` + xmlsec.TransformXPath + `"><ds:XPath xmlns:rep="` + bind + `">` + e + `</ds:XPath></ds:Transform>` +
			`<ds:Transform Algorithm="` + xmlsec.TransformBase64 + `"/></xenc:Transforms></xenc:CipherReference>` +
			`</xenc:CipherData></xenc:EncryptedData>`))
		if err != nil {
			t.Fatal(err)
		}
		return tree.Root.ChildElements()[0]
	}
	allow := []dsig.XPathExpression{{Expr: expr, Namespaces: map[string]string{"rep": rep}}}
	for name, c := range map[string]struct {
		el    *xdm.Node
		allow []dsig.XPathExpression
	}{
		"no allow-list":  {ed(rep, expr), nil},
		"not listed":     {ed(rep, `//text()`), allow},
		"prefix rebound": {ed("urn:attacker", expr), allow},
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			_, err := xenc.DecryptData(c.el, []byte("bad key"), xenc.DecryptOptions{
				AllowedXPathExpressions: c.allow,
				ResolveURI:              func(string) ([]byte, error) { called = true; return nil, nil },
			})
			if !errors.Is(err, xmlsec.ErrTransformRefused) || called {
				t.Fatalf("got %v, resolver called %v", err, called)
			}
		})
	}
}

// A relative CipherReference URI is resolved against the caller's
// DecryptOptions.BaseURI only. The document's xml:base, the sender's
// choice, never steers the fetch: without BaseURI the reference is
// refused, and with it xml:base is ignored.
func TestCipherReferenceBaseURINeverFromXMLBase(t *testing.T) {
	tree, err := xmlsec.Parse([]byte(`<r xml:base="http://169.254.169.254/latest/"><xenc:EncryptedData xmlns:xenc="` + xmlsec.NSXEnc + `" xml:base="file:///etc/">` +
		`<xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128GCM + `"/>` +
		`<xenc:CipherData><xenc:CipherReference URI="passwd"/></xenc:CipherData></xenc:EncryptedData></r>`))
	if err != nil {
		t.Fatal(err)
	}
	ed := tree.Root.ChildElements()[0].ChildElements()[0]
	var fetched []string
	resolve := func(u string) ([]byte, error) { fetched = append(fetched, u); return nil, errors.New("not served") }

	if _, err := xenc.DecryptData(ed, make([]byte, 16), xenc.DecryptOptions{ResolveURI: resolve}); !errors.Is(err, xmlsec.ErrMalformed) || len(fetched) != 0 {
		t.Fatalf("without BaseURI: %v, fetched %q", err, fetched)
	}
	_, err = xenc.DecryptData(ed, make([]byte, 16), xenc.DecryptOptions{ResolveURI: resolve, BaseURI: "https://example.com/msgs/1.xml"})
	if !errors.Is(err, xmlsec.ErrDereference) || len(fetched) != 1 || fetched[0] != "https://example.com/msgs/passwd" {
		t.Fatalf("with BaseURI: %v, fetched %q", err, fetched)
	}
}
