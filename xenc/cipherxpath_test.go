package xenc_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/xenc"
)

const repNS = "http://www.example.org/repository"

// cipherRef is an EncryptedData of Type Element whose CipherReference names
// uri with the given xenc:Transforms content.
func cipherRef(uri, transforms string) string {
	return covED(`Type="`+xenc.TypeElement+`"`, covEM(xmlsec.EncAES128GCM)+
		`<xenc:CipherData><xenc:CipherReference URI="`+uri+`"><xenc:Transforms xmlns:ds="`+xmlsec.NSDSig+`">`+
		transforms+`</xenc:Transforms></xenc:CipherReference></xenc:CipherData>`)
}

// xpathT is a ds:Transform of the XPath transform carrying expr, binding
// the rep prefix to uri.
func xpathT(uri, expr string) string {
	return `<ds:Transform Algorithm="` + xmlsec.TransformXPath + `"><ds:XPath xmlns:rep="` + uri + `">` + expr + `</ds:XPath></ds:Transform>`
}

var base64T = `<ds:Transform Algorithm="` + xmlsec.TransformBase64 + `"/>`

// repository is Example 13's CipherValues.xml, with the ciphertext split
// across two text nodes and a decoy value beside it.
func repository(b64 string) string {
	return `<rep:CipherValues xmlns:rep="` + repNS + `"><rep:CipherValue Id="decoy">AAAA</rep:CipherValue>` +
		`<rep:CipherValue Id="example1">` + b64[:8] + `<!-- split -->` + b64[8:] + `</rep:CipherValue></rep:CipherValues>`
}

const example13 = `self::text()[parent::rep:CipherValue[@Id="example1"]]`

var allowExample13 = []dsig.XPathExpression{{Expr: example13, Namespaces: map[string]string{"rep": repNS}}}

// Section 3.3.1, Example 13: an XPath transform selecting the ciphertext's
// base64 text, then base64, on an external or same-document reference.
func TestCipherReferenceXPath(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	b64 := base64.StdEncoding.EncodeToString(sealGCM(key, "secret"))
	const uri = "http://www.example.com/CipherValues.xml"
	chain := xpathT(repNS, "\n  "+example13+"\n") + base64T
	var fetched []string
	opts := xenc.DecryptOptions{
		AllowedXPathExpressions: allowExample13,
		ResolveURI: func(u string) ([]byte, error) {
			fetched = append(fetched, u)
			return []byte(repository(b64)), nil
		},
	}
	for name, doc := range map[string]string{
		"external":      cipherRef(uri, chain),
		"same document": `<r>` + repository(b64) + cipherRef("", chain) + `</r>`,
		"#id":           `<r>` + repository(b64) + cipherRef("#example1", chain) + `</r>`,
	} {
		t.Run(name, func(t *testing.T) {
			pt, err := xenc.DecryptData(firstNamed(covParse(t, doc), "EncryptedData"), key, opts)
			if err != nil || string(pt) != "secret" {
				t.Fatalf("%s, %v", pt, err)
			}
		})
	}
	if len(fetched) != 1 || fetched[0] != uri {
		t.Fatalf("fetched %q", fetched)
	}
}

// Every refusal of the XPath transform comes before ResolveURI is called
// and before any decryption.
func TestCipherReferenceXPathRefused(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	const uri = "http://example.invalid/cv.xml"
	good := xpathT(repNS, example13)
	for name, c := range map[string]struct {
		transforms string
		allow      []dsig.XPathExpression
		want       error
	}{
		"no allow-list":      {good + base64T, nil, xmlsec.ErrTransformRefused},
		"not listed":         {xpathT(repNS, "self::text()") + base64T, allowExample13, xmlsec.ErrTransformRefused},
		"prefix rebound":     {xpathT("urn:attacker", example13) + base64T, allowExample13, xmlsec.ErrTransformRefused},
		"no ds:XPath":        {`<ds:Transform Algorithm="` + xmlsec.TransformXPath + `"/>` + base64T, allowExample13, xmlsec.ErrMalformed},
		"XPath with child":   {`<ds:Transform Algorithm="` + xmlsec.TransformXPath + `"><ds:XPath><x/></ds:XPath></ds:Transform>` + base64T, allowExample13, xmlsec.ErrMalformed},
		"other element":      {`<ds:Transform Algorithm="` + xmlsec.TransformXPath + `"><ds:Other/></ds:Transform>` + base64T, allowExample13, xmlsec.ErrMalformed},
		"not ds:Transform":   {`<xenc:Transform Algorithm="` + xmlsec.TransformXPath + `"/>` + base64T, allowExample13, xmlsec.ErrTransformRefused},
		"XPath alone":        {good, allowExample13, xmlsec.ErrUnsupportedAlgorithm},
		"XPath after base64": {base64T + good, allowExample13, xmlsec.ErrUnsupportedAlgorithm},
		"two XPaths":         {good + good + base64T, allowExample13, xmlsec.ErrUnsupportedAlgorithm},
		"XPath Filter 2.0":   {`<ds:Transform Algorithm="` + xmlsec.TransformXPathFilter2 + `"/>` + base64T, allowExample13, xmlsec.ErrTransformRefused},
		"XSLT":               {`<ds:Transform Algorithm="` + xmlsec.TransformXSLT + `"/>` + base64T, allowExample13, xmlsec.ErrTransformRefused},
		"entry not XPath":    {xpathT(repNS, "((") + base64T, []dsig.XPathExpression{{Expr: "(("}}, xmlsec.ErrMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			opts := xenc.DecryptOptions{
				AllowedXPathExpressions: c.allow,
				ResolveURI:              func(string) ([]byte, error) { called = true; return nil, nil },
			}
			// A key of the wrong size: decryption, if reached, would fail
			// otherwise.
			for _, doc := range []string{cipherRef(uri, c.transforms), `<r><v Id="v">AAAA</v>` + cipherRef("#v", c.transforms) + `</r>`} {
				_, err := xenc.DecryptData(firstNamed(covParse(t, doc), "EncryptedData"), key[:3], opts)
				if !errors.Is(err, c.want) {
					t.Fatalf("got %v, want %v", err, c.want)
				}
			}
			if called {
				t.Fatal("ResolveURI called")
			}
		})
	}
}

// Failures after the XPath transform is accepted: the resolved octets must
// parse, the expression evaluate, and the selected text be base64.
func TestCipherReferenceXPathContent(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	const uri = "http://example.invalid/cv.xml"
	here := []dsig.XPathExpression{{Expr: "count(here()) = 1"}}
	for name, c := range map[string]struct {
		doc   string
		body  string
		allow []dsig.XPathExpression
	}{
		"not XML":         {cipherRef(uri, xpathT(repNS, example13)+base64T), "not xml", allowExample13},
		"DOCTYPE":         {cipherRef(uri, xpathT(repNS, example13)+base64T), `<!DOCTYPE r [<!ENTITY e "x">]><r>&e;</r>`, allowExample13},
		"not base64":      {cipherRef(uri, xpathT(repNS, example13)+base64T), repository("!!!!!!!!!!"), allowExample13},
		"here() external": {cipherRef(uri, xpathT(repNS, "count(here()) = 1")+base64T), `<r><a>AAAA</a><b>AAAA</b></r>`, here},
	} {
		t.Run(name, func(t *testing.T) {
			opts := xenc.DecryptOptions{
				AllowedXPathExpressions: c.allow,
				ResolveURI:              func(string) ([]byte, error) { return []byte(c.body), nil },
			}
			if _, err := xenc.DecryptData(firstNamed(covParse(t, c.doc), "EncryptedData"), key, opts); !errors.Is(err, xmlsec.ErrMalformed) {
				t.Fatalf("got %v", err)
			}
		})
	}

	// here() is the ds:XPath element, in a same-document reference.
	b64 := base64.StdEncoding.EncodeToString(sealGCM(key, "secret"))
	doc := `<r><v>` + b64 + `</v>` + cipherRef("", xpathT(repNS, "count(here()) = 1 and parent::v")+base64T) + `</r>`
	pt, err := xenc.DecryptData(firstNamed(covParse(t, doc), "EncryptedData"), key, xenc.DecryptOptions{
		AllowedXPathExpressions: []dsig.XPathExpression{{Expr: "count(here()) = 1 and parent::v"}},
	})
	if err != nil || string(pt) != "secret" {
		t.Fatalf("%s, %v", pt, err)
	}
}

// Section 3.3.1: a relative CipherReference URI is resolved against
// DecryptOptions.BaseURI, never against xml:base, and refused without it.
func TestCipherReferenceBaseURI(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	ct := sealGCM(key, "secret")
	doc := `<r xml:base="http://attacker.invalid/">` + covED(`Type="`+xenc.TypeElement+`"`, covEM(xmlsec.EncAES128GCM)+
		`<xenc:CipherData><xenc:CipherReference URI="../ct/1.bin"/></xenc:CipherData>`) + `</r>`
	var fetched []string
	resolve := func(u string) ([]byte, error) { fetched = append(fetched, u); return ct, nil }
	ed := firstNamed(covParse(t, doc), "EncryptedData")

	pt, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{ResolveURI: resolve, BaseURI: "https://example.com/msg/doc.xml"})
	if err != nil || string(pt) != "secret" || len(fetched) != 1 || fetched[0] != "https://example.com/ct/1.bin" {
		t.Fatalf("%s, %v, fetched %q", pt, err, fetched)
	}

	for name, c := range map[string]struct {
		opts xenc.DecryptOptions
		want error
	}{
		"no BaseURI":       {xenc.DecryptOptions{ResolveURI: resolve}, xmlsec.ErrMalformed},
		"no ResolveURI":    {xenc.DecryptOptions{BaseURI: "https://example.com/"}, xmlsec.ErrMalformed},
		"relative BaseURI": {xenc.DecryptOptions{ResolveURI: resolve, BaseURI: "msg/doc.xml"}, nil},
		"bad BaseURI":      {xenc.DecryptOptions{ResolveURI: resolve, BaseURI: "http://[::1"}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			fetched = nil
			_, err := xenc.DecryptData(ed, key, c.opts)
			if err == nil || c.want != nil && !errors.Is(err, c.want) || len(fetched) != 0 {
				t.Fatalf("got %v, fetched %q", err, fetched)
			}
		})
	}
}
