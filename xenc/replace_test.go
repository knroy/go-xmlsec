package xenc_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

func canonical(t *testing.T, n *xdm.Node) string {
	t.Helper()
	b, err := c14n.Bytes(n.Root(), c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Sections 4.1 and 4.5: decrypting and replacing restores the document
// that was encrypted, for an element, content, and the document element.
func TestDecryptAndReplaceRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	opts := xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM}
	const src = `<!--head--><Document xmlns="http://example.org/" xmlns:p="urn:p&amp;q"><p:a x="1">text<b/><!--c--></p:a>` +
		`<ToBeEncrypted xmlns="" a="1"><c/></ToBeEncrypted><s>mixed <i>content</i> <?pi x?></s></Document>`
	for name, c := range map[string]struct {
		target  func(doc *xdm.Node) *xdm.Node
		content bool
	}{
		"element":                {func(d *xdm.Node) *xdm.Node { return d.ChildElements()[0] }, false},
		"xmlns undeclared":       {func(d *xdm.Node) *xdm.Node { return d.ChildElements()[1] }, false},
		"content":                {func(d *xdm.Node) *xdm.Node { return d.ChildElements()[2] }, true},
		"empty content":          {func(d *xdm.Node) *xdm.Node { return firstNamed(d, "b") }, true},
		"document element":       {func(d *xdm.Node) *xdm.Node { return d }, false},
		"content, no default ns": {func(d *xdm.Node) *xdm.Node { return d.ChildElements()[1] }, true},
	} {
		t.Run(name, func(t *testing.T) {
			doc := covParse(t, src)
			want := canonical(t, doc)
			encrypt := xenc.EncryptElement
			if c.content {
				encrypt = xenc.EncryptContent
			}
			out, err := encrypt(doc, c.target(doc), key, opts)
			if err != nil {
				t.Fatal(err)
			}
			enc := covParse(t, string(out))
			ed := firstNamed(enc, "EncryptedData")
			got, err := xenc.DecryptAndReplace(enc, ed, key, xenc.DecryptOptions{})
			if err != nil || string(got) != want {
				t.Fatalf("%v\n got %s\nwant %s", err, got, want)
			}
			if canonical(t, enc) != string(out) {
				t.Fatal("the encrypted document was modified")
			}
		})
	}
}

func TestDecryptAndReplaceRefused(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	ed := func(typ, plaintext string) string {
		return covED(`Type="`+typ+`"`, covEM(xmlsec.EncAES128GCM)+`<xenc:CipherData><xenc:CipherValue>`+
			base64.StdEncoding.EncodeToString(sealGCM(key, plaintext))+`</xenc:CipherValue></xenc:CipherData>`)
	}
	for name, c := range map[string]struct {
		doc  string
		want error
	}{
		"two elements":            {`<r>` + ed(xenc.TypeElement, `<a/><b/>`) + `</r>`, xmlsec.ErrMalformed},
		"text for an element":     {`<r>` + ed(xenc.TypeElement, `text`) + `</r>`, xmlsec.ErrMalformed},
		"nothing for an element":  {`<r>` + ed(xenc.TypeElement, ``) + `</r>`, xmlsec.ErrMalformed},
		"root content not single": {ed(xenc.TypeContent, `t<a/>`), xmlsec.ErrMalformed},
		"not well-formed":         {`<r>` + ed(xenc.TypeContent, `<a>`) + `</r>`, xmlsec.ErrMalformed},
		"closes the wrapper":      {`<r>` + ed(xenc.TypeContent, `</w><w>`) + `</r>`, xmlsec.ErrMalformed},
		"DOCTYPE":                 {`<r>` + ed(xenc.TypeElement, `<!DOCTYPE a><a/>`) + `</r>`, xmlsec.ErrMalformed},
		"undeclared prefix":       {`<r>` + ed(xenc.TypeElement, `<q:a/>`) + `</r>`, xmlsec.ErrMalformed},
		"octets Type":             {`<r>` + ed("urn:octets", `<a/>`) + `</r>`, xmlsec.ErrUnsupportedAlgorithm},
		"no Type":                 {`<r>` + ed("", `<a/>`) + `</r>`, xmlsec.ErrUnsupportedAlgorithm},
		"not allowed":             {`<r>` + covED(`Type="`+xenc.TypeElement+`"`, covEM(xmlsec.EncAES128CBC)) + `</r>`, xmlsec.ErrAlgorithmNotAllowed},
	} {
		t.Run(name, func(t *testing.T) {
			doc := covParse(t, c.doc)
			if out, err := xenc.DecryptAndReplace(doc, firstNamed(doc, "EncryptedData"), key, xenc.DecryptOptions{}); !errors.Is(err, c.want) || out != nil {
				t.Fatalf("got %s, %v; want %v", out, err, c.want)
			}
		})
	}

	// Content at the document element's place is fine as one element, and
	// the prefixes in scope are those of the document: none.
	doc := covParse(t, ed(xenc.TypeContent, `<a/>`))
	if out, err := xenc.DecryptAndReplace(doc, doc, key, xenc.DecryptOptions{}); err != nil || string(out) != `<a></a>` {
		t.Fatalf("%s, %v", out, err)
	}
	// Not inside doc, and the wrong key.
	other := covParse(t, `<o/>`)
	if _, err := xenc.DecryptAndReplace(other, doc, key, xenc.DecryptOptions{}); err == nil {
		t.Fatal("EncryptedData outside doc accepted")
	}
	if _, err := xenc.DecryptAndReplace(doc, doc, bytes.Repeat([]byte{8}, 16), xenc.DecryptOptions{}); err == nil {
		t.Fatal("wrong key accepted")
	}
}
