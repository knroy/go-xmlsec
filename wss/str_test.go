package wss

import (
	"errors"
	"testing"

	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

func TestNewSecurityTokenReference(t *testing.T) {
	if _, err := NewSecurityTokenReference(nil, "", ""); err == nil {
		t.Fatal("empty token ID accepted")
	}
	str, err := NewSecurityTokenReference(nil, "tok", "")
	if err != nil {
		t.Fatal(err)
	}
	ref := str.ChildElements()[0]
	if ref.AttrValue("URI") != "#tok" || ref.Attr("", "ValueType") != nil {
		t.Fatalf("reference URI %q, ValueType present %v", ref.AttrValue("URI"), ref.Attr("", "ValueType") != nil)
	}
}

func TestResolveSecurityTokenReferenceErrors(t *testing.T) {
	str := func(inner string) string {
		return `<soap:Envelope xmlns:soap="` + NSSOAP11 + `" xmlns:wsse="` + NSWSSE + `" xmlns:wsu="` + NSWSU + `">` +
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
