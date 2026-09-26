// Package xpathfilter holds the allow-listed XPath 1.0 expression handling
// that dsig's XPath transforms and xenc's CipherReference share: matching a
// received expression against a caller's entry, and compiling the entry,
// never the received text.
package xpathfilter

import (
	"fmt"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xml/xpath"
	"github.com/knroy/go-xmlsec"
)

// Allowed reports whether the XPath element x carries expr: the same text
// once surrounding whitespace is trimmed from both, with each prefix of ns
// bound to the same URI in x's scope.
func Allowed(x *xdm.Node, expr string, ns map[string]string) bool {
	if strings.TrimSpace(expr) != strings.TrimSpace(x.StringValue()) {
		return false
	}
	for p, u := range ns {
		if v, ok := x.LookupPrefix(p); !ok || v != u {
			return false
		}
	}
	return true
}

// prefixMap resolves an expression's prefixes from its bindings alone.
type prefixMap map[string]string

func (m prefixMap) ResolvePrefix(p string) (string, bool) {
	if p == "xml" {
		return xdm.NSXML, true
	}
	u, ok := m[p]
	return u, ok
}
func (prefixMap) DefaultElementNamespace() string  { return "" }
func (prefixMap) DefaultFunctionNamespace() string { return xdm.NSFN }

// Compile compiles an XML-DSig expression, which is XPath 1.0, with the
// bindings ns alone, under XPath 1.0 compatibility mode.
func Compile(expr string, ns map[string]string) (*xpath.Compiled, error) {
	c, err := xpath.CompileWith(strings.TrimSpace(expr), xpath.CompileOptions{Namespaces: prefixMap(ns)})
	if err != nil {
		return nil, fmt.Errorf("%w: XPath %q: %v", xmlsec.ErrMalformed, expr, err)
	}
	return c.WithCompatMode(true), nil
}

// Library is the XPath 1.0 core function library plus XML-DSig's here()
// (6.6.3.1): the element bearing the expression, which must be in the
// document being evaluated.
func Library(here, doc *xdm.Node) xpath.FunctionLibrary {
	lib := xpath.NewLibrary(xpath.Builtins())
	lib.Add(xpath.Function{Name: xdm.QName{URI: xdm.NSFN, Local: "here"}, Call: func(*xpath.Context, []xdm.Sequence) (xdm.Sequence, error) {
		if here.Root() != doc {
			return nil, fmt.Errorf("%w: here() outside the document the expression is evaluated against", xmlsec.ErrMalformed)
		}
		return xdm.Sequence{here}, nil
	}})
	return lib
}
