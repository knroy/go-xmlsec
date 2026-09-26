// Package xmltree holds the few xdm construction and reading helpers the
// security packages share. It emits no octets: serialization is c14n's.
package xmltree

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/knroy/go-xml/xdm"
)

// Element creates an element and, if parent is non-nil, appends it there.
func Element(parent *xdm.Node, prefix, uri, local string) *xdm.Node {
	e := &xdm.Node{Kind: xdm.KindElement, Name: xdm.QName{Prefix: prefix, URI: uri, Local: local}}
	if parent != nil {
		parent.AppendChild(e)
	}
	return e
}

// SetAttr sets an attribute, replacing any with the same expanded name.
func SetAttr(e *xdm.Node, prefix, uri, local, value string) {
	if a := e.Attr(uri, local); a != nil {
		a.Value = value
		return
	}
	e.AddAttr(&xdm.Node{Name: xdm.QName{Prefix: prefix, URI: uri, Local: local}, Value: value})
}

// Text appends a text node.
func Text(e *xdm.Node, s string) {
	e.AppendChild(&xdm.Node{Kind: xdm.KindText, Value: s})
}

// Declare binds prefix to uri on e unless that binding is already in scope.
// It refuses to shadow a different binding of the same prefix, which would
// change the meaning of any descendant using it.
func Declare(e *xdm.Node, prefix, uri string) error {
	if got, ok := e.LookupPrefix(prefix); ok && got != "" {
		if got == uri {
			return nil
		}
		return fmt.Errorf("prefix %q already bound to %q", prefix, got)
	}
	e.AddNamespace(prefix, uri)
	return nil
}

// DocumentElement returns the element child of n's document node.
func DocumentElement(n *xdm.Node) *xdm.Node {
	root := n.Root()
	if root.Kind == xdm.KindElement {
		return root
	}
	for _, c := range root.Children {
		if c.Kind == xdm.KindElement {
			return c
		}
	}
	return nil
}

// Walk calls f for every element in n's subtree, in document order.
func Walk(n *xdm.Node, f func(*xdm.Node)) {
	if n.Kind == xdm.KindElement {
		f(n)
	}
	for _, c := range n.Children {
		Walk(c, f)
	}
}

// Base64 decodes element content as xs:base64Binary, which permits
// whitespace between characters.
func Base64(e *xdm.Node) ([]byte, error) {
	s := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, e.StringValue())
	return base64.StdEncoding.DecodeString(s)
}

// AttrValue returns the value of the attribute with the given expanded name,
// or "".
func AttrValue(e *xdm.Node, uri, local string) string {
	if a := e.Attr(uri, local); a != nil {
		return a.Value
	}
	return ""
}
