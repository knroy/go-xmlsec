// Package xmltree holds the few xdm construction and reading helpers the
// security packages share. It emits no octets: serialization is c14n's.
package xmltree

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/knroy/go-xml/v2/xdm"
)

// Element creates an element and, if parent is non-nil, appends it there.
// Trees are built top-down: parent must still be open, and the element's
// attributes go on before its children.
func Element(parent *xdm.Node, prefix, uri, local string) *xdm.Node {
	name := xdm.QName{Prefix: prefix, URI: uri, Local: local}
	if parent == nil {
		return xdm.NewNode(xdm.KindElement, name, "")
	}
	return parent.AppendElement(name)
}

// SetAttr sets an attribute, replacing any with the same expanded name. A
// new one must come before e's first child.
func SetAttr(e *xdm.Node, prefix, uri, local, value string) {
	if a := e.Attr(uri, local); a != nil {
		a.SetValue(value)
		return
	}
	e.AppendAttr(xdm.QName{Prefix: prefix, URI: uri, Local: local}, value)
}

// Text appends a text node.
func Text(e *xdm.Node, s string) {
	e.AppendText(s)
}

// Declare binds prefix to uri on e unless that binding is already in scope.
// It refuses to shadow a different binding of the same prefix, which would
// change the meaning of any descendant using it.
func Declare(e *xdm.Node, prefix, uri string) error {
	need, err := NeedsDeclaration(e, prefix, uri)
	if need {
		e.AddNamespace(prefix, uri)
	}
	return err
}

// NeedsDeclaration reports whether binding prefix to uri on e takes a
// declaration, which is when prefix is not in scope there. A different
// binding of prefix in scope is an error, as for Declare.
func NeedsDeclaration(e *xdm.Node, prefix, uri string) (bool, error) {
	if got, ok := e.LookupPrefix(prefix); ok && got != "" {
		if got == uri {
			return false, nil
		}
		return false, fmt.Errorf("prefix %q already bound to %q", prefix, got)
	}
	return true, nil
}

// DocumentElement returns the element child of n's document node, or nil.
func DocumentElement(n *xdm.Node) *xdm.Node {
	if n == nil {
		return nil
	}
	root := n.Root()
	if root.Kind() == xdm.KindElement {
		return root
	}
	for c := range root.Children() {
		if c.Kind() == xdm.KindElement {
			return c
		}
	}
	return nil
}

// Walk calls f for every element in n's subtree, in document order.
func Walk(n *xdm.Node, f func(*xdm.Node)) {
	if n.Kind() == xdm.KindElement {
		f(n)
	}
	for c := range n.Children() {
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
		return a.Value()
	}
	return ""
}

// Clone returns a detached deep copy of n: its attributes, namespace
// declarations and descendants.
func Clone(n *xdm.Node) *xdm.Node { return xdm.Copy(n) }
