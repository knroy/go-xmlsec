// Package xmltree holds the few xdm construction and reading helpers the
// security packages share. It emits no octets: serialization is c14n's.
package xmltree

import (
	"encoding/base64"
	"fmt"
	"io"

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
// whitespace between characters. The text is stripped of space, tab, CR
// and LF and decoded a chunk at a time, not copied whole first: wrapped
// values, as xmlsec1, WSS4J and Santuario write them, would cost a third
// more than their decoded size again.
//
// It strips octets where the strings.Map it replaced stripped runes, which
// never changes the result: no UTF-8 sequence holds an ASCII octet, and
// decoding stops at the first non-ASCII octet, whatever follows.
func Base64(e *xdm.Node) ([]byte, error) { return DecodeBase64(e.StringValue()) }

// DecodeBase64 is Base64 for the concatenation of parts, which it never
// makes: the parts are read in place, twice, to size the result and to
// decode into it.
func DecodeBase64[T string | []byte](parts ...T) ([]byte, error) {
	space := func(c byte) bool { return c <= ' ' && (c == ' ' || c == '\t' || c == '\r' || c == '\n') }
	n := 0
	for _, s := range parts {
		n += len(s)
		for i := range len(s) {
			if space(s[i]) {
				n--
			}
		}
	}
	enc := base64.StdEncoding
	dst := make([]byte, enc.DecodedLen(n))
	var buf [4096]byte
	chunk, at, w := buf[:0], 0, 0
	// decode decodes chunk, at octet at of the stripped text, which it ends
	// unless more follows. Chunks are whole quanta, so Decode treats each as
	// it would within the whole text, except that padding ending a chunk
	// with text after it is trailing garbage there.
	decode := func(more bool) error {
		k, err := enc.Decode(dst[w:], chunk)
		w += k
		if err == nil && more && chunk[len(chunk)-1] == '=' {
			err = base64.CorruptInputError(len(chunk))
		}
		if err != nil {
			err = err.(base64.CorruptInputError) + base64.CorruptInputError(at)
		}
		at += len(chunk)
		chunk = chunk[:0]
		return err
	}
	for _, s := range parts {
		for len(s) > 0 {
			k := 0
			for k < len(s) && !space(s[k]) {
				k++
			}
			for run := s[:k]; len(run) > 0; {
				if len(chunk) == cap(chunk) {
					if err := decode(true); err != nil {
						return dst[:w], err
					}
				}
				m := copy(buf[len(chunk):], run)
				chunk, run = buf[:len(chunk)+m], run[m:]
			}
			s = s[min(k+1, len(s)):]
		}
	}
	err := decode(false)
	return dst[:w], err
}

// AttrValue returns the value of the attribute with the given expanded name,
// or "".
func AttrValue(e *xdm.Node, uri, local string) string {
	if a := e.Attr(uri, local); a != nil {
		return a.Value()
	}
	return ""
}

// Parse parses the octets r holds as xmlsec.Parse parses a slice of them,
// with the same pinned options and errors. Package xmlsec sets it, so that
// a document assembled from pieces is parsed without being copied whole.
var Parse func(r io.Reader) (*xdm.Tree, error)

// ParseOptions are the pinned options Parse parses with, for a parse go-xml
// makes itself. Package xmlsec sets it.
var ParseOptions func() xdm.ParseOptions

// Clone returns a detached deep copy of n: its attributes, namespace
// declarations and descendants.
func Clone(n *xdm.Node) *xdm.Node { return xdm.Copy(n) }
