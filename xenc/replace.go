package xenc

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
)

// DecryptAndReplace decrypts ed, an xenc:EncryptedData of Type Element or
// Content inside doc, as DecryptData does with opts, and returns doc's
// octets with the plaintext in place of ed (sections 4.1 and 4.5), in
// canonical form (Inclusive10WithComments). doc itself is left unmodified.
//
// The plaintext is parsed with xmlsec.Parse, so under its limits and with
// no DOCTYPE, as the content of an element declaring every namespace in
// scope at ed's parent: that is the context XML Encryption serializes it
// for (section 4.5), so an element without a namespace prefix lands in its
// parent's default namespace, and one carrying xmlns="", as EncryptElement
// writes it, stays out of it. For Type Element the plaintext must be one
// element; for Type Content its nodes, of any kind, take ed's place. When
// ed is the document element the result must be one element either way,
// the new document element. Anything else is xmlsec.ErrDecryptionFailed,
// the error a wrong key gives, with no detail, as DecryptHeader reports
// it: with a legacy CBC algorithm, telling the two apart is a padding
// oracle. Any other Type is xmlsec.ErrUnsupportedAlgorithm, refused before
// decryption.
func DecryptAndReplace(doc, ed *xdm.Node, key []byte, opts DecryptOptions) ([]byte, error) {
	if err := checkTarget(doc, ed); err != nil {
		return nil, err
	}
	typ := ed.AttrValue("Type")
	if typ != TypeElement && typ != TypeContent {
		return nil, unsupported("EncryptedData Type %q: DecryptAndReplace replaces Element and Content", typ)
	}
	pt, err := DecryptData(ed, key, opts)
	if err != nil {
		return nil, err
	}
	// A plaintext of the wrong shape is a decryption failure like a wrong
	// key: with CBC data, which of the two it was is a padding oracle.
	size := len(pt)
	nodes, err := parseIn(pt, ed.Parent())
	clear(pt)
	if err != nil {
		return nil, errDecrypt
	}
	if (typ == TypeElement || ed.Parent().Kind() == xdm.KindDocument) && (len(nodes) != 1 || nodes[0].Kind() != xdm.KindElement) {
		return nil, errDecrypt
	}
	if ed.Parent().Kind() != xdm.KindDocument {
		if out, ok := splice(doc, ed, nodes, size); ok {
			return out, nil
		}
	}
	var e xmltree.Edits
	e.ReplaceNode(ed, nodes...)
	return emit(doc, &e)
}

// attrEscaper escapes a namespace URI for a double-quoted attribute.
var attrEscaper = strings.NewReplacer(`&`, "&amp;", `<`, "&lt;", `"`, "&quot;", "\t", "&#9;", "\n", "&#10;", "\r", "&#13;")

// parseIn parses plaintext as the content of an element that declares the
// namespaces in scope at parent, and returns the resulting nodes. With
// outer, that element is inside one declaring the namespaces in scope at
// outer: nested as the plaintext will be in the output, for splice to
// render it against outer's.
func parseIn(plaintext []byte, parent *xdm.Node, outer ...*xdm.Node) ([]*xdm.Node, error) {
	var start bytes.Buffer
	for _, n := range append(outer, parent) {
		start.WriteString("<w")
		ns := n.InScopeNamespaces()
		if _, ok := ns[""]; !ok && len(outer) > 0 {
			// An undeclared default is absent from the map; inside an outer
			// wrapper that binds one, it must be undeclared again.
			ns[""] = ""
		}
		for _, p := range slices.Sorted(maps.Keys(ns)) {
			switch p {
			case "xml":
			case "":
				fmt.Fprintf(&start, ` xmlns="%s"`, attrEscaper.Replace(ns[p]))
			default:
				fmt.Fprintf(&start, ` xmlns:%s="%s"`, p, attrEscaper.Replace(ns[p]))
			}
		}
		start.WriteByte('>')
	}
	end := strings.Repeat("</w>", len(outer)+1)
	tree, err := xmltree.Parse(io.MultiReader(&start, bytes.NewReader(plaintext), strings.NewReader(end)))
	if err != nil {
		return nil, fmt.Errorf("%w: parsing the decrypted octets: %w", xmlsec.ErrMalformed, err)
	}
	// The plaintext cannot close the wrapper and leave one document
	// element: w is the only child, and holds only the inner w.
	w := tree.Root.FirstChild()
	if len(outer) > 0 {
		if w.NumChildren() != 1 {
			return nil, fmt.Errorf("%w: the decrypted octets close their context", xmlsec.ErrMalformed)
		}
		w = w.FirstChild()
	}
	return slices.Collect(w.Children()), nil
}

// splice returns doc's canonical octets with nodes, the content parseIn
// made of a plaintext of size octets, in place of old, as emit would
// return them, rendering the content straight into the output: the
// document is rebuilt without it, with a random comment at its place,
// and the content canonicalized on its own, under the wrapper whose
// namespaces are those in scope at old's parent. With an inner wrapper,
// as DecryptHeader parses, the inner one is left out of the rendering.
// ok is false when the output could differ from emit's: the comment is
// not found exactly once, or a canonicalization fails, or the content is
// deep enough that emit's might fail where these succeed. The caller then
// emits as before.
func splice(doc, old *xdm.Node, nodes []*xdm.Node, size int) (out []byte, ok bool) {
	depth := 0
	for p := old.Parent(); p.Kind() == xdm.KindElement; p = p.Parent() {
		depth++
	}
	for _, n := range nodes {
		if depth+elementDepth(n)+2 > xmlsec.MaxC14NDepth {
			return nil, false
		}
	}
	mark := []byte("<!--" + randomID() + "-->")
	var e xmltree.Edits
	e.ReplaceNode(old, xdm.NewNode(xdm.KindComment, xdm.QName{}, string(mark[4:len(mark)-3])))
	b, err := emit(doc, &e)
	if err != nil || bytes.Count(b, mark) != 1 {
		return nil, false
	}
	i := bytes.Index(b, mark)
	var w spliceWriter
	w.buf = append(make([]byte, 0, len(b)-len(mark)+size+size/8), b[:i]...)
	if len(nodes) > 0 {
		root := nodes[0].Root()
		set := c14n.Subtree(root)
		if inner := nodes[0].Parent(); inner.Parent().Kind() != xdm.KindDocument {
			set = c14n.Func(root, func(n *xdm.Node) bool { return n != inner })
		}
		if err := c14n.WriteNodeSet(&w, set, c14n.Options{Algorithm: c14n.Inclusive10WithComments}); err != nil {
			return nil, false
		}
		w.buf = w.buf[:len(w.buf)-len("</w>")]
	}
	return append(w.buf, b[i+len(mark):]...), true
}

// spliceWriter appends what is written to it to buf, but for the start
// tag it begins with: the wrapper's, whose end tag the caller trims. In
// canonical form an attribute value is in double quotes, and holds none.
type spliceWriter struct {
	buf          []byte
	body, quoted bool
}

func (s *spliceWriter) Write(p []byte) (int, error) {
	n := len(p)
	for ; !s.body && len(p) > 0; p = p[1:] {
		switch p[0] {
		case '"':
			s.quoted = !s.quoted
		case '>':
			s.body = !s.quoted
		}
	}
	s.buf = append(s.buf, p...)
	return n, nil
}

// elementDepth is the depth of the deepest element in n's subtree, n's own
// level being 1, or 0 when n is not an element.
func elementDepth(n *xdm.Node) int {
	if n.Kind() != xdm.KindElement {
		return 0
	}
	d := 0
	for c := range n.Children() {
		d = max(d, elementDepth(c))
	}
	return d + 1
}
