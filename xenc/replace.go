package xenc

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
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
// the new document element. Anything else is xmlsec.ErrMalformed, and any
// other Type xmlsec.ErrUnsupportedAlgorithm, refused before decryption.
//
// With a legacy CBC algorithm the parse happens after decryption like any
// use of the plaintext, and a parse error is observable: see DecryptData.
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
	nodes, err := parseIn(pt, ed.Parent)
	if err != nil {
		return nil, err
	}
	if (typ == TypeElement || ed.Parent.Kind == xdm.KindDocument) && (len(nodes) != 1 || nodes[0].Kind != xdm.KindElement) {
		return nil, malformed("the decrypted %s is not a single element", ed.Name.Local)
	}
	kids := slices.Clone(ed.Parent.Children)
	i := slices.Index(kids, ed)
	return emitWith(doc, ed.Parent, slices.Replace(kids, i, i+1, nodes...), nodes...)
}

// attrEscaper escapes a namespace URI for a double-quoted attribute.
var attrEscaper = strings.NewReplacer(`&`, "&amp;", `<`, "&lt;", `"`, "&quot;", "\t", "&#9;", "\n", "&#10;", "\r", "&#13;")

// parseIn parses plaintext as the content of an element that declares the
// namespaces in scope at parent, and returns the resulting nodes.
func parseIn(plaintext []byte, parent *xdm.Node) ([]*xdm.Node, error) {
	var b bytes.Buffer
	b.WriteString("<w")
	ns := parent.InScopeNamespaces()
	for _, p := range slices.Sorted(maps.Keys(ns)) {
		switch p {
		case "xml":
		case "":
			fmt.Fprintf(&b, ` xmlns="%s"`, attrEscaper.Replace(ns[p]))
		default:
			fmt.Fprintf(&b, ` xmlns:%s="%s"`, p, attrEscaper.Replace(ns[p]))
		}
	}
	b.WriteByte('>')
	b.Write(plaintext)
	b.WriteString("</w>")
	tree, err := xmlsec.Parse(b.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%w: parsing the decrypted octets: %w", xmlsec.ErrMalformed, err)
	}
	// The plaintext cannot close the wrapper and leave one document
	// element: w is the only child.
	return tree.Root.Children[0].Children, nil
}
