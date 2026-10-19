package xmltree

import (
	"errors"

	"github.com/knroy/go-xml/v2/xdm"
)

// Edits are the changes Rebuild makes while it copies a tree. Every key is a
// node of the tree being copied; the nodes in the values may come from any
// tree, and are copied.
type Edits struct {
	// Attrs sets attributes on an element, each replacing the value of one
	// with the same expanded name or else added after the element's own.
	Attrs map[*xdm.Node][]Attr

	// Namespaces declares prefixes on an element.
	Namespaces map[*xdm.Node][]Binding

	// Before inserts nodes ahead of a node, and Append after the last child
	// of an element or document node.
	Before map[*xdm.Node][]*xdm.Node
	Append map[*xdm.Node][]*xdm.Node

	// Replace puts nodes in the place of a node and its subtree, which is
	// left out of the copy. An empty list removes it.
	Replace map[*xdm.Node][]*xdm.Node
}

// Attr is an attribute Edits sets.
type Attr struct {
	Name  xdm.QName
	Value string
}

// Binding is a namespace declaration Edits adds.
type Binding struct{ Prefix, URI string }

// SetAttr records an attribute to set on el.
func (e *Edits) SetAttr(el *xdm.Node, name xdm.QName, value string) {
	if e.Attrs == nil {
		e.Attrs = map[*xdm.Node][]Attr{}
	}
	e.Attrs[el] = append(e.Attrs[el], Attr{name, value})
}

// Declare records a namespace declaration on el.
func (e *Edits) Declare(el *xdm.Node, prefix, uri string) {
	if e.Namespaces == nil {
		e.Namespaces = map[*xdm.Node][]Binding{}
	}
	e.Namespaces[el] = append(e.Namespaces[el], Binding{prefix, uri})
}

// Insert records nodes to become the children of parent from position i,
// counting every kind of child; i equal to the number of children appends.
func (e *Edits) Insert(parent *xdm.Node, i int, nodes ...*xdm.Node) {
	if i < parent.NumChildren() {
		c := parent.ChildAt(i)
		if e.Before == nil {
			e.Before = map[*xdm.Node][]*xdm.Node{}
		}
		e.Before[c] = append(e.Before[c], nodes...)
		return
	}
	if e.Append == nil {
		e.Append = map[*xdm.Node][]*xdm.Node{}
	}
	e.Append[parent] = append(e.Append[parent], nodes...)
}

// ReplaceNode records nodes to take n's place.
func (e *Edits) ReplaceNode(n *xdm.Node, nodes ...*xdm.Node) {
	if e.Replace == nil {
		e.Replace = map[*xdm.Node][]*xdm.Node{}
	}
	e.Replace[n] = nodes
}

// Rebuild copies the tree n belongs to, from its root, applying e, and
// returns the copy's root and a map from each node copied, inserted nodes
// included, to its copy. A node e replaces has no entry. The source is left
// as it was: a parsed document cannot be changed, so a changed document is
// always a new one.
func Rebuild(n *xdm.Node, e *Edits) (*xdm.Node, map[*xdm.Node]*xdm.Node) {
	if e == nil {
		e = &Edits{}
	}
	src := n.Root()
	r := rebuild{e: e, m: map[*xdm.Node]*xdm.Node{}}
	var root *xdm.Node
	if src.Kind() == xdm.KindDocument {
		t := xdm.NewTree()
		root = t.Root
		root.SetBaseURI(src.BaseURI())
		root.SetDocumentURI(src.DocumentURI())
		if st := src.Tree(); st != nil {
			t.DocType, t.XMLVersion = st.DocType, st.XMLVersion
		}
	} else {
		root = xdm.ShallowCopy(src)
	}
	r.m[src] = root
	r.fill(root, src)
	if t := root.Tree(); t != nil {
		t.Finalize()
	}
	return root, r.m
}

type rebuild struct {
	e *Edits
	m map[*xdm.Node]*xdm.Node
}

// copy appends a copy of src, a child of the node being copied or a node
// inserted there, to dst.
func (r *rebuild) copy(dst, src *xdm.Node) {
	c := dst.AppendShallowCopy(src)
	r.m[src] = c
	r.fill(c, src)
}

// fill completes c, the shallow copy of src: namespace declarations,
// attributes and children, with the edits keyed on src and its children.
func (r *rebuild) fill(c, src *xdm.Node) {
	if k := src.Kind(); k != xdm.KindElement && k != xdm.KindDocument {
		return
	}
	for prefix, uri := range src.DeclaredNamespaces() {
		c.AddNamespace(prefix, uri)
	}
	for _, b := range r.e.Namespaces[src] {
		c.AddNamespace(b.Prefix, b.URI)
	}
	set := r.e.Attrs[src]
	done := make([]bool, len(set))
	for a := range src.Attrs() {
		ca := c.AppendShallowCopy(a)
		r.m[a] = ca
		for i, s := range set {
			if s.Name.Equal(a.Name()) {
				ca.SetValue(s.Value)
				done[i] = true
			}
		}
	}
	for i, s := range set {
		if !done[i] {
			c.AppendAttr(s.Name, s.Value)
		}
	}
	for ch := range src.Children() {
		r.place(c, r.e.Before[ch]...)
		if rep, ok := r.e.Replace[ch]; ok {
			r.place(c, rep...)
			continue
		}
		r.copy(c, ch)
	}
	r.place(c, r.e.Append[src]...)
}

// place copies nodes into dst, an attribute as an attribute.
func (r *rebuild) place(dst *xdm.Node, nodes ...*xdm.Node) {
	for _, n := range nodes {
		r.copy(dst, n)
	}
}

// Doc is a document that changes by being rebuilt: each Apply makes a new
// tree, and Node maps a node of any earlier one to its counterpart.
type Doc struct {
	root  *xdm.Node
	steps []map[*xdm.Node]*xdm.Node
}

// DocOf returns the Doc an *xmlsec.Document holds, or nil for anything else.
// Package xmlsec sets it, which keeps Apply out of the Document's API.
var DocOf func(doc any) *Doc

// NewDoc starts a Doc at the tree n belongs to.
func NewDoc(n *xdm.Node) *Doc { return &Doc{root: n.Root()} }

// Root returns the root of the current tree.
func (d *Doc) Root() *xdm.Node { return d.root }

// Node returns n's counterpart in the current tree: n itself if it is
// there, or nil if an edit removed it or n was never part of d.
func (d *Doc) Node(n *xdm.Node) *xdm.Node {
	if n == nil {
		return nil
	}
	for _, m := range d.steps {
		if c, ok := m[n]; ok {
			n = c
		}
	}
	if n.Root() != d.root {
		return nil
	}
	return n
}

// errForeign reports a node an edit names that is not in the document.
var errForeign = errors.New("node is not in the document")

// Apply rebuilds the current tree with e, whose keys may be nodes of any
// earlier tree, and makes the result current. The returned map takes each
// node of the previous tree, and each node e inserted, to its copy.
func (d *Doc) Apply(e *Edits) (map[*xdm.Node]*xdm.Node, error) {
	root, m, err := d.Prepare(e)
	if err != nil {
		return nil, err
	}
	d.Commit(root, m)
	return m, nil
}

// Commit makes root, which Prepare returned with m, the current tree.
func (d *Doc) Commit(root *xdm.Node, m map[*xdm.Node]*xdm.Node) {
	d.root = root
	d.steps = append(d.steps, m)
}

// Prepare is Apply without making the result current, for a caller that
// finishes its work on the new tree before committing it.
func (d *Doc) Prepare(e *Edits) (*xdm.Node, map[*xdm.Node]*xdm.Node, error) {
	cur := Edits{}
	var err error
	key := func(n *xdm.Node) *xdm.Node {
		c := d.Node(n)
		if c == nil {
			err = errForeign
		}
		return c
	}
	cur.Attrs = rekey(e.Attrs, key)
	cur.Namespaces = rekey(e.Namespaces, key)
	cur.Before = rekey(e.Before, key)
	cur.Append = rekey(e.Append, key)
	cur.Replace = rekey(e.Replace, key)
	if err != nil {
		return nil, nil, err
	}
	root, m := Rebuild(d.root, &cur)
	return root, m, nil
}

func rekey[V any](in map[*xdm.Node]V, key func(*xdm.Node) *xdm.Node) map[*xdm.Node]V {
	if in == nil {
		return nil
	}
	out := make(map[*xdm.Node]V, len(in))
	for k, v := range in {
		out[key(k)] = v
	}
	return out
}
