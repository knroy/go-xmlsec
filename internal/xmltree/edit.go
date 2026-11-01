package xmltree

import (
	"errors"
	"weak"

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
// returns the copy's root and where each node copied, inserted nodes
// included, went. A node e replaces has no copy. The source is left as it
// was: a parsed document cannot be changed, so a changed document is always
// a new one.
func Rebuild(n *xdm.Node, e *Edits) (*xdm.Node, *Copies) {
	c := &Copies{}
	c.root = rebuildTree(n, e, c)
	return c.root, c
}

// RebuildTree is Rebuild without the copies, for a caller that needs only
// the new tree.
func RebuildTree(n *xdm.Node, e *Edits) *xdm.Node { return rebuildTree(n, e, nil) }

// rebuildTree is Rebuild, recording runs in c when it is not nil.
func rebuildTree(n *xdm.Node, e *Edits, c *Copies) *xdm.Node {
	if e == nil {
		e = &Edits{}
	}
	src := n.Root()
	r := rebuild{e: e, c: c, from: src}
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
	r.note(src, root)
	r.fill(root, src)
	if t := root.Tree(); t != nil {
		t.Finalize()
	}
	if c != nil {
		c.runs = make([]run, len(r.runs))
		for i, b := range r.runs {
			c.runs[i] = run{weak.Make(b.from), b.start, b.n, b.at}
		}
	}
	return root
}

// Copies says where Rebuild put the nodes it copied, as runs of
// consecutive positions (Node.Index) in a source and in the copy. A tree
// is copied in document order, so a run breaks only where an edit adds,
// removes or inserts something: a handful of runs describe a tree of any
// size, where a map from each node to its copy would cost more than the
// tree.
type Copies struct {
	root *xdm.Node
	runs []run
}

// run is n nodes from position start of the tree whose root is src,
// copied to position at of the copy and on. src is weak, so that the
// record pins no source tree: two weak pointers are equal when the
// pointers they were made from are, even after the tree is gone.
type run struct {
	src          weak.Pointer[xdm.Node]
	start, n, at int
}

// Of returns n's copy, or nil if Rebuild did not copy it.
func (c *Copies) Of(n *xdm.Node) *xdm.Node {
	if i, ok := find(c.runs, weak.Make(n.Root()), n.Index()); ok {
		return nodeAt(c.root, i)
	}
	return nil
}

// find returns where the node at position i of the tree whose root is src
// was copied to. The last run wins, as the last copy of a node inserted
// twice is what a map from each node to its copy would hold.
func find(runs []run, src weak.Pointer[xdm.Node], i int) (int, bool) {
	for k := len(runs) - 1; k >= 0; k-- {
		if r := runs[k]; r.src == src && i >= r.start && i < r.start+r.n {
			return r.at + i - r.start, true
		}
	}
	return 0, false
}

// nodeAt returns the node at position i of the tree root is the root of:
// by Tree.NodeAt for a document, and for a fragment, which has no Tree,
// by descending to the child whose subtree holds i.
func nodeAt(root *xdm.Node, i int) *xdm.Node {
	if t := root.Tree(); t != nil {
		return t.NodeAt(i)
	}
	n := root
	for n.Index() != i {
		for a := range n.Attrs() {
			if a.Index() == i {
				return a
			}
		}
		for c := range n.Children() {
			if i < c.SubtreeEnd() {
				n = c
				break
			}
		}
	}
	return n
}

type rebuild struct {
	e    *Edits
	c    *Copies
	from *xdm.Node // the root of the tree being copied from
	runs []strongRun
}

// strongRun is a run while Rebuild records it.
type strongRun struct {
	from         *xdm.Node
	start, n, at int
}

// note records that c is the copy of src, extending the last run when both
// follow on from it.
func (r *rebuild) note(src, c *xdm.Node) {
	if r.c == nil {
		return
	}
	i, j := src.Index(), c.Index()
	if k := len(r.runs) - 1; k >= 0 {
		if l := &r.runs[k]; l.from == r.from && l.start+l.n == i && l.at+l.n == j {
			l.n++
			return
		}
	}
	r.runs = append(r.runs, strongRun{r.from, i, 1, j})
}

// copy appends a copy of src, a child of the node being copied or a node
// inserted there, to dst.
func (r *rebuild) copy(dst, src *xdm.Node) {
	c := dst.AppendShallowCopy(src)
	r.note(src, c)
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
		r.note(a, ca)
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
	from := r.from
	for _, n := range nodes {
		r.from = n.Root()
		r.copy(dst, n)
	}
	r.from = from
}

// Doc is a document that changes by being rebuilt: each Apply makes a new
// tree, and Node maps a node of any earlier one to its counterpart. It
// keeps each change's runs, not its trees: a node of an earlier tree is
// found by position, change by change, and only the current tree is held.
type Doc struct {
	root  *xdm.Node
	steps []step
}

// step is one change: the runs from the tree before it, and from the nodes
// it inserted, to the tree it made, whose root is to.
type step struct {
	runs []run
	to   weak.Pointer[xdm.Node]
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
	src, i, moved := weak.Make(n.Root()), n.Index(), false
	for _, s := range d.steps {
		if j, ok := find(s.runs, src, i); ok {
			src, i, moved = s.to, j, true
		}
	}
	switch {
	case !moved && n.Root() == d.root:
		return n
	case moved && src == d.steps[len(d.steps)-1].to:
		return nodeAt(d.root, i)
	}
	return nil
}

// errForeign reports a node an edit names that is not in the document.
var errForeign = errors.New("node is not in the document")

// Apply rebuilds the current tree with e, whose keys may be nodes of any
// earlier tree, and makes the result current. The returned Copies take each
// node of the previous tree, and each node e inserted, to its copy.
func (d *Doc) Apply(e *Edits) (*Copies, error) {
	root, m, err := d.Prepare(e)
	if err != nil {
		return nil, err
	}
	d.Commit(root, m)
	return m, nil
}

// Commit makes root, which Prepare or Rebuild returned with c, the current
// tree.
func (d *Doc) Commit(root *xdm.Node, c *Copies) {
	d.root = root
	d.steps = append(d.steps, step{c.runs, weak.Make(root)})
}

// Prepare is Apply without making the result current, for a caller that
// finishes its work on the new tree before committing it.
func (d *Doc) Prepare(e *Edits) (*xdm.Node, *Copies, error) {
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
