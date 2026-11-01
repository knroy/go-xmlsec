package xmltree

import (
	"errors"
	"testing"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
)

func parse(t *testing.T, s string) *xdm.Node {
	t.Helper()
	tree, err := xdm.ParseString(s, xdm.ParseOptions{BaseURI: "http://example.com/d.xml"})
	if err != nil {
		t.Fatal(err)
	}
	return tree.Root
}

func canon(t *testing.T, n *xdm.Node) string {
	t.Helper()
	b, err := c14n.Bytes(n, c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEdits(t *testing.T) {
	doc := parse(t, `<r xmlns:p="urn:p" a="1"><x/><!--c--><y/></r>`)
	r := doc.FirstChild()
	x, c, y := r.ChildAt(0), r.ChildAt(1), r.ChildAt(2)
	ins := func(local string) *xdm.Node { return Element(nil, "", "", local) }
	ins1, ins2, front, end, rep := ins("m1"), ins("m2"), ins("f"), ins("e"), ins("z")
	Text(ins1, "t")

	var e Edits
	e.SetAttr(r, xdm.QName{Local: "a"}, "2")                            // replaces
	e.SetAttr(r, xdm.QName{Prefix: "p", URI: "urn:p", Local: "b"}, "3") // adds
	e.Declare(y, "q", "urn:q")
	e.Insert(r, 0, front)
	e.Insert(r, 1, ins1)
	e.Insert(r, 1, ins2) // same position: after ins1
	e.Insert(r, 3, end)
	e.Insert(r, 3, end) // appended twice: two copies
	e.ReplaceNode(c, rep)
	e.ReplaceNode(x) // removed

	root, m := Rebuild(y, &e)
	want := `<r xmlns:p="urn:p" a="2" p:b="3"><f></f><m1>t</m1><m2></m2><z></z><y xmlns:q="urn:q"></y><e></e><e></e></r>`
	if got := canon(t, root); got != want {
		t.Fatalf("rebuilt\n got %s\nwant %s", got, want)
	}
	if canon(t, doc) != `<r xmlns:p="urn:p" a="1"><x></x><!--c--><y></y></r>` {
		t.Fatal("source changed")
	}
	if root.Kind() != xdm.KindDocument || m.Of(doc) != root || root.BaseURI() != doc.BaseURI() || root.Tree() == nil {
		t.Fatal("document node not rebuilt as a document")
	}
	nr := root.FirstChild()
	if m.Of(r) != nr || m.Of(y) != nr.ChildAt(4) || m.Of(ins1) != nr.ChildAt(1) || m.Of(ins1.FirstChild()) != nr.ChildAt(1).FirstChild() ||
		m.Of(rep) != nr.ChildAt(3) || m.Of(r.AttrAt(0)) != nr.Attr("", "a") {
		t.Fatal("map does not take nodes to their copies")
	}
	if m.Of(x) != nil {
		t.Fatal("removed node mapped")
	}
	if m.Of(c) != nil {
		t.Fatal("replaced node mapped")
	}
}

func TestRebuildFragment(t *testing.T) {
	f := Element(nil, "p", "urn:p", "f")
	f.AddNamespace("p", "urn:p")
	k := Element(f, "", "", "k")
	Text(k, "v")
	root, m := Rebuild(k, nil)
	if root == f || m.Of(f) != root || root.Parent() != nil || root.Tree() != nil || canon(t, root) != canon(t, f) {
		t.Fatalf("fragment copy %s", canon(t, root))
	}
	if m.Of(k).Parent() != root {
		t.Fatal("child copy not under root copy")
	}
}

func TestRebuildConstructedDocument(t *testing.T) {
	d := xdm.NewNode(xdm.KindDocument, xdm.QName{}, "")
	Element(d, "", "", "a")
	root, _ := Rebuild(d, nil)
	if root.Kind() != xdm.KindDocument || canon(t, root) != "<a></a>" {
		t.Fatal(canon(t, root))
	}
}

func TestDoc(t *testing.T) {
	doc := parse(t, `<r><a/><b/></r>`)
	r := doc.FirstChild()
	a, b := r.ChildAt(0), r.ChildAt(1)
	d := NewDoc(a)
	if d.Root() != doc || d.Node(a) != a || d.Node(nil) != nil {
		t.Fatal("fresh Doc")
	}

	// Version 2: an attribute on a.
	var e1 Edits
	e1.SetAttr(a, xdm.QName{Local: "v"}, "2")
	m1, err := d.Apply(&e1)
	if err != nil {
		t.Fatal(err)
	}
	v2 := d.Root()
	if v2 == doc || m1.Of(a) != d.Node(a) || AttrValue(d.Node(a), "", "v") != "2" {
		t.Fatal("version 2")
	}

	// Version 3, keyed on nodes of version 1: b removed, a node appended to a.
	n := Element(nil, "", "", "n")
	var e2 Edits
	e2.ReplaceNode(b)
	e2.Insert(a, 0, n)
	if _, err := d.Apply(&e2); err != nil {
		t.Fatal(err)
	}
	if got := canon(t, d.Root()); got != `<r><a v="2"><n></n></a></r>` {
		t.Fatal(got)
	}
	if d.Node(b) != nil || d.Node(m1.Of(b)) != nil {
		t.Fatal("removed node still found")
	}
	if d.Node(a) != d.Node(m1.Of(a)) || d.Node(a).Root() != d.Root() || d.Node(n) == nil || d.Node(n).Parent() != d.Node(a) {
		t.Fatal("nodes of earlier versions not mapped to the latest")
	}

	// Prepare leaves the Doc as it was until Commit.
	var e3 Edits
	e3.Declare(r, "p", "urn:p")
	root, m, err := d.Prepare(&e3)
	if err != nil || d.Root() == root {
		t.Fatal("Prepare committed")
	}
	d.Commit(root, m)
	if d.Root() != root || d.Node(r).NumNamespaceDecls() != 1 || d.Node(a) == nil {
		t.Fatal("Commit")
	}

	// An edit naming a node of no version is refused, and nothing changes.
	cur := d.Root()
	var bad Edits
	bad.SetAttr(Element(nil, "", "", "foreign"), xdm.QName{Local: "x"}, "")
	if _, err := d.Apply(&bad); !errors.Is(err, errForeign) || d.Root() != cur {
		t.Fatalf("foreign node: %v", err)
	}
	if d.Node(v2) != d.Root() {
		t.Fatal("root of an earlier version")
	}
}

// label names a node of the trees TestDocNodeEveryVersion builds, in which
// every element name and every text, comment and PI value is unique: the
// same label in two versions is the same node.
func label(n *xdm.Node) string {
	switch n.Kind() {
	case xdm.KindDocument:
		return "/"
	case xdm.KindElement:
		return n.Name().Local
	case xdm.KindAttribute:
		return label(n.Parent()) + "@" + n.Name().Local
	}
	return "#" + n.Value()
}

// allNodes returns n and every node under it, attributes included.
func allNodes(n *xdm.Node) []*xdm.Node {
	out := []*xdm.Node{n}
	for a := range n.Attrs() {
		out = append(out, a)
	}
	for c := range n.Children() {
		out = append(out, allNodes(c)...)
	}
	return out
}

// checkEveryVersion checks that d.Node takes every node of every tree in
// seen to the node of the current tree with its label, or nil when there
// is none: what a map from each node to its copy, followed change by
// change, gives.
func checkEveryVersion(t *testing.T, d *Doc, seen [][]*xdm.Node) {
	t.Helper()
	cur := map[string]*xdm.Node{}
	for _, n := range allNodes(d.Root()) {
		cur[label(n)] = n
	}
	checked := 0
	for v, nodes := range seen {
		for _, n := range nodes {
			if got, want := d.Node(n), cur[label(n)]; got != want {
				t.Fatalf("version %d, %s: got %v, want %v", v, label(n), got, want)
			}
			checked++
		}
	}
	if checked < 20 {
		t.Fatalf("checked only %d nodes", checked)
	}
}

func TestDocNodeEveryVersion(t *testing.T) {
	frag := func(s string) *xdm.Node { return parse(t, s).FirstChild() }
	for name, start := range map[string]*xdm.Node{
		"document": parse(t, `<r xmlns:p="urn:p" ra="1"><a aa="1">ta<b ba="1">tb</b><!--ca--></a><c ca="1">tc</c><d da="1"><e/></d><?pi x?></r>`),
		"fragment": xdm.Copy(frag(`<r xmlns:p="urn:p" ra="1"><a aa="1">ta<b ba="1">tb</b><!--ca--></a><c ca="1">tc</c><d da="1"><e/></d><?pi x?></r>`)),
	} {
		t.Run(name, func(t *testing.T) {
			d := NewDoc(start)
			seen := [][]*xdm.Node{allNodes(d.Root())}
			el := func(local string) *xdm.Node {
				for _, n := range allNodes(d.Root()) {
					if n.Kind() == xdm.KindElement && n.Name().Local == local {
						return n
					}
				}
				t.Fatalf("no %s", local)
				return nil
			}
			apply := func(e *Edits, inserted ...*xdm.Node) {
				t.Helper()
				prev := allNodes(d.Root())
				c, err := d.Apply(e)
				if err != nil {
					t.Fatal(err)
				}
				for _, n := range inserted {
					seen = append(seen, allNodes(n))
				}
				seen = append(seen, allNodes(d.Root()))
				checkEveryVersion(t, d, seen)
				// The Copies Apply returns agree with Node for the
				// previous tree.
				for _, n := range prev {
					if c.Of(n) != d.Node(n) {
						t.Fatalf("Copies.Of(%s) = %v, Node %v", label(n), c.Of(n), d.Node(n))
					}
				}
			}
			r, a, c := el("r"), el("a"), el("c")

			var e1 Edits
			e1.SetAttr(a, xdm.QName{Local: "aa"}, "2")
			e1.SetAttr(c, xdm.QName{Local: "na"}, "1")
			e1.Declare(el("d"), "q", "urn:q")
			apply(&e1)

			// Keyed on nodes of the first version.
			f, h := frag(`<f fa="1">tf<g/></f>`), frag(`<h ha="1"/>`)
			var e2 Edits
			e2.Insert(r, 1, f)
			e2.ReplaceNode(el("e"), h)
			apply(&e2, f, h)

			// Keyed on a node of the second version, on an inserted node
			// and on the nodes it was copied to.
			i, j := frag(`<i>ti</i>`), frag(`<j/>`)
			var e3 Edits
			e3.ReplaceNode(el("b"))
			e3.Insert(el("r"), el("r").NumChildren(), i)
			e3.Insert(f, 0, j)
			e3.SetAttr(c, xdm.QName{Local: "ca"}, "3")
			apply(&e3, i, j)

			root, m, err := d.Prepare(&Edits{Namespaces: map[*xdm.Node][]Binding{a: {{"z", "urn:z"}}}})
			if err != nil {
				t.Fatal(err)
			}
			d.Commit(root, m)
			seen = append(seen, allNodes(d.Root()))
			checkEveryVersion(t, d, seen)
			if got := canon(t, d.Root()); got != `<r xmlns:p="urn:p" ra="1"><a xmlns:z="urn:z" aa="2">ta<!--ca--></a><f fa="1"><j></j>tf<g></g></f><c ca="3" na="1">tc</c><d xmlns:q="urn:q" da="1"><h ha="1"></h></d><?pi x?><i>ti</i></r>` {
				t.Fatal(got)
			}
		})
	}
}

func TestRebuildTree(t *testing.T) {
	doc := parse(t, `<r><a/></r>`)
	var e Edits
	e.SetAttr(doc.FirstChild(), xdm.QName{Local: "v"}, "1")
	want, _ := Rebuild(doc, &e)
	if got := RebuildTree(doc, &e); canon(t, got) != canon(t, want) {
		t.Fatal(canon(t, got))
	}
}
