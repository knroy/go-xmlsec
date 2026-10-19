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
	if root.Kind() != xdm.KindDocument || m[doc] != root || root.BaseURI() != doc.BaseURI() || root.Tree() == nil {
		t.Fatal("document node not rebuilt as a document")
	}
	nr := root.FirstChild()
	if m[r] != nr || m[y] != nr.ChildAt(4) || m[ins1] != nr.ChildAt(1) || m[ins1.FirstChild()] != nr.ChildAt(1).FirstChild() ||
		m[rep] != nr.ChildAt(3) || m[r.AttrAt(0)] != nr.Attr("", "a") {
		t.Fatal("map does not take nodes to their copies")
	}
	if _, ok := m[x]; ok {
		t.Fatal("removed node mapped")
	}
	if _, ok := m[c]; ok {
		t.Fatal("replaced node mapped")
	}
}

func TestRebuildFragment(t *testing.T) {
	f := Element(nil, "p", "urn:p", "f")
	f.AddNamespace("p", "urn:p")
	k := Element(f, "", "", "k")
	Text(k, "v")
	root, m := Rebuild(k, nil)
	if root == f || m[f] != root || root.Parent() != nil || root.Tree() != nil || canon(t, root) != canon(t, f) {
		t.Fatalf("fragment copy %s", canon(t, root))
	}
	if m[k].Parent() != root {
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
	if v2 == doc || m1[a] != d.Node(a) || AttrValue(d.Node(a), "", "v") != "2" {
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
	if d.Node(b) != nil || d.Node(m1[b]) != nil {
		t.Fatal("removed node still found")
	}
	if d.Node(a) != d.Node(m1[a]) || d.Node(a).Root() != d.Root() || d.Node(n) == nil || d.Node(n).Parent() != d.Node(a) {
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
