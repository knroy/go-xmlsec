package xmlsec

import (
	"testing"

	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
)

func TestDocument(t *testing.T) {
	tree, err := Parse([]byte(`<a><b/></a>`))
	if err != nil {
		t.Fatal(err)
	}
	d := NewDocument(tree.Root.FirstChild())
	if d.Root() != tree.Root {
		t.Fatal("Root: want the document node of the tree started from")
	}
	b := tree.Root.FirstChild().FirstChild()
	if d.Node(b) != b {
		t.Fatal("Node before a change: want the node itself")
	}

	// A change through the internal Doc is what Root and Node report.
	in := xmltree.DocOf(d)
	if in == nil || xmltree.DocOf(tree.Root) != nil || xmltree.DocOf((*Document)(nil)) != nil {
		t.Fatal("DocOf: want the Doc of a *Document only")
	}
	var e xmltree.Edits
	e.SetAttr(b, xdm.QName{Local: "x"}, "1")
	if _, err := in.Apply(&e); err != nil {
		t.Fatal(err)
	}
	nb := d.Node(b)
	if d.Root() == tree.Root || nb == nil || nb == b || nb.Root() != d.Root() || xmltree.AttrValue(nb, "", "x") != "1" {
		t.Fatalf("after a change: root %p, node %v", d.Root(), nb)
	}
	if d.Node(xdm.NewNode(xdm.KindElement, xdm.QName{Local: "c"}, "")) != nil {
		t.Fatal("Node of a foreign node: want nil")
	}
}
