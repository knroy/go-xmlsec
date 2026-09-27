package xmltree

import (
	"bytes"
	"testing"

	"github.com/knroy/go-xml/xdm"
)

func TestClone(t *testing.T) {
	e := Element(nil, "p", "urn:p", "e")
	e.AddNamespace("p", "urn:p")
	SetAttr(e, "", "", "a", "1")
	Text(Element(e, "p", "urn:p", "k"), "v")
	c := Clone(e)
	SetAttr(e, "", "", "a", "2")
	e.Children[0].Children[0].Value = "w"
	if c.Parent != nil || AttrValue(c, "", "a") != "1" || c.Attrs[0].Parent != c ||
		c.Namespaces[0].Value != "urn:p" || c.Children[0].Parent != c || c.Children[0].StringValue() != "v" {
		t.Fatalf("clone %+v", c)
	}
}

func TestSetAttrAndAttrValue(t *testing.T) {
	e := Element(nil, "p", "urn:p", "e")
	if got := AttrValue(e, "", "a"); got != "" {
		t.Fatalf("absent attribute: %q", got)
	}
	SetAttr(e, "", "", "a", "1")
	SetAttr(e, "", "", "a", "2")
	if len(e.Attrs) != 1 || AttrValue(e, "", "a") != "2" {
		t.Fatalf("replace: %d attrs, value %q", len(e.Attrs), AttrValue(e, "", "a"))
	}
}

func TestDeclare(t *testing.T) {
	cases := []struct {
		name    string
		bound   string // URI already bound to "p" on the parent, "" for none
		uri     string
		wantErr bool
		wantNew bool
	}{
		{"unbound", "", "urn:a", false, true},
		{"same binding in scope", "urn:a", "urn:a", false, false},
		{"conflicting binding", "urn:a", "urn:b", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parent := Element(nil, "", "", "parent")
			if c.bound != "" {
				parent.AddNamespace("p", c.bound)
			}
			e := Element(parent, "", "", "e")
			err := Declare(e, "p", c.uri)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v", err)
			}
			if got := len(e.Namespaces) == 1; got != c.wantNew {
				t.Fatalf("declared on e: %v", got)
			}
		})
	}
}

func TestDocumentElement(t *testing.T) {
	root := Element(nil, "", "", "root")
	child := Element(root, "", "", "child")
	if got := DocumentElement(child); got != root {
		t.Fatal("detached element tree: want its root element")
	}

	doc := &xdm.Node{Kind: xdm.KindDocument}
	Text(doc, "stray")
	el := Element(doc, "", "", "el")
	if got := DocumentElement(el); got != el {
		t.Fatal("document: want its element child")
	}

	empty := &xdm.Node{Kind: xdm.KindDocument}
	Text(empty, "only text")
	if got := DocumentElement(empty); got != nil {
		t.Fatal("document without element: want nil")
	}
}

func TestBase64(t *testing.T) {
	cases := []struct {
		in      string
		want    []byte
		wantErr bool
	}{
		{"aGVs\r\n bG8=\t", []byte("hello"), false},
		{"", []byte{}, false},
		{"not base64!", nil, true},
	}
	for _, c := range cases {
		e := Element(nil, "", "", "e")
		Text(e, c.in)
		got, err := Base64(e)
		if (err != nil) != c.wantErr || !c.wantErr && !bytes.Equal(got, c.want) {
			t.Errorf("%q: %q, %v", c.in, got, err)
		}
	}
}

func TestWalk(t *testing.T) {
	root := Element(nil, "", "", "a")
	Text(root, "t")
	Element(Element(root, "", "", "b"), "", "", "c")
	var names []string
	Walk(root, func(n *xdm.Node) { names = append(names, n.Name.Local) })
	if len(names) != 3 || names[0] != "a" || names[1] != "b" || names[2] != "c" {
		t.Fatalf("walk order %v", names)
	}
}

func TestDocumentElementNil(t *testing.T) {
	if DocumentElement(nil) != nil {
		t.Fatal("non-nil")
	}
}
