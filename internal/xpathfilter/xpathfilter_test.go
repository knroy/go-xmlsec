package xpathfilter

import (
	"errors"
	"testing"

	"github.com/knroy/go-xml/xpath"
	"github.com/knroy/go-xmlsec"
)

func TestAllowed(t *testing.T) {
	tree, err := xmlsec.Parse([]byte(`<r xmlns:p="urn:p"><x> self::p:a </x></r>`))
	if err != nil {
		t.Fatal(err)
	}
	x := tree.Root.Children[0].Children[0]
	for _, c := range []struct {
		expr string
		ns   map[string]string
		want bool
	}{
		{"self::p:a", map[string]string{"p": "urn:p"}, true},
		{" self::p:a\n", nil, true},
		{"self::p:b", map[string]string{"p": "urn:p"}, false},
		{"self::p:a", map[string]string{"p": "urn:other"}, false},
		{"self::p:a", map[string]string{"q": "urn:p"}, false},
	} {
		if got := Allowed(x, c.expr, c.ns); got != c.want {
			t.Errorf("Allowed(%q, %v) = %v", c.expr, c.ns, got)
		}
	}
}

func TestCompileAndLibrary(t *testing.T) {
	tree, err := xmlsec.Parse([]byte(`<r xml:lang="en" xmlns="urn:d"><a/></r>`))
	if err != nil {
		t.Fatal(err)
	}
	r := tree.Root.Children[0]
	c, err := Compile(" count(self::p:r) = 1 and @xml:lang = 'en' and namespace-uri(here()) = 'urn:d' ", map[string]string{"p": "urn:d"})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.EvalBool(xpath.NewContext(r, Library(r, tree.Root)).WithFocus(r, 1, 1))
	if err != nil || !ok {
		t.Fatalf("EvalBool = %v, %v", ok, err)
	}

	// here() outside the evaluated document.
	other, _ := xmlsec.Parse([]byte(`<o/>`))
	if _, err := c.EvalBool(xpath.NewContext(r, Library(other.Root.Children[0], tree.Root)).WithFocus(r, 1, 1)); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("here() elsewhere: %v", err)
	}

	// An unprefixed name is in no namespace, as in XPath 1.0.
	if c, err := Compile("self::a", nil); err != nil {
		t.Fatal(err)
	} else if ok, _ := c.EvalBool(xpath.NewContext(r, Library(r, tree.Root)).WithFocus(r.Children[0], 1, 1)); ok {
		t.Fatal("self::a matched an element in urn:d")
	}

	for _, expr := range []string{"self::q:r", "(("} {
		if _, err := Compile(expr, nil); !errors.Is(err, xmlsec.ErrMalformed) {
			t.Errorf("Compile(%q): %v", expr, err)
		}
	}
}
