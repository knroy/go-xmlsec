package dsig

import (
	"errors"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
)

// The STR Dereference Transform's output: Exclusive C14N with the default
// namespace inclusive, and xmlns="" on the apex only when no default
// namespace is in scope there (SOAP Message Security 1.1.1 section 8.3).
func TestSTROctets(t *testing.T) {
	for _, c := range []struct {
		name, doc, want string
		prefixes        []string
	}{
		{"default namespace in scope", `<r xmlns="urn:d"><t a="1"/></r>`, `<t xmlns="urn:d" a="1"></t>`, nil},
		{"no default namespace", `<r xmlns:p="urn:p"><p:t a="1"/></r>`, `<p:t xmlns="" xmlns:p="urn:p" a="1"></p:t>`, nil},
		{"bare apex", `<r><t/></r>`, `<t xmlns=""></t>`, []string{""}},
		{"inclusive prefix", `<r xmlns:q="urn:q"><t/></r>`, `<t xmlns="" xmlns:q="urn:q"></t>`, []string{"q"}},
	} {
		tree, err := xmlsec.Parse([]byte(c.doc))
		if err != nil {
			t.Fatal(err)
		}
		tok := tree.Root.Children[0].Children[0]
		got, err := strOctets(tok, c.prefixes)
		if err != nil || string(got) != c.want {
			t.Errorf("%s: %s, %v; want %s", c.name, got, err, c.want)
		}
	}

	// A token with no canonical form fails the transform.
	tree, err := xmlsec.Parse([]byte(`<r xmlns:p="relative"><p:t/></r>`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strOctets(tree.Root.Children[0].Children[0], nil); !errors.Is(err, c14n.ErrRelativeNamespaceURI) {
		t.Fatalf("relative namespace: %v", err)
	}
}
