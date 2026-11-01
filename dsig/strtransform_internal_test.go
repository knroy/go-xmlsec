package dsig

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xmlsec/v2"
)

// The STR Dereference Transform's output: Exclusive C14N with the default
// namespace inclusive, and xmlns="" on the apex only when no default
// namespace is in scope there (SOAP Message Security 1.1.1 section 8.3).
func TestSTROctets(t *testing.T) {
	exc := string(c14n.Exclusive10)
	for _, c := range []struct {
		name, doc, want, alg string
		prefixes             []string
	}{
		{"default namespace in scope", `<r xmlns="urn:d"><t a="1"/></r>`, `<t xmlns="urn:d" a="1"></t>`, exc, nil},
		{"no default namespace", `<r xmlns:p="urn:p"><p:t a="1"/></r>`, `<p:t xmlns="" xmlns:p="urn:p" a="1"></p:t>`, exc, nil},
		{"bare apex", `<r><t/></r>`, `<t xmlns=""></t>`, exc, []string{""}},
		{"inclusive prefix", `<r xmlns:q="urn:q"><t/></r>`, `<t xmlns="" xmlns:q="urn:q"></t>`, exc, []string{"q"}},
		// Inclusive C14N renders every namespace in scope, and the
		// transform still adds xmlns="" when no default is.
		{"inclusive C14N", `<r xmlns:q="urn:q"><t/></r>`, `<t xmlns="" xmlns:q="urn:q"></t>`, string(c14n.Inclusive10), nil},
		{"inclusive C14N, default in scope", `<r xmlns="urn:d" xmlns:q="urn:q"><t/></r>`, `<t xmlns="urn:d" xmlns:q="urn:q"></t>`, string(c14n.Inclusive10), nil},
	} {
		tree, err := xmlsec.Parse([]byte(c.doc))
		if err != nil {
			t.Fatal(err)
		}
		tok := tree.Root.FirstChild().FirstChild()
		var got bytes.Buffer
		if err := writeSTR(&got, tok, c.alg, c.prefixes); err != nil || got.String() != c.want {
			t.Errorf("%s: %s, %v; want %s", c.name, got.String(), err, c.want)
		}
	}

	// A token with no canonical form fails the transform.
	tree, err := xmlsec.Parse([]byte(`<r xmlns:p="relative"><p:t/></r>`))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSTR(io.Discard, tree.Root.FirstChild().FirstChild(), string(c14n.Exclusive10), nil); !errors.Is(err, c14n.ErrRelativeNamespaceURI) {
		t.Fatalf("relative namespace: %v", err)
	}
}

// errAfter fails every write after the first n.
type errAfter struct{ n int }

func (w *errAfter) Write(p []byte) (int, error) {
	if w.n == 0 {
		return 0, io.ErrShortWrite
	}
	w.n--
	return len(p), nil
}

// apexWriter takes the apex start tag in pieces, and passes write errors
// on.
func TestAPEXWriter(t *testing.T) {
	var got bytes.Buffer
	a := &apexWriter{w: &got}
	for _, c := range []byte(`<t a="1">x</t>`) {
		if n, err := a.Write([]byte{c}); n != 1 || err != nil {
			t.Fatalf("write: %d, %v", n, err)
		}
	}
	if want := `<t xmlns="" a="1">x</t>`; got.String() != want {
		t.Fatalf("%s, want %s", got.String(), want)
	}
	for n := range 2 {
		if _, err := (&apexWriter{w: &errAfter{n}}).Write([]byte(`<t>x</t>`)); err != io.ErrShortWrite {
			t.Errorf("failing after %d writes: %v", n, err)
		}
	}
}
