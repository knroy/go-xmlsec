package xmlsec

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
)

// Assert the effective DOCTYPE behaviour rather than trust the upstream
// documentation.
func TestParseRefusesDOCTYPE(t *testing.T) {
	for name, doc := range map[string]string{
		"internal entity": `<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>`,
		"external entity": `<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>`,
		"bare doctype":    `<!DOCTYPE a><a/>`,
	} {
		_, err := Parse([]byte(doc))
		// ErrMalformed, with the parser's refusal still wrapped, and no
		// mention of a parse option the caller cannot set.
		var de doctypeError
		if !errors.Is(err, ErrMalformed) || !errors.As(err, &de) || de.cause == nil || strings.Contains(err.Error(), "AllowDOCTYPE") {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := ParseWithLimits([]byte(doc), ParseLimits{MaxDepth: 10}); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s, with limits: %v", name, err)
		}
	}
	// Other syntax errors are reported as the parser gives them.
	if _, err := Parse([]byte(`<a>`)); err == nil || errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(`<a/>`)); err != nil {
		t.Fatal(err)
	}
}

func TestParseLimits(t *testing.T) {
	deep := func(n int) []byte {
		return []byte(strings.Repeat("<a>", n) + strings.Repeat("</a>", n))
	}
	cases := []struct {
		name    string
		doc     []byte
		wantErr bool
		limit   bool // the error is ErrLimitExceeded
	}{
		{"at depth limit", deep(MaxParseDepth), false, false},
		{"beyond depth limit", deep(MaxParseDepth + 1), true, true},
		{"not well-formed", []byte("<a>"), true, false},
		{"empty", nil, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(c.doc)
			if (err != nil) != c.wantErr || errors.Is(err, ErrLimitExceeded) != c.limit {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestParseWithLimits(t *testing.T) {
	deep := strings.Repeat("<a>", 20) + strings.Repeat("</a>", 20)
	cases := []struct {
		name   string
		doc    string
		limits ParseLimits
		want   error
	}{
		{"pinned defaults", deep, ParseLimits{}, nil},
		{"tighter bytes", deep, ParseLimits{MaxBytes: 10}, ErrLimitExceeded},
		{"tighter depth", deep, ParseLimits{MaxDepth: 5}, ErrLimitExceeded},
		{"tighter nodes", deep, ParseLimits{MaxNodes: 5}, ErrLimitExceeded},
		{"within tighter limits", deep, ParseLimits{MaxBytes: 1 << 10, MaxDepth: 30, MaxNodes: 100}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseWithLimits([]byte(c.doc), c.limits)
			if !errors.Is(err, c.want) && !(c.want == nil && err == nil) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
	// Limits can only be tightened.
	for name, l := range map[string]ParseLimits{
		"bytes above pinned": {MaxBytes: MaxParseBytes + 1},
		"depth above pinned": {MaxDepth: MaxParseDepth + 1},
		"nodes above pinned": {MaxNodes: MaxParseNodes + 1},
		"negative":           {MaxDepth: -1},
	} {
		if _, err := ParseWithLimits([]byte(`<a/>`), l); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The reader parse the internal packages use is Parse, limits and errors
// included, over the octets a reader holds.
func TestParseReader(t *testing.T) {
	for _, doc := range []string{`<a><b/>t</a>`, `<!DOCTYPE a><a/>`, `<a>`, strings.Repeat("<a>", MaxParseDepth+1)} {
		want, werr := Parse([]byte(doc))
		got, err := xmltree.Parse(io.MultiReader(strings.NewReader(doc[:len(doc)/2]), strings.NewReader(doc[len(doc)/2:])))
		if fmt.Sprint(err) != fmt.Sprint(werr) || errors.Is(err, ErrLimitExceeded) != errors.Is(werr, ErrLimitExceeded) ||
			errors.Is(err, ErrMalformed) != errors.Is(werr, ErrMalformed) || (got == nil) != (want == nil) {
			t.Fatalf("%.20q: got %v, want %v", doc, err, werr)
		}
		if got != nil && got.Root.StringValue() != want.Root.StringValue() {
			t.Fatalf("%q: different trees", doc)
		}
	}
}

// The options go-xml parses an XSLT transform's input with are the pinned ones.
func TestParseOptionsPinned(t *testing.T) {
	o := xmltree.ParseOptions()
	if o.MaxDepth != MaxParseDepth || o.MaxBytes != MaxParseBytes || o.MaxNodes != MaxParseNodes {
		t.Fatalf("%+v", o)
	}
}
