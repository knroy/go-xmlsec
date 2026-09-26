package xmlsec

import (
	"errors"
	"strings"
	"testing"
)

// Open item X-1: assert the effective DOCTYPE behaviour rather than trust
// either version of the upstream documentation.
func TestParseRefusesDOCTYPE(t *testing.T) {
	for name, doc := range map[string]string{
		"internal entity": `<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>`,
		"external entity": `<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>`,
		"bare doctype":    `<!DOCTYPE a><a/>`,
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
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
	}{
		{"at depth limit", deep(MaxParseDepth), false},
		{"beyond depth limit", deep(MaxParseDepth + 1), true},
		{"not well-formed", []byte("<a>"), true},
		{"empty", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(c.doc); (err != nil) != c.wantErr {
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
