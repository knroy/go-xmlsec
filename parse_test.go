package xmlsec

import (
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
