package xmlsec

import (
	"errors"
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

func TestAttachmentSet(t *testing.T) {
	a := &Attachment{ID: "part 1@example.com"}
	s, err := NewAttachmentSet(a)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Lookup("cid:part%201@example.com"); err != nil || got != a {
		t.Fatalf("percent-decoded lookup: %v", err)
	}
	for _, uri := range []string{"cid:other", "part 1@example.com", "cid:%zz"} {
		if _, err := s.Lookup(uri); !errors.Is(err, ErrAttachmentNotFound) {
			t.Errorf("%q: %v", uri, err)
		}
	}
	if _, err := NewAttachmentSet(a, &Attachment{ID: a.ID}); !errors.Is(err, ErrDuplicateAttachmentID) {
		t.Fatalf("duplicate: %v", err)
	}
}
