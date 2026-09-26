package xmlsec

import (
	"errors"
	"testing"
)

func TestAttachmentSetAll(t *testing.T) {
	a, b := &Attachment{ID: "a"}, &Attachment{ID: "b"}
	s, err := NewAttachmentSet(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if all := s.All(); len(all) != 2 || all[0] != a || all[1] != b {
		t.Fatalf("All = %v", all)
	}
	if _, err := s.Lookup("cid:"); !errors.Is(err, ErrAttachmentNotFound) {
		t.Fatalf("empty cid: %v", err)
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
