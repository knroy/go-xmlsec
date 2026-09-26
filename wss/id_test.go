package wss

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

func TestAssignIDErrors(t *testing.T) {
	doc := parseDoc(t, envWSUClash)
	body := xmltree.DocumentElement(doc).ChildElements()[0]
	if _, err := AssignID(doc, body); err == nil {
		t.Fatal("wsu prefix bound to another URI accepted")
	}
	if body.Attr(NSWSU, "Id") != nil {
		t.Fatal("wsu:Id set despite the error")
	}
}

type failReader struct{}

func TestRandomnessFailure(t *testing.T) {
	old := randReader
	randReader = failReader{}
	t.Cleanup(func() { randReader = old })

	doc := parseDoc(t, env11)
	h, err := NewHeader(doc, NSSOAP11, "", false)
	if err != nil {
		t.Fatal(err)
	}
	body := xmltree.DocumentElement(doc).ChildElements()[1]
	calls := map[string]func() error{
		"AssignID": func() error { _, err := AssignID(doc, body); return err },
		"AddBinarySecurityToken": func() error {
			_, err := h.AddBinarySecurityToken(testCert(t, "c"), nil, xmlsec.BSTValueTypeX509v3)
			return err
		},
		"AddTimestamp": func() error { _, err := h.AddTimestamp(time.Unix(0, 0), time.Minute); return err },
	}
	for name, f := range calls {
		if err := f(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// newID skips a random value already used as an ID in the document.
func TestNewIDSkipsCollision(t *testing.T) {
	old := randReader
	randReader = bytes.NewReader(append(bytes.Repeat([]byte{0xab}, 16), bytes.Repeat([]byte{0xcd}, 16)...))
	t.Cleanup(func() { randReader = old })

	doc := parseDoc(t, strings.Replace(env11, `wsu:Id="x"`, `wsu:Id="id-abababababababababababababababab"`, 1))
	id, err := newID(doc)
	if err != nil || id != "id-cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" {
		t.Fatalf("newID = %q, %v", id, err)
	}
}
