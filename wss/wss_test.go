package wss

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
)

const env11 = `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
	`<soap:Body><a wsu:Id="x" xmlns:wsu="` + NSWSU + `"/><b xml:id="y"/></soap:Body></soap:Envelope>`

func TestFindByID(t *testing.T) {
	tree, err := xmlsec.Parse([]byte(env11))
	if err != nil {
		t.Fatal(err)
	}
	doc := tree.Root
	for _, id := range []string{"x", "y"} {
		if _, err := FindByID(doc, id); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
	if _, err := FindByID(doc, "z"); !errors.Is(err, xmlsec.ErrIDNotFound) {
		t.Errorf("missing: %v", err)
	}

	// The same value as wsu:Id on one element and xml:id on another is
	// still ambiguous.
	tree, _ = xmlsec.Parse([]byte(strings.Replace(env11, `xml:id="y"`, `xml:id="x"`, 1)))
	if _, err := FindByID(tree.Root, "x"); !errors.Is(err, xmlsec.ErrAmbiguousID) {
		t.Errorf("duplicate: %v", err)
	}
}

func TestHeaderAndAssignID(t *testing.T) {
	old := randReader
	randReader = bytes.NewReader(append(bytes.Repeat([]byte{0xab}, 16), bytes.Repeat([]byte{0xcd}, 16)...))
	t.Cleanup(func() { randReader = old })

	tree, err := xmlsec.Parse([]byte(env11))
	if err != nil {
		t.Fatal(err)
	}
	doc := tree.Root
	body := doc.Children[0].ChildElements()[0]
	id, err := AssignID(doc, body)
	if err != nil || id != "id-abababababababababababababababab" {
		t.Fatalf("AssignID = %q, %v", id, err)
	}
	if again, _ := AssignID(doc, body); again != id {
		t.Fatalf("AssignID not idempotent: %q", again)
	}

	h, err := NewHeader(doc, NSSOAP11, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.AddTimestamp(time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := NewHeader(doc, NSSOAP11, "", false); err == nil {
		t.Fatal("second Security header for the same actor accepted")
	}

	out, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Exclusive10})
	if err != nil {
		t.Fatal(err)
	}
	want := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header>` +
		`<wsse:Security xmlns:wsse="` + NSWSSE + `" soap:mustUnderstand="1">` +
		`<wsu:Timestamp xmlns:wsu="` + NSWSU + `" wsu:Id="id-cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd">`
	if !strings.HasPrefix(string(out), want) {
		t.Fatalf("got\n%s", out)
	}
}
