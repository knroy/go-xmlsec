package wss

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
)

const env11 = `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
	`<soap:Body><a wsu:Id="x" xmlns:wsu="` + xmlsec.NSWSU + `"/><b xml:id="y"/></soap:Body></soap:Envelope>`

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

func TestFindByIDExtraAttributes(t *testing.T) {
	samlID := xdm.QName{Local: "ID"}
	plainID := xdm.QName{Local: "Id"}
	const doc = `<r xmlns:wsu="` + xmlsec.NSWSU + `" xmlns:p="urn:p">` +
		`<a ID="s"/><b Id="d"/><c wsu:Id="w"/><d p:ID="q"/><e ID="n"/></r>`
	root := parseDoc(t, doc)

	// Default: only wsu:Id and xml:id, exactly as FindByID.
	for _, id := range []string{"s", "d", "q"} {
		if _, err := FindByID(root, id); !errors.Is(err, xmlsec.ErrIDNotFound) {
			t.Errorf("default resolved %q: %v", id, err)
		}
	}
	for _, c := range []struct {
		id, want string
		attr     xdm.QName
	}{
		{"s", "a", samlID},
		{"d", "b", plainID},
		{"w", "c", samlID}, // wsu:Id always counts
		{"n", "e", xdm.QName{Prefix: "ignored", Local: "ID"}},
	} {
		if e, err := FindByID(root, c.id, c.attr); err != nil || e.Name.Local != c.want {
			t.Errorf("%q: %v, %v", c.id, e, err)
		}
	}
	// Unprefixed names have no namespace: p:ID is not ID.
	if _, err := FindByID(root, "q", samlID); !errors.Is(err, xmlsec.ErrIDNotFound) {
		t.Errorf("p:ID matched ID: %v", err)
	}

	// Duplicates across every combination of the effective set.
	for name, c := range map[string]struct {
		doc   string
		attrs []xdm.QName
	}{
		"ID and wsu:Id":      {`<a ID="x"/><b wsu:Id="x"/>`, []xdm.QName{samlID}},
		"ID and xml:id":      {`<a ID="x"/><b xml:id="x"/>`, []xdm.QName{samlID}},
		"ID and Id":          {`<a ID="x"/><b Id="x"/>`, []xdm.QName{samlID, plainID}},
		"ID twice":           {`<a ID="x"/><b ID="x"/>`, []xdm.QName{samlID}},
		"one element, two":   {`<a ID="x" wsu:Id="x"/>`, []xdm.QName{samlID}},
		"attribute repeated": {`<a ID="x"/><b ID="x"/>`, []xdm.QName{samlID, samlID}},
	} {
		d := parseDoc(t, `<r xmlns:wsu="`+xmlsec.NSWSU+`">`+c.doc+`</r>`)
		if _, err := FindByID(d, "x", c.attrs...); !errors.Is(err, xmlsec.ErrAmbiguousID) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A repeated name in the set counts an attribute once, not twice.
	if _, err := FindByID(root, "s", samlID, samlID); err != nil {
		t.Errorf("repeated name: %v", err)
	}
	if _, err := FindByID(nil, "s", samlID); !errors.Is(err, xmlsec.ErrIDNotFound) {
		t.Errorf("nil document: %v", err)
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

	h, err := NewHeader(doc, xmlsec.NSSOAP11, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.AddTimestamp(time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := NewHeader(doc, xmlsec.NSSOAP11, "", false); err == nil {
		t.Fatal("second Security header for the same actor accepted")
	}

	out, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Exclusive10})
	if err != nil {
		t.Fatal(err)
	}
	want := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header>` +
		`<wsse:Security xmlns:wsse="` + xmlsec.NSWSSE + `" soap:mustUnderstand="1">` +
		`<wsu:Timestamp xmlns:wsu="` + xmlsec.NSWSU + `" wsu:Id="id-cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd">`
	if !strings.HasPrefix(string(out), want) {
		t.Fatalf("got\n%s", out)
	}
}
