package wss

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
)

func TestAssignIDErrors(t *testing.T) {
	doc := newDoc(t, envWSUClash)
	body := xmltree.DocumentElement(doc.Root()).ChildElements()[0]
	if _, err := AssignID(doc, body); err == nil {
		t.Fatal("wsu prefix bound to another URI accepted")
	}
	if doc.Node(body) != body || body.Attr(xmlsec.NSWSU, "Id") != nil {
		t.Fatal("wsu:Id set despite the error")
	}
}

type failReader struct{}

func TestRandomnessFailure(t *testing.T) {
	old := randReader
	randReader = failReader{}
	t.Cleanup(func() { randReader = old })

	doc := newDoc(t, env11)
	h, err := NewHeader(doc, xmlsec.NSSOAP11, "", false)
	if err != nil {
		t.Fatal(err)
	}
	body := xmltree.DocumentElement(doc.Root()).ChildElements()[1]
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

	// An unqualified Id or ID counts as used too: dsig resolves both on
	// request, so a clash would be ambiguous there.
	for _, attr := range []string{`Id`, `ID`} {
		randReader = bytes.NewReader(append(bytes.Repeat([]byte{0xab}, 16), bytes.Repeat([]byte{0xcd}, 16)...))
		doc := parseDoc(t, `<r><a `+attr+`="id-abababababababababababababababab"/></r>`)
		if id, err := newID(doc); err != nil || id != "id-cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" {
			t.Errorf("%s: newID = %q, %v", attr, id, err)
		}
	}
}

// XML Signature and XML Encryption elements get the unqualified Id their
// schemas define, never wsu:Id (BSP R3003, R3004); everything else wsu:Id.
func TestAssignIDSignatureAndEncryption(t *testing.T) {
	for _, ns := range []string{xmlsec.NSDSig, xmlsec.NSDSig11, xmlsec.NSXEnc, xmlsec.NSXEnc11} {
		doc := newDoc(t, `<r xmlns:x="`+ns+`" xmlns:wsu="`+xmlsec.NSWSU+`">`+
			`<x:New/><x:HasId Id="given"/><x:HasWSUId wsu:Id="w"/></r>`)
		kids := xmltree.DocumentElement(doc.Root()).ChildElements()
		id, err := AssignID(doc, kids[0])
		if k := doc.Node(kids[0]); err != nil || k.AttrValue("Id") != id || k.Attr(xmlsec.NSWSU, "Id") != nil {
			t.Fatalf("%s: %q, %v, attrs %v", ns, id, err, slices.Collect(k.Attrs()))
		}
		if again, _ := AssignID(doc, kids[0]); again != id {
			t.Errorf("%s: not idempotent: %q", ns, again)
		}
		if got, _ := AssignID(doc, kids[1]); got != "given" {
			t.Errorf("%s: existing Id: %q", ns, got)
		}
		// A wsu:Id on such an element is not the ID a reference may use.
		if got, _ := AssignID(doc, kids[2]); got == "w" || doc.Node(kids[2]).AttrValue("Id") != got {
			t.Errorf("%s: wsu:Id reused: %q", ns, got)
		}
		if _, err := FindByID(doc.Root(), id, xdm.QName{Local: "Id"}); err != nil {
			t.Errorf("%s: dsig.IDAttrDSig does not resolve it: %v", ns, err)
		}
	}
}

// Nil or wrong-kind input from a failed lookup is an error, never a panic.
func TestNilInputs(t *testing.T) {
	doc := newDoc(t, env11)
	text := xdm.NewNode(xdm.KindText, xdm.QName{}, "t")
	foreign := xmltree.DocumentElement(parseDoc(t, env11))
	checks := map[string]error{}
	_, checks["FindByID(nil)"] = FindByID(nil, "x")
	_, checks["AssignID(nil)"] = AssignID(doc, nil)
	_, checks["AssignID(text)"] = AssignID(doc, text)
	_, checks["AssignID(nil document)"] = AssignID(nil, foreign)
	_, checks["AssignID(foreign)"] = AssignID(doc, foreign)
	_, checks["ParseBinarySecurityToken(nil)"] = ParseBinarySecurityToken(nil)
	_, checks["ResolveSecurityTokenReference(doc, nil)"] = ResolveSecurityTokenReference(doc.Root(), nil)
	_, checks["ResolveSecurityTokenReference(nil, nil)"] = ResolveSecurityTokenReference(nil, nil)
	_, checks["NewHeader(nil)"] = NewHeader(nil, xmlsec.NSSOAP11, "", false)
	for name, err := range checks {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
		if strings.HasPrefix(name, "AssignID") && !errors.Is(err, xmlsec.ErrMalformed) {
			t.Errorf("%s: %v, want ErrMalformed", name, err)
		}
	}
}

// SOAP Message Security 1.1.1 section 4: an element MUST NOT carry both a
// wsu:Id and an xml:id, so AssignID returns an existing xml:id and adds
// nothing.
func TestAssignIDKeepsXMLID(t *testing.T) {
	doc := newDoc(t, env11)
	b := xmltree.DocumentElement(doc.Root()).ChildElements()[0].ChildElements()[1]
	id, err := AssignID(doc, b)
	if err != nil || id != "y" || doc.Node(b) != b || b.Attr(xmlsec.NSWSU, "Id") != nil {
		t.Fatalf("AssignID: %q, %v, attributes %v", id, err, slices.Collect(b.Attrs()))
	}
}

// The explicit-ID variants take the caller's ID, check it, and keep an ID
// an element already has, exactly as the minting functions do.
func TestExplicitIDs(t *testing.T) {
	doc := newDoc(t, env11)
	body := xmltree.DocumentElement(doc.Root()).ChildElements()[0]
	a, b := body.ChildElements()[0], body.ChildElements()[1]
	for _, c := range []struct {
		name string
		el   *xdm.Node
		id   string
		want error
	}{
		{"empty", body, "", xmlsec.ErrMalformed},
		{"not an NCName", body, "1st", xmlsec.ErrMalformed},
		{"in use as a wsu:Id", body, "x", xmlsec.ErrAmbiguousID},
		{"in use as an xml:id", body, "y", xmlsec.ErrAmbiguousID},
	} {
		if _, err := AssignIDWith(doc, c.el, c.id); !errors.Is(err, c.want) {
			t.Errorf("AssignIDWith %s: got %v, want %v", c.name, err, c.want)
		}
	}
	if id, err := AssignIDWith(doc, a, "other"); err != nil || id != "x" {
		t.Fatalf("existing wsu:Id: %q, %v", id, err)
	}
	if id, err := AssignIDWith(doc, b, "other"); err != nil || id != "y" {
		t.Fatalf("existing xml:id: %q, %v", id, err)
	}
	if id, err := AssignIDWith(doc, body, "body-1"); err != nil || id != "body-1" || xmltree.AttrValue(doc.Node(body), xmlsec.NSWSU, "Id") != "body-1" {
		t.Fatalf("AssignIDWith: %q, %v", id, err)
	}

	h, err := NewHeader(doc, xmlsec.NSSOAP11, "", false)
	if err != nil {
		t.Fatal(err)
	}
	cert := testCert(t, "c")
	adders := map[string]func(id string) (string, error){
		"AddBinarySecurityTokenWithID": func(id string) (string, error) {
			return h.AddBinarySecurityTokenWithID(cert, nil, xmlsec.BSTValueTypeX509v3, id)
		},
		"AddTimestampWithID": func(id string) (string, error) {
			return h.AddTimestampWithID(time.Unix(0, 0), time.Minute, id)
		},
		"AddSignatureConfirmationWithID": func(id string) (string, error) { return h.AddSignatureConfirmationWithID(nil, id) },
	}
	for name, add := range adders {
		for id, want := range map[string]error{"": xmlsec.ErrMalformed, "1st": xmlsec.ErrMalformed, "body-1": xmlsec.ErrAmbiguousID} {
			if _, err := add(id); !errors.Is(err, want) {
				t.Errorf("%s(%q): got %v, want %v", name, id, err, want)
			}
		}
		if got, err := add(name); err != nil || got != name {
			t.Errorf("%s: %q, %v", name, got, err)
		}
		if _, err := FindByID(doc.Root(), name); err != nil {
			t.Errorf("%s: the element does not carry its ID: %v", name, err)
		}
	}
}

func TestWithID(t *testing.T) {
	str := NewEncryptedKeyReference("ek-1")
	c, id, err := WithID(str, "str-1")
	if err != nil || id != "str-1" || xmltree.AttrValue(c, xmlsec.NSWSU, "Id") != "str-1" || str.Attr(xmlsec.NSWSU, "Id") != nil {
		t.Fatalf("WithID = %v, %q, %v", c, id, err)
	}
	if again, got, err := WithID(c, "other"); err != nil || again != c || got != "str-1" {
		t.Fatalf("an element with an ID: %v, %q, %v", again, got, err)
	}
	if _, id, err := WithID(NewEncryptedKeyReference("ek-1"), ""); err != nil || !strings.HasPrefix(id, "id-") {
		t.Fatalf("minted: %q, %v", id, err)
	}

	ed := xdm.NewNode(xdm.KindElement, xdm.QName{Prefix: "xenc", URI: xmlsec.NSXEnc, Local: "EncryptedData"}, "")
	if c, _, err := WithID(ed, "ed-1"); err != nil || xmltree.AttrValue(c, "", "Id") != "ed-1" {
		t.Fatalf("xenc element: %v", err)
	}

	clash := xdm.NewNode(xdm.KindElement, xdm.QName{Local: "x"}, "")
	clash.AddNamespace("wsu", "urn:other")
	for name, el := range map[string]*xdm.Node{
		"nil":      nil,
		"text":     xdm.NewNode(xdm.KindText, xdm.QName{}, "t"),
		"attached": c.FirstChild(),
		"clash":    clash,
	} {
		if _, _, err := WithID(el, "a"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, err := WithID(NewEncryptedKeyReference("ek-1"), "1bad"); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("non-NCName: %v", err)
	}
}
