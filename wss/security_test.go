package wss

import (
	"io"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

func parseDoc(t *testing.T, s string) *xdm.Node {
	t.Helper()
	tree, err := xmlsec.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return tree.Root
}

const (
	env12 = `<env:Envelope xmlns:env="` + NSSOAP12 + `"><env:Body/></env:Envelope>`
	// wsu is bound to an unrelated namespace on the document element.
	envWSUClash  = `<soap:Envelope xmlns:soap="` + NSSOAP11 + `" xmlns:wsu="urn:other"><soap:Body/></soap:Envelope>`
	envWSSEClash = `<soap:Envelope xmlns:soap="` + NSSOAP11 + `" xmlns:wsse="urn:other"><soap:Body/></soap:Envelope>`
)

func TestNewHeaderErrors(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		ns   string
	}{
		{"unknown SOAP namespace", env11, "urn:not-soap"},
		{"not a SOAP document", `<a/>`, NSSOAP11},
		{"SOAP version mismatch", env11, NSSOAP12},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewHeader(parseDoc(t, c.doc), c.ns, "", false); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestNewHeaderSOAP12(t *testing.T) {
	doc := parseDoc(t, env12)
	h, err := NewHeader(doc, NSSOAP12, "urn:role", true)
	if err != nil {
		t.Fatal(err)
	}
	sec := h.Element()
	if !sec.IsElement(NSWSSE, "Security") {
		t.Fatalf("Element() = %v", sec.Name)
	}
	if got := xmltree.AttrValue(sec, NSSOAP12, "role"); got != "urn:role" {
		t.Errorf("role = %q", got)
	}
	if got := xmltree.AttrValue(sec, NSSOAP12, "mustUnderstand"); got != "true" {
		t.Errorf("mustUnderstand = %q", got)
	}
	if xmltree.AttrValue(sec, NSSOAP12, "actor") != "" {
		t.Error("SOAP 1.2 header carries actor")
	}
	env := xmltree.DocumentElement(doc)
	if kids := env.ChildElements(); len(kids) != 2 || !kids[0].IsElement(NSSOAP12, "Header") {
		t.Fatal("Header not inserted before Body")
	}

	// A second header for a different role reuses the existing Header;
	// the same role again is refused.
	if _, err := NewHeader(doc, NSSOAP12, "", false); err != nil {
		t.Fatal(err)
	}
	if n := len(env.ChildElements()); n != 2 {
		t.Fatalf("%d children of Envelope, want existing Header reused", n)
	}
	if n := len(env.ChildElements()[0].ChildElements()); n != 2 {
		t.Fatalf("%d Security headers, want 2", n)
	}
	if _, err := NewHeader(doc, NSSOAP12, "urn:role", false); err == nil {
		t.Fatal("duplicate role accepted")
	}
}

func TestAppend(t *testing.T) {
	h, err := NewHeader(parseDoc(t, env11), NSSOAP11, "", false)
	if err != nil {
		t.Fatal(err)
	}
	el := xmltree.Element(nil, "", "", "x")
	if err := h.Append(el); err != nil {
		t.Fatal(err)
	}
	if el.Parent != h.Element() {
		t.Fatal("not appended to Security")
	}
	if err := h.Append(el); err == nil {
		t.Fatal("already-parented element accepted")
	}
}

// A wsu or wsse prefix bound to another namespace higher up is not an error:
// each new element declares its own binding, so the output still resolves
// every prefix to the right namespace once reparsed.
func TestPrefixBoundElsewhere(t *testing.T) {
	for name, src := range map[string]string{"wsu": envWSUClash, "wsse": envWSSEClash} {
		t.Run(name, func(t *testing.T) {
			doc := parseDoc(t, src)
			h, err := NewHeader(doc, NSSOAP11, "", false)
			if err != nil {
				t.Fatal(err)
			}
			tok, err := h.AddBinarySecurityToken(testCert(t, "c"), nil, xmlsec.BSTValueTypeX509v3)
			if err != nil {
				t.Fatal(err)
			}
			ts, err := h.AddTimestamp(time.Unix(0, 0), 0)
			if err != nil {
				t.Fatal(err)
			}
			out, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10})
			if err != nil {
				t.Fatal(err)
			}
			re := parseDoc(t, string(out))
			for _, id := range []string{tok, ts} {
				el, err := FindByID(re, id)
				if err != nil {
					t.Fatalf("%s: %v\n%s", id, err, out)
				}
				if el.Parent == nil || !el.Parent.IsElement(NSWSSE, "Security") {
					t.Fatalf("%s is not under wsse:Security:\n%s", id, out)
				}
			}
		})
	}
}

func (failReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
