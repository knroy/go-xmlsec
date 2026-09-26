package wss

import (
	"io"
	"slices"
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

// An Envelope in the default namespace has no prefix for the SOAP
// attributes to take; the header declares one, so that mustUnderstand and
// actor/role are still SOAP attributes once serialized and reparsed.
func TestNewHeaderDefaultNamespace(t *testing.T) {
	for _, c := range []struct{ ns, actorAttr, mu, prefix string }{
		{NSSOAP11, "actor", "1", "soap"},
		{NSSOAP12, "role", "true", "env"},
	} {
		t.Run(c.prefix, func(t *testing.T) {
			doc := parseDoc(t, `<Envelope xmlns="`+c.ns+`"><Body/></Envelope>`)
			if _, err := NewHeader(doc, c.ns, "urn:r", true); err != nil {
				t.Fatal(err)
			}
			out, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10})
			if err != nil {
				t.Fatal(err)
			}
			env := xmltree.DocumentElement(parseDoc(t, string(out)))
			hdr := env.ChildElements()[0]
			if !hdr.IsElement(c.ns, "Header") || hdr.Name.Prefix != "" {
				t.Fatalf("Header %v:\n%s", hdr.Name, out)
			}
			sec := hdr.ChildElements()[0]
			if xmltree.AttrValue(sec, c.ns, "mustUnderstand") != c.mu || xmltree.AttrValue(sec, c.ns, c.actorAttr) != "urn:r" {
				t.Fatalf("SOAP attributes lost:\n%s", out)
			}
			if a := sec.Attr(c.ns, "mustUnderstand"); a.Name.Prefix != c.prefix {
				t.Errorf("prefix %q, want %q", a.Name.Prefix, c.prefix)
			}
		})
	}
}

// One header per recipient: SOAP 1.2's ultimateReceiver role is the
// recipient of a header without a role; SOAP 1.1's next actor is not.
func TestNewHeaderSameRecipient(t *testing.T) {
	const ult = "http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver"
	for _, order := range [][2]string{{"", ult}, {ult, ""}, {ult, ult}} {
		doc := parseDoc(t, env12)
		if _, err := NewHeader(doc, NSSOAP12, order[0], false); err != nil {
			t.Fatal(err)
		}
		if _, err := NewHeader(doc, NSSOAP12, order[1], false); err == nil {
			t.Errorf("%q then %q accepted", order[0], order[1])
		}
	}
	doc := parseDoc(t, env11)
	for _, actor := range []string{"", "http://schemas.xmlsoap.org/soap/actor/next", ult} {
		if _, err := NewHeader(doc, NSSOAP11, actor, false); err != nil {
			t.Errorf("SOAP 1.1 actor %q: %v", actor, err)
		}
	}
}

// childNames lists the header's children as local name, '#', and wsu:Id or
// Id.
func childNames(h *Header) []string {
	var out []string
	for _, e := range h.Element().ChildElements() {
		out = append(out, e.Name.Local+"#"+xmltree.AttrValue(e, NSWSU, "Id")+e.AttrValue("Id"))
	}
	return out
}

// usesToken builds a detached ns:local that references tokenID through a
// SecurityTokenReference and, if data is set, lists #data as a
// DataReference, as a ds:Signature or an xenc:EncryptedKey does.
func usesToken(t *testing.T, ns, local, tokenID, data string) *xdm.Node {
	t.Helper()
	el := xmltree.Element(nil, "x", ns, local)
	el.AddNamespace("x", ns)
	if tokenID != "" {
		str, err := NewSecurityTokenReference(nil, tokenID, xmlsec.BSTValueTypeX509v3)
		if err != nil {
			t.Fatal(err)
		}
		xmltree.Element(el, "ds", nsDSig, "KeyInfo").AppendChild(str)
	}
	if data != "" {
		rl := xmltree.Element(el, "xenc", nsXEnc, "ReferenceList")
		xmltree.SetAttr(xmltree.Element(rl, "xenc", nsXEnc, "DataReference"), "", "", "URI", "#"+data)
		// Not a token reference: an attachment by cid.
		xmltree.SetAttr(xmltree.Element(rl, "wsse", NSWSSE, "Reference"), "", "", "URI", "cid:a")
	}
	return el
}

// The natural sign-then-encrypt sequence gives a header a receiver
// processes in order: the timestamp, the recipient's token, the
// EncryptedKey (decrypt), the signer's token, the Signature (verify). Each
// token precedes the references to it (BSP R5205).
func TestPrependOrder(t *testing.T) {
	doc := parseDoc(t, env12)
	h, err := NewHeader(doc, NSSOAP12, "", true)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := h.AddTimestamp(time.Unix(0, 0), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := h.AddBinarySecurityToken(testCert(t, "signer"), nil, xmlsec.BSTValueTypeX509v3)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Prepend(usesToken(t, nsDSig, "Signature", signer, "")); err != nil {
		t.Fatal(err)
	}
	recipient, err := h.AddBinarySecurityToken(testCert(t, "recipient"), nil, xmlsec.BSTValueTypeX509v3)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Prepend(usesToken(t, nsXEnc, "EncryptedKey", recipient, "ED-1")); err != nil {
		t.Fatal(err)
	}
	// A reference list needs no token: it goes first, after the timestamp.
	if err := h.Prepend(usesToken(t, nsXEnc, "ReferenceList", "", "ED-2")); err != nil {
		t.Fatal(err)
	}
	want := []string{"Timestamp#" + ts, "ReferenceList#", "BinarySecurityToken#" + recipient,
		"EncryptedKey#", "BinarySecurityToken#" + signer, "Signature#"}
	if got := childNames(h); !slices.Equal(got, want) {
		t.Fatalf("header order\n got %v\nwant %v", got, want)
	}

	// Without a timestamp, first is first.
	h2, err := NewHeader(parseDoc(t, env11), NSSOAP11, "", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, local := range []string{"B", "A"} {
		if err := h2.Prepend(usesToken(t, "urn:x", local, "", "")); err != nil {
			t.Fatal(err)
		}
	}
	if got := childNames(h2); !slices.Equal(got, []string{"A#", "B#"}) {
		t.Fatalf("got %v", got)
	}
}

func TestPrependRefusals(t *testing.T) {
	h, err := NewHeader(parseDoc(t, env11), NSSOAP11, "", false)
	if err != nil {
		t.Fatal(err)
	}
	parented := xmltree.Element(xmltree.Element(nil, "", "", "p"), "", "", "x")
	for name, el := range map[string]*xdm.Node{
		"nil":      nil,
		"text":     {Kind: xdm.KindText, Value: "t"},
		"parented": parented,
	} {
		if err := h.Prepend(el); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	// A token appended after an EncryptedData: an EncryptedKey that needs
	// the token and lists the EncryptedData cannot precede both (R3208).
	ed := xmltree.Element(nil, "xenc", nsXEnc, "EncryptedData")
	xmltree.SetAttr(ed, "", "", "Id", "ED-1")
	if err := h.Append(ed); err != nil {
		t.Fatal(err)
	}
	tok := xmltree.Element(nil, "wsse", NSWSSE, "BinarySecurityToken")
	xmltree.SetAttr(tok, "wsu", NSWSU, "Id", "late")
	if err := h.Append(tok); err != nil {
		t.Fatal(err)
	}
	before := childNames(h)
	if err := h.Prepend(usesToken(t, nsXEnc, "EncryptedKey", "late", "ED-1")); err == nil {
		t.Fatal("EncryptedKey placed after its EncryptedData")
	}
	if got := childNames(h); !slices.Equal(got, before) {
		t.Fatalf("header changed: %v", got)
	}
}
