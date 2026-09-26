//go:build interop

package interop

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

// kwKey is a session key for opts wrapped under a fresh shared KEK, the
// EncryptedKey naming it "kek" as xmlsec1 finds it.
func kwKey(t *testing.T, opts xenc.EncryptOptions) (*xenc.EncryptedKey, string) {
	t.Helper()
	kek, kekPath := kekFile(t, 16)
	opts.KeyTransportAlgorithm, opts.KeyEncryptionKey = xmlsec.KeyWrapAES128, kek
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	name := xmltree.Element(nil, "ds", xmlsec.NSDSig, "KeyName")
	name.AddNamespace("ds", xmlsec.NSDSig)
	xmltree.Text(name, "kek")
	if err := ek.SetKeyInfo(name); err != nil {
		t.Fatal(err)
	}
	return ek, kekPath
}

// withKeyInfo puts ek in ed's ds:KeyInfo, after its EncryptionMethod.
func withKeyInfo(ed *xdm.Node, ek *xenc.EncryptedKey) {
	ki := xmltree.Element(nil, "ds", xmlsec.NSDSig, "KeyInfo")
	ki.AddNamespace("ds", xmlsec.NSDSig)
	ki.AppendChild(ek.Element)
	ed.AppendChild(ki)
	kids := ed.Children
	ed.Children = append([]*xdm.Node{kids[0], ki}, kids[1:len(kids)-1]...)
}

func canonicalOf(t *testing.T, n *xdm.Node) []byte {
	t.Helper()
	b, err := c14n.Bytes(n, c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// xmlsec1 and Santuario decrypt our EncryptOctets output (section 2.1.4):
// binary octets with a MimeType and no XML Type, the EncryptedData the
// document element.
func TestReferenceImplementationsDecryptOurOctets(t *testing.T) {
	opts := xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, MimeType: "image/png"}
	ek, kekPath := kwKey(t, opts)
	png := []byte("\x89PNG\r\n\x1a\n\x00\x01\xff binary")
	_, ed, err := xenc.EncryptOctets(png, ek.SessionKey, opts)
	if err != nil {
		t.Fatal(err)
	}
	withKeyInfo(ed, ek)
	enc := tempFile(t, "enc.xml", canonicalOf(t, ed))

	out := filepath.Join(t.TempDir(), "xmlsec1.bin")
	run(t, "--decrypt", "--aeskey:kek", kekPath, "--output", out, enc)
	if got := readFile(t, out); !bytes.Equal(got, png) {
		t.Fatalf("xmlsec1: %q", got)
	}
	out = filepath.Join(t.TempDir(), "santuario.bin")
	mustSantuario(t, "decrypt-octets-kw", enc, kekPath, out)
	if got := readFile(t, out); !bytes.Equal(got, png) {
		t.Fatalf("Santuario: %q", got)
	}
}

// xmlsec1 and Santuario decrypt an element whose EncryptedData carries
// xenc:EncryptionProperties after CipherData (section 3.7), and MimeType
// and Encoding.
func TestReferenceImplementationsDecryptOurEncryptionProperties(t *testing.T) {
	prop := parse(t, []byte(`<xenc:EncryptionProperty xmlns:xenc="`+xmlsec.NSXEnc+`" Target="#ED"><t:Date xmlns:t="urn:example:t">2026-09-26</t:Date></xenc:EncryptionProperty>`))
	opts := xenc.EncryptOptions{
		DataAlgorithm: xmlsec.EncAES128GCM, DataID: "ED", MimeType: "text/xml", Encoding: "urn:example:utf-8",
		EncryptionProperties: []*xdm.Node{xmltree.DocumentElement(prop)},
	}
	ek, kekPath := kwKey(t, opts)
	doc := parse(t, []byte(envelope))
	var payload *xdm.Node
	xmltree.Walk(doc, func(e *xdm.Node) {
		if e.Name.Local == "Payload" {
			payload = e
		}
	})
	encrypted, err := xenc.EncryptElement(doc, payload, ek.SessionKey, opts)
	if err != nil {
		t.Fatal(err)
	}
	edoc := parse(t, encrypted)
	ed := find(edoc, xmlsec.NSXEnc, "EncryptedData")
	withKeyInfo(ed, ek)
	if names := func() (s string) {
		for _, k := range ed.ChildElements() {
			s += k.Name.Local + " "
		}
		return
	}(); names != "EncryptionMethod KeyInfo CipherData EncryptionProperties " {
		t.Fatalf("children %s", names)
	}
	enc := tempFile(t, "enc.xml", canonicalOf(t, edoc))

	out := filepath.Join(t.TempDir(), "xmlsec1.xml")
	run(t, "--decrypt", "--aeskey:kek", kekPath, "--output", out, enc)
	assertDecryptedEnvelope(t, readFile(t, out))
	out = filepath.Join(t.TempDir(), "santuario.xml")
	mustSantuario(t, "decrypt-kw", enc, kekPath, out)
	assertDecryptedEnvelope(t, readFile(t, out))
}

// Sections 4.1 and 4.5: xmlsec1 and Santuario encrypt the document element;
// DecryptAndReplace yields, octet for octet, the canonical form of what
// each of them decrypts it to.
func TestWeDecryptAndReplaceTheirDocumentElement(t *testing.T) {
	const src = `<Document xmlns="urn:example:d" xmlns:p="urn:example:p"><p:a x="1">text<b/></p:a><c xmlns="">no namespace</c></Document>`
	kek, kekPath := kekFile(t, 16)
	unwrap := func(ek *xdm.Node) ([]byte, error) {
		return xenc.UnwrapEncryptedKey(ek, kek, xenc.DecryptOptions{AllowedKeyWrapAlgorithms: []string{xmlsec.KeyWrapAES128}})
	}
	check := func(who string, enc []byte, decrypt func(enc, out string)) {
		t.Helper()
		doc := parse(t, enc)
		ed := xmltree.DocumentElement(doc)
		if !ed.IsElement(xmlsec.NSXEnc, "EncryptedData") {
			t.Fatalf("%s did not encrypt the document element:\n%s", who, enc)
		}
		ekEl, err := xenc.FindEncryptedKey(ed)
		if err != nil {
			t.Fatal(err)
		}
		key, err := unwrap(ekEl)
		if err != nil {
			t.Fatal(err)
		}
		ours, err := xenc.DecryptAndReplace(doc, ed, key, xenc.DecryptOptions{})
		if err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "decrypted.xml")
		decrypt(tempFile(t, "enc.xml", enc), out)
		theirs := canonicalOf(t, parse(t, readFile(t, out)))
		if !bytes.Equal(ours, theirs) {
			t.Fatalf("%s:\n ours %s\ntheirs %s", who, ours, theirs)
		}
		if want := canonicalOf(t, parse(t, []byte(src))); !bytes.Equal(ours, want) {
			t.Fatalf("%s: %s, want %s", who, ours, want)
		}
	}

	out := filepath.Join(t.TempDir(), "santuario.xml")
	mustSantuario(t, "encrypt-kw", tempFile(t, "in.xml", []byte(src)), kekPath, "Document", out)
	check("Santuario", readFile(t, out), func(enc, out string) { mustSantuario(t, "decrypt-kw", enc, kekPath, out) })

	tmpl := `<xenc:EncryptedData xmlns:xenc="` + xmlsec.NSXEnc + `" Type="` + xenc.TypeElement + `">` +
		`<xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128GCM + `"/>` +
		`<ds:KeyInfo xmlns:ds="` + xmlsec.NSDSig + `"><xenc:EncryptedKey>` +
		`<xenc:EncryptionMethod Algorithm="` + xmlsec.KeyWrapAES128 + `"/><ds:KeyInfo><ds:KeyName>kek</ds:KeyName></ds:KeyInfo>` +
		`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>` +
		`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>`
	out = filepath.Join(t.TempDir(), "xmlsec1.xml")
	run(t, "--encrypt", "--session-key", "aes-128", "--aeskey:kek", kekPath,
		"--xml-data", tempFile(t, "data.xml", []byte(src)), "--node-name", "urn:example:d:Document",
		"--output", out, tempFile(t, "tmpl.xml", []byte(tmpl)))
	check("xmlsec1", readFile(t, out), func(enc, out string) { run(t, "--decrypt", "--aeskey:kek", kekPath, "--output", out, enc) })
}

// Section 3.3.1, Example 13: a CipherReference whose XPath transform
// selects the base64 text of the ciphertext held elsewhere in the
// document, then base64. xmlsec1, Santuario and DecryptAndReplace, the
// XPath allowed, all decrypt and replace it to the same document.
func TestCipherReferenceXPathDecryptedByAll(t *testing.T) {
	const rep = "http://www.example.org/repository"
	const expr = `self::text()[parent::rep:CipherValue[@Id="example1"]]`
	opts := xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, Type: xenc.TypeElement}
	ek, kekPath := kwKey(t, opts)
	_, inline, err := xenc.EncryptOctets([]byte(`<Payload xmlns="urn:example:d">hello</Payload>`), ek.SessionKey, opts)
	if err != nil {
		t.Fatal(err)
	}
	b64 := firstText(inline, "CipherValue")
	ekXML := string(canonicalOf(t, ek.Element))
	src := `<Document xmlns="urn:example:d" xmlns:rep="` + rep + `"><rep:CipherValue Id="example1">` + b64 + `</rep:CipherValue>` +
		`<xenc:EncryptedData xmlns:xenc="` + xmlsec.NSXEnc + `" xmlns:ds="` + xmlsec.NSDSig + `" Type="` + xenc.TypeElement + `">` +
		`<xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128GCM + `"/><ds:KeyInfo>` + ekXML + `</ds:KeyInfo>` +
		`<xenc:CipherData><xenc:CipherReference URI=""><xenc:Transforms>` +
		`<ds:Transform Algorithm="` + xmlsec.TransformXPath + `"><ds:XPath>` + expr + `</ds:XPath></ds:Transform>` +
		`<ds:Transform Algorithm="` + xmlsec.TransformBase64 + `"/>` +
		`</xenc:Transforms></xenc:CipherReference></xenc:CipherData></xenc:EncryptedData></Document>`
	want := `<Document xmlns="urn:example:d" xmlns:rep="` + rep + `"><rep:CipherValue Id="example1">` + b64 + `</rep:CipherValue><Payload>hello</Payload></Document>`

	doc := parse(t, []byte(src))
	ours, err := xenc.DecryptAndReplace(doc, find(doc, xmlsec.NSXEnc, "EncryptedData"), ek.SessionKey, xenc.DecryptOptions{
		AllowedXPathExpressions: []dsig.XPathExpression{{Expr: expr, Namespaces: map[string]string{"rep": rep}}},
	})
	if err != nil || string(ours) != want {
		t.Fatalf("ours %s, %v\nwant %s", ours, err, want)
	}
	enc := tempFile(t, "enc.xml", []byte(src))
	out := filepath.Join(t.TempDir(), "xmlsec1.xml")
	run(t, "--decrypt", "--aeskey:kek", kekPath, "--output", out, enc)
	if got := canonicalOf(t, parse(t, readFile(t, out))); string(got) != want {
		t.Fatalf("xmlsec1 %s", got)
	}
	out = filepath.Join(t.TempDir(), "santuario.xml")
	mustSantuario(t, "decrypt-kw", enc, kekPath, out)
	if got := canonicalOf(t, parse(t, readFile(t, out))); string(got) != want {
		t.Fatalf("Santuario %s", got)
	}
}

func firstText(n *xdm.Node, local string) string {
	s := ""
	xmltree.Walk(n, func(e *xdm.Node) {
		if s == "" && e.Name.Local == local {
			s = e.StringValue()
		}
	})
	return s
}
