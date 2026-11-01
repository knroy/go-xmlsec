package xenc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/idref"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
)

// The decrypt paths as they were before splice, verbatim: the reference
// splice is held to, octet for octet and error for error.

func oldParseIn(plaintext []byte, parent *xdm.Node) ([]*xdm.Node, error) {
	var b bytes.Buffer
	b.WriteString("<w")
	ns := parent.InScopeNamespaces()
	for _, p := range slices.Sorted(maps.Keys(ns)) {
		switch p {
		case "xml":
		case "":
			fmt.Fprintf(&b, ` xmlns="%s"`, attrEscaper.Replace(ns[p]))
		default:
			fmt.Fprintf(&b, ` xmlns:%s="%s"`, p, attrEscaper.Replace(ns[p]))
		}
	}
	b.WriteByte('>')
	b.Write(plaintext)
	b.WriteString("</w>")
	tree, err := xmlsec.Parse(b.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%w: parsing the decrypted octets: %w", xmlsec.ErrMalformed, err)
	}
	return slices.Collect(tree.Root.FirstChild().Children()), nil
}

func oldDecryptAndReplace(doc, ed *xdm.Node, key []byte, opts DecryptOptions) ([]byte, error) {
	if err := checkTarget(doc, ed); err != nil {
		return nil, err
	}
	typ := ed.AttrValue("Type")
	if typ != TypeElement && typ != TypeContent {
		return nil, unsupported("EncryptedData Type %q: DecryptAndReplace replaces Element and Content", typ)
	}
	pt, err := DecryptData(ed, key, opts)
	if err != nil {
		return nil, err
	}
	nodes, err := oldParseIn(pt, ed.Parent())
	if err != nil {
		return nil, errDecrypt
	}
	if (typ == TypeElement || ed.Parent().Kind() == xdm.KindDocument) && (len(nodes) != 1 || nodes[0].Kind() != xdm.KindElement) {
		return nil, errDecrypt
	}
	var e xmltree.Edits
	e.ReplaceNode(ed, nodes...)
	return emit(doc, &e)
}

func oldDecryptHeader(doc, eh *xdm.Node, sessionKey []byte, opts DecryptOptions) ([]byte, error) {
	// The checks before decryption are unchanged.
	pt, err := DecryptData(eh.ChildElements()[0], sessionKey, opts)
	if err != nil {
		return nil, err
	}
	nodes, err := oldParseIn(pt, eh)
	if err != nil || len(nodes) != 1 || nodes[0].Kind() != xdm.KindElement {
		return nil, errDecrypt
	}
	block := nodes[0]
	var e xmltree.Edits
	e.ReplaceNode(eh, block)
	ns := eh.InScopeNamespaces()
	for _, p := range slices.Sorted(maps.Keys(ns)) {
		declared := false
		for q := range block.DeclaredNamespaces() {
			declared = declared || q == p
		}
		if p != "xml" && ns[p] != "" && !declared {
			e.Declare(block, p, ns[p])
		}
	}
	// Not in v2.0.1, which lost an xmlns="" in eh's context under a
	// parent with a default namespace (TestDecryptHeaderUndeclaredDefault).
	if _, ok := ns[""]; !ok && eh.Parent().InScopeNamespaces()[""] != "" {
		declared := false
		for q := range block.DeclaredNamespaces() {
			declared = declared || q == ""
		}
		if !declared {
			e.Declare(block, "", "")
		}
	}
	return emit(doc, &e)
}

var spliceKey = bytes.Repeat([]byte{7}, 16)

// spliceED is an EncryptedData of Type typ holding plaintext.
func spliceED(typ, plaintext string) string {
	b, _ := aes.NewCipher(spliceKey)
	a, _ := cipher.NewGCM(b)
	iv := make([]byte, 12)
	return `<xenc:EncryptedData xmlns:xenc="` + xmlsec.NSXEnc + `" Type="` + typ + `"><xenc:EncryptionMethod Algorithm="` +
		xmlsec.EncAES128GCM + `"/><xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(a.Seal(iv, iv, []byte(plaintext), nil)) +
		`</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>`
}

func spliceParse(t *testing.T, s string) *xdm.Node {
	t.Helper()
	tree, err := xmlsec.Parse([]byte(s))
	if err != nil {
		t.Fatalf("%v\n%s", err, s)
	}
	return tree.Root
}

func firstEl(n *xdm.Node, local string) *xdm.Node {
	var found *xdm.Node
	xmltree.Walk(n, func(e *xdm.Node) {
		if found == nil && e.Name().Local == local {
			found = e
		}
	})
	return found
}

// sameDecrypt checks that DecryptAndReplace, or DecryptHeader when ed's
// parent is an EncryptedHeader, gives what the old path gives, and
// reports whether splice made it.
func sameDecrypt(t *testing.T, name string, doc *xdm.Node) (spliced bool) {
	return sameDecryptSeeded(t, name, doc, func() {})
}

// sameDecryptSeeded is sameDecrypt calling seed before each splice.
func sameDecryptSeeded(t *testing.T, name string, doc *xdm.Node, seed func()) (spliced bool) {
	t.Helper()
	ed := firstEl(doc, "EncryptedData")
	var got, want []byte
	var gerr, werr error
	if eh := ed.Parent(); eh.IsElement(xmlsec.NSWSSE11, "EncryptedHeader") {
		seed()
		got, gerr = DecryptHeader(doc, eh, spliceKey, DecryptOptions{})
		want, werr = oldDecryptHeader(doc, eh, spliceKey, DecryptOptions{})
		seed()
		if pt, err := DecryptData(ed, spliceKey, DecryptOptions{}); err == nil {
			if nodes, err := parseIn(pt, eh, eh.Parent()); err == nil && len(nodes) == 1 {
				_, spliced = splice(doc, eh, nodes, len(pt))
			}
		}
	} else {
		seed()
		got, gerr = DecryptAndReplace(doc, ed, spliceKey, DecryptOptions{})
		want, werr = oldDecryptAndReplace(doc, ed, spliceKey, DecryptOptions{})
		seed()
		if pt, err := DecryptData(ed, spliceKey, DecryptOptions{}); err == nil && ed.Parent().Kind() == xdm.KindElement {
			if nodes, err := parseIn(pt, ed.Parent()); err == nil {
				_, spliced = splice(doc, ed, nodes, len(pt))
			}
		}
	}
	if !bytes.Equal(got, want) || fmt.Sprint(gerr) != fmt.Sprint(werr) {
		t.Errorf("%s:\n got %s, %v\nwant %s, %v", name, got, gerr, want, werr)
	}
	return spliced
}

// spliceDocs are the documents of the decrypt tests, and namespace edge
// cases: default namespaces, xmlns="", prefixes shadowed at the parent,
// comments, PIs, entity-like text, and a namespace URI holding a quote
// and a '>'.
var spliceDocs = []string{
	`<!--head--><Document xmlns="http://example.org/" xmlns:p="urn:p&amp;q"><p:a x="1">text<b/><!--c--></p:a>` +
		`<ToBeEncrypted xmlns="" a="1"><c/></ToBeEncrypted><s>mixed <i>content</i> <?pi x?></s></Document>`,
	`<S:Envelope xmlns:S="` + xmlsec.NSSOAP11 + `" xmlns:q="urn:q"><S:Header><wsse:Security xmlns:wsse="` + xmlsec.NSWSSE + `" S:mustUnderstand="1"></wsse:Security>` +
		`<m:Block xmlns:m="urn:m" q:a="1">v<!--c--></m:Block><n></n></S:Header><S:Body></S:Body></S:Envelope>`,
	`<S:Envelope xmlns:S="` + xmlsec.NSSOAP12 + `"><S:Header xmlns="urn:h"><wsse:Security xmlns:wsse="` + xmlsec.NSWSSE + `"/>` +
		`<b xmlns="">v</b><c>w</c><p:d xmlns:p="urn:p"><p:e xmlns:p="urn:p2"/></p:d></S:Header><S:Body xmlns="urn:d">` + "\n" +
		`<Payload xmlns=""><item id="x">a &amp; b</item></Payload>` + "\n" + `</S:Body></S:Envelope>`,
	`<r xmlns="urn:d"><a xmlns=""><b/>t</a><c><d xmlns="urn:e"/></c></r>`,
	`<r xmlns:p="urn:1"><s xmlns:p="urn:2"><p:x p:y="1"/><t/></s><p:u/></r>`,
	`<r><s>&amp;lt; &#x3C; <!--c--><?pi d?> <![CDATA[<x>&]]>` + "\r\n" + `</s><e/></r>`,
	`<r xmlns:q='urn:x"y>z&amp;&#9;'><s q:a="1">text<!--c--><q:t/><?pi?>tail</s></r>`,
	`<r xml:lang="en" xml:space="preserve"><s xml:lang="fr"><t a="&#10;"/></s></r>`,
}

// The plaintexts of EncryptedData other encryptors write: not canonical,
// and in every namespace shape.
var splicePlaintexts = []string{
	`<a/>`, `<a b='1' c="&quot;&lt;&#x9;>"/>`, `<a>&#x41;&amp;lt;<![CDATA[<x>&]]></a>`, `<a xmlns=""/>`,
	`<a xmlns="urn:z"><b xmlns=""/></a>`, `<p:a xmlns:p="urn:other"><p:b/></p:a>`, `<p:a/>`, `<q:a/>`,
	`<!--c--><?pi x?>text<a/>`, "  <a/>\r\n  ", `<a xml:lang="de"/>`, `<a z="1" a="2" xmlns:b="urn:b" b:c="3"/>`,
	``, `text`, `<a/><b/>`, `</w><w>`, `<a>`, `<a/></w><w>`,
}

func TestSpliceMatchesEmit(t *testing.T) {
	opts := EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM}
	n, spliced := 0, 0
	check := func(name string, doc *xdm.Node) {
		n++
		if sameDecrypt(t, name, doc) {
			spliced++
		}
	}
	// Every element of every document, encrypted every way that applies.
	for i, src := range spliceDocs {
		doc := spliceParse(t, src)
		var sec *xdm.Node
		xmltree.Walk(doc, func(e *xdm.Node) {
			if e.IsElement(xmlsec.NSWSSE, "Security") {
				sec = e
			}
		})
		var els []*xdm.Node
		xmltree.Walk(doc, func(e *xdm.Node) { els = append(els, e) })
		for j, el := range els {
			for k, encrypt := range []func() ([]byte, error){
				func() ([]byte, error) { return EncryptElement(doc, el, spliceKey, opts) },
				func() ([]byte, error) { return EncryptContent(doc, el, spliceKey, opts) },
				func() ([]byte, error) { return EncryptHeader(doc, el, sec, spliceKey, opts) },
			} {
				if out, err := encrypt(); err == nil {
					check(fmt.Sprintf("doc %d element %d way %d", i, j, k), spliceParse(t, string(out)))
				}
			}
		}
	}
	// Each plaintext in each context, as an element and as content.
	for i, ctx := range []string{
		`<r>ED</r>`, `<r xmlns="urn:d">ED</r>`, `<r xmlns="urn:d"><s xmlns="">ED</s></r>`,
		`<r xmlns:p="urn:p"><s xmlns:p="urn:q">ED</s></r>`, `<r xmlns:q='urn:x"y>z&amp;&#9;'><s>text<!--c-->ED<?pi?>tail</s></r>`,
		`<r xml:lang="en" xml:space="preserve"><s>ED</s></r>`,
	} {
		for j, pt := range splicePlaintexts {
			for _, typ := range []string{TypeElement, TypeContent} {
				check(fmt.Sprintf("context %d plaintext %d %s", i, j, typ), spliceParse(t, strings.Replace(ctx, "ED", spliceED(typ, pt), 1)))
			}
		}
	}
	// Each block in each EncryptedHeader context.
	for i, c := range [][2]string{
		{``, ``}, {`xmlns="urn:h"`, `xmlns=""`}, {`xmlns="urn:h"`, `xmlns="urn:e"`}, {``, `xmlns="urn:e"`},
		{`xmlns:p="urn:1"`, `xmlns:p="urn:2"`}, {`xmlns:q='a"b>c'`, `xmlns:z="urn:z"`}, {`xmlns:p="urn:1"`, `xmlns:p="urn:1"`},
	} {
		for j, pt := range append(splicePlaintexts, `<p:b/>`, `<z:b xmlns:z="urn:zz"/>`, `<b xmlns="urn:own"/>`, `<z:b/>`) {
			doc := `<S:Envelope xmlns:S="` + xmlsec.NSSOAP11 + `"><S:Header ` + c[0] + `><wsse:Security xmlns:wsse="` + xmlsec.NSWSSE + `"/>` +
				`<wsse11:EncryptedHeader xmlns:wsse11="` + xmlsec.NSWSSE11 + `" ` + c[1] + `>` + spliceED(TypeElement, pt) +
				`</wsse11:EncryptedHeader></S:Header><S:Body/></S:Envelope>`
			check(fmt.Sprintf("header %d plaintext %d", i, j), spliceParse(t, doc))
		}
	}
	// Around the canonicalization depth limit, which the old path checks
	// on the whole document, and the parse limit, which a nested parse
	// reaches first.
	nest := func(n int, in string) string {
		return strings.Repeat("<a>", n) + in + strings.Repeat("</a>", n)
	}
	for _, d := range []int{1, 10, 490} {
		for k := 490 - d; k <= 512-d; k++ {
			check(fmt.Sprintf("depth %d+%d", d, k), spliceParse(t, nest(d, spliceED(TypeElement, nest(k, "")))))
		}
	}
	check("deep elsewhere", spliceParse(t, `<r>`+nest(600, "")+spliceED(TypeElement, `<a/>`)+`</r>`))
	for k := 995; k <= 1001; k++ {
		check(fmt.Sprintf("header depth %d", k), spliceParse(t, `<S:Envelope xmlns:S="`+xmlsec.NSSOAP11+`"><S:Header>`+
			`<wsse11:EncryptedHeader xmlns:wsse11="`+xmlsec.NSWSSE11+`">`+spliceED(TypeElement, nest(k, ""))+
			`</wsse11:EncryptedHeader></S:Header></S:Envelope>`))
	}
	t.Logf("splice made %d of %d outputs", spliced, n)
	if spliced < n/2 {
		t.Errorf("splice made %d of %d outputs", spliced, n)
	}
}

// When the random comment splice marks the EncryptedData's place with is
// already in the document, or the content does not canonicalize, the old
// path gives the output.
func TestSpliceFallback(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 1)
	mark := randomID()
	doc := spliceParse(t, `<r><!--`+mark+`-->`+spliceED(TypeElement, `<a/>`)+`</r>`)
	if sameDecryptSeeded(t, "marker in the document", doc, func() { cryptotest.SetGlobalRandom(t, 1) }) {
		t.Error("spliced around a second marker")
	}

	defer func(d int) { c14n.MaxDepth = d }(c14n.MaxDepth)
	c14n.MaxDepth = 3
	if sameDecrypt(t, "content too deep", spliceParse(t, `<r>`+spliceED(TypeElement, `<a><b><c><d/></c></b></a>`)+`</r>`)) {
		t.Error("spliced content that does not canonicalize")
	}
}

// A CipherValue marker the document already holds is refused, not written
// in two places.
func TestEmitCipherMarker(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 1)
	rand.Read(make([]byte, ivSize))
	doc := spliceParse(t, `<r><a/><b>`+randomID()+`</b></r>`)
	cryptotest.SetGlobalRandom(t, 1)
	a := firstEl(doc, "a")
	if out, err := EncryptElement(doc, a, spliceKey, EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM}); err == nil {
		t.Fatalf("encrypted around a second marker: %s", out)
	}
}

// oldDecode64 is decode64 as it was before it decoded in place.
func oldDecode64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil, malformed("CipherReference content: %v", err)
	}
	return b, nil
}

// decode64 gives what it gave when it joined its text, for text in one
// piece or several, valid or not, with white space of every kind.
func TestDecode64MatchesOld(t *testing.T) {
	long := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("0123456789"), 1000))
	var wrapped strings.Builder
	for s := long; len(s) > 0; s = s[min(76, len(s)):] {
		wrapped.WriteString(s[:min(76, len(s))] + "\r\n")
	}
	for _, s := range []string{
		"", " \t\r\n", "AAAA", "AA==", "A", "AA==AA==", "AA== ", "AA==\nAAAA", "AA AA", "AA\vAA", "AA\fAA",
		"AA AA", "AA\u0085AA", "AA　AA", "AA\xffAA", "AA!A", "é", long, wrapped.String(), wrapped.String() + "!",
		long[:4092] + "AA==" + long[:4], long[:4094] + " " + long[:8], long[:4096] + "\v",
	} {
		want, werr := oldDecode64(s)
		for i := 0; i <= len(s); i += max(1, len(s)/7) {
			got, err := decode64(s[:i], s[i:])
			gotb, errb := decode64([]byte(s))
			if !bytes.Equal(got, want) || !bytes.Equal(gotb, want) || fmt.Sprint(err) != fmt.Sprint(werr) || fmt.Sprint(errb) != fmt.Sprint(werr) {
				t.Fatalf("%.40q at %d: got %x, %v and %x, %v; want %x, %v", s, i, got, err, gotb, errb, want, werr)
			}
		}
	}
}

// oldReferencedData is ReferencedData as it was, a document walk per
// reference.
func oldReferencedData(list *xdm.Node) ([]*xdm.Node, error) {
	if list == nil || !list.IsElement(xmlsec.NSXEnc, "ReferenceList") {
		return nil, malformed("not an xenc:ReferenceList")
	}
	var out []*xdm.Node
	for _, r := range list.ChildElements() {
		if r.IsElement(xmlsec.NSXEnc, "KeyReference") {
			continue
		}
		if !r.IsElement(xmlsec.NSXEnc, "DataReference") {
			return nil, malformed("%s in an xenc:ReferenceList", r.Name().Local)
		}
		uri := r.AttrValue("URI")
		id, ok := strings.CutPrefix(uri, "#")
		if !ok || id == "" {
			return nil, malformed("xenc:DataReference URI %q is not a local #id", uri)
		}
		t, err := idref.Find(list, id, idAttr)
		if err != nil {
			return nil, err
		}
		if t.IsElement(xmlsec.NSWSSE11, "EncryptedHeader") {
			if kids := t.ChildElements(); len(kids) == 1 {
				t = kids[0]
			}
		}
		if !t.IsElement(xmlsec.NSXEnc, "EncryptedData") {
			return nil, malformed("xenc:DataReference %q names a %s, not an xenc:EncryptedData", uri, t.Name().Local)
		}
		if slices.Contains(out, t) {
			return nil, malformed("xenc:DataReference %q listed twice", uri)
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, malformed("an xenc:ReferenceList without xenc:DataReference")
	}
	return out, nil
}

// ReferencedData's one walk finds and refuses what a walk per reference
// did, with the same errors in the same order.
func TestReferencedDataMatchesOld(t *testing.T) {
	ed := func(attr string) string {
		return `<xenc:EncryptedData ` + attr + `/>`
	}
	ref := func(uri string) string { return `<xenc:DataReference URI="` + uri + `"/>` }
	body := ed(`Id="a"`) + ed(`wsu:Id="b"`) + ed(`xml:id="c"`) + ed(`Id="d"`) + `<x Id="d"/>` + ed(`Id="e" wsu:Id="e"`) +
		`<wsse11:EncryptedHeader wsu:Id="h">` + ed(`Id="f"`) + `</wsse11:EncryptedHeader><x Id="g"/>` + ed(`Other="z"`)
	for _, refs := range []string{
		ref("#a") + ref("#b") + ref("#c") + ref("#h") + ref("#f"),
		ref("#a") + `<xenc:KeyReference URI="#nope"/>` + ref("#b"),
		ref("#a") + ref("#d"), ref("#a") + ref("#e"), ref("#a") + ref("#z"), ref("#g"), ref("#a") + ref("#a"),
		ref("#h") + ref("#f"), ref("a") + ref("#nope"), ref("#nope") + ref("a"), ref("#") + ref("#a"),
		ref("#nope") + ref("#d"), ref("#d") + ref("#nope"), `<xenc:KeyReference URI="#a"/>`, ``, `<x/>`, ref("#a") + `<x/>`,
	} {
		doc := spliceParse(t, `<r xmlns:xenc="`+xmlsec.NSXEnc+`" xmlns:wsu="`+xmlsec.NSWSU+`" xmlns:wsse11="`+xmlsec.NSWSSE11+`">`+
			body+`<xenc:ReferenceList>`+refs+`</xenc:ReferenceList></r>`)
		list := firstEl(doc, "ReferenceList")
		got, err := ReferencedData(list)
		want, werr := oldReferencedData(list)
		if !slices.Equal(got, want) || fmt.Sprint(err) != fmt.Sprint(werr) {
			t.Errorf("%s: got %v, %v; want %v, %v", refs, got, err, want, werr)
		}
	}
}

// A ReferenceList of many references costs one walk of the document, not
// one per reference: 20000 took the walk per reference 6 s, and take one
// walk under 0.1 s.
func TestReferencedDataLinear(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<r xmlns:xenc="` + xmlsec.NSXEnc + `">`)
	const n = 20000
	for i := range n {
		fmt.Fprintf(&b, `<xenc:EncryptedData Id="d%d"/>`, i)
	}
	b.WriteString(`<xenc:ReferenceList>`)
	for i := range n {
		fmt.Fprintf(&b, `<xenc:DataReference URI="#d%d"/>`, i)
	}
	b.WriteString(`</xenc:ReferenceList></r>`)
	list := firstEl(spliceParse(t, b.String()), "ReferenceList")
	start := time.Now()
	got, err := ReferencedData(list)
	if err != nil || len(got) != n {
		t.Fatalf("%d, %v", len(got), err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("%d references took %v", n, d)
	}
}

// A document that does not canonicalize is refused as before.
func TestEmitCipherDeep(t *testing.T) {
	doc := spliceParse(t, `<r><a/>`+strings.Repeat("<d>", 600)+strings.Repeat("</d>", 600)+`</r>`)
	if _, err := EncryptElement(doc, firstEl(doc, "a"), spliceKey, EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM}); !errors.Is(err, c14n.ErrDepthExceeded) {
		t.Fatal(err)
	}
}

// XML Encryption 1.1 section 4.5.4: an EncryptedHeader that undeclares the
// default namespace its SOAP Header binds gives its block no namespace, in
// the spliced output and in the fallback, which a marker comment forces.
func TestDecryptHeaderUndeclaredDefault(t *testing.T) {
	for _, c := range []struct {
		forceFallback bool
		plaintext     string
	}{{false, `<a><b/></a>`}, {true, `<a><b/></a>`}, {true, `<a xmlns:p="urn:p"><b/></a>`}} {
		forceFallback := c.forceFallback
		cryptotest.SetGlobalRandom(t, 1)
		mark := ""
		if forceFallback {
			mark = "<!--" + randomID() + "-->"
			cryptotest.SetGlobalRandom(t, 1)
		}
		doc := spliceParse(t, `<S:Envelope xmlns:S="`+xmlsec.NSSOAP11+`"><S:Header xmlns="urn:h">`+mark+
			`<wsse11:EncryptedHeader xmlns:wsse11="`+xmlsec.NSWSSE11+`" xmlns="">`+spliceED(TypeElement, c.plaintext)+
			`</wsse11:EncryptedHeader></S:Header><S:Body/></S:Envelope>`)
		out, err := DecryptHeader(doc, firstEl(doc, "EncryptedHeader"), spliceKey, DecryptOptions{})
		if err != nil {
			t.Fatal(err)
		}
		got := spliceParse(t, string(out))
		for _, local := range []string{"a", "b"} {
			if uri := firstEl(got, local).Name().URI; uri != "" {
				t.Errorf("fallback %v: %s in namespace %q\n%s", forceFallback, local, uri, out)
			}
		}
	}
}
