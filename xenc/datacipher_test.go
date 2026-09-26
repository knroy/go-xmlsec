package xenc_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

// covED is an xenc:EncryptedData with the given attributes and content.
func covED(attrs, content string) string {
	return `<xenc:EncryptedData xmlns:xenc="` + xmlsec.NSXEnc + `" ` + attrs + `>` + content + `</xenc:EncryptedData>`
}

func TestDecryptDataErrors(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	em := covEM(xmlsec.EncAES128GCM)
	cv := func(b []byte) string {
		return `<xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(b) + `</xenc:CipherValue></xenc:CipherData>`
	}
	cases := []struct {
		name    string
		el      string
		key     []byte
		allowed []string
		want    error // nil: any error
	}{
		{"not EncryptedData", `<xenc:EncryptedKey xmlns:xenc="` + xmlsec.NSXEnc + `"/>`, key, nil, xmlsec.ErrMalformed},
		{"no EncryptionMethod", covED(``, cv(make([]byte, 40))), key, nil, xmlsec.ErrMalformed},
		{"EncryptionMethod not first", covED(``, cv(make([]byte, 40))+em), key, nil, xmlsec.ErrMalformed},
		{"unknown algorithm", covED(``, covEM("urn:x")+cv(make([]byte, 40))), key, nil, xmlsec.ErrAlgorithmNotAllowed},
		{"CBC algorithm", covED(``, covEM("http://www.w3.org/2001/04/xmlenc#aes128-cbc")+cv(make([]byte, 40))), key, nil, xmlsec.ErrAlgorithmNotAllowed},
		{"allow-listed but unimplemented", covED(``, covEM("urn:x")+cv(make([]byte, 40))), key, []string{"urn:x"}, xmlsec.ErrUnsupportedAlgorithm},
		{"no CipherData", covED(``, em), key, nil, xmlsec.ErrMalformed},
		{"empty CipherData", covED(``, em+`<xenc:CipherData/>`), key, nil, xmlsec.ErrMalformed},
		{"CipherReference", covED(``, em+`<xenc:CipherData><xenc:CipherReference URI="cid:x"/></xenc:CipherData>`), key, nil, xmlsec.ErrMalformed},
		{"CipherValue not base64", covED(``, em+`<xenc:CipherData><xenc:CipherValue>!!</xenc:CipherValue></xenc:CipherData>`), key, nil, xmlsec.ErrMalformed},
		{"short ciphertext", covED(``, em+cv(make([]byte, 27))), key, nil, xmlsec.ErrMalformed},
		{"wrong session key length", covED(``, em+cv(make([]byte, 40))), make([]byte, 24), nil, nil},
		{"authentication failure", covED(``, em+cv(make([]byte, 40))), key, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pt, err := xenc.DecryptData(covParse(t, c.el), c.key, xenc.DecryptOptions{AllowedDataAlgorithms: c.allowed})
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if pt != nil {
				t.Fatal("plaintext returned with an error")
			}
		})
	}
}

func TestEncryptElementErrors(t *testing.T) {
	const src = `<r><a>x</a><rel:b xmlns:rel="relative/uri"/></r>`
	tree, err := xmlsec.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	doc := tree.Root
	root := xmltree.DocumentElement(doc)
	other := covParse(t, `<o><a/></o>`)
	key := bytes.Repeat([]byte{1}, 16)

	cases := []struct {
		name   string
		target *xdm.Node
		key    []byte
		alg    string
		want   error // nil: any error
	}{
		{"target in another document", other.ChildElements()[0], key, xmlsec.EncAES128GCM, nil},
		{"detached target", xmltree.Element(nil, "", "", "d"), key, xmlsec.EncAES128GCM, nil},
		{"target is the document node", doc, key, xmlsec.EncAES128GCM, nil},
		{"target is text", root.ChildElements()[0].Children[0], key, xmlsec.EncAES128GCM, nil},
		{"unknown algorithm", root.ChildElements()[0], key, "urn:x", xmlsec.ErrUnsupportedAlgorithm},
		{"wrong session key length", root.ChildElements()[0], key[:8], xmlsec.EncAES128GCM, nil},
		{"target with no canonical form", root.ChildElements()[1], key, xmlsec.EncAES128GCM, c14n.ErrRelativeNamespaceURI},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := as4Opts(t)
			opts.DataAlgorithm = c.alg
			out, err := xenc.EncryptElement(doc, c.target, c.key, opts)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if out != nil {
				t.Fatal("output returned with an error")
			}
			if len(root.ChildElements()) != 2 || root.ChildElements()[0].Name.Local != "a" {
				t.Fatal("document modified")
			}
		})
	}
}

// Nil input from a failed lookup is an error, never a panic.
func TestNilInputs(t *testing.T) {
	key := make([]byte, 16)
	tree, err := xmlsec.Parse([]byte(`<r><a/></r>`))
	if err != nil {
		t.Fatal(err)
	}
	ek, err := xenc.GenerateEncryptedKey(as4Opts(t))
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]error{}
	_, checks["DecryptEncryptedKey(nil)"] = xenc.DecryptEncryptedKey(nil, recipientKey, xenc.DecryptOptions{})
	_, checks["DecryptEncryptedKey(el, nil)"] = xenc.DecryptEncryptedKey(reparse(t, ek.Element), nil, xenc.DecryptOptions{})
	_, checks["DecryptData(nil)"] = xenc.DecryptData(nil, key, xenc.DecryptOptions{})
	_, checks["DecryptAttachment(nil)"] = xenc.DecryptAttachment(nil, nil, key, xenc.DecryptOptions{})
	_, checks["EncryptElement(nil, nil)"] = xenc.EncryptElement(nil, nil, key, as4Opts(t))
	_, checks["EncryptElement(doc, nil)"] = xenc.EncryptElement(tree.Root, nil, key, as4Opts(t))
	_, _, checks["EncryptAttachment(nil)"] = xenc.EncryptAttachment(nil, key, xmlsec.TransformAttachmentContentOnly, as4Opts(t))
	for name, err := range checks {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// firstNamed returns the first element named local, in document order.
func firstNamed(n *xdm.Node, local string) *xdm.Node {
	var found *xdm.Node
	xmltree.Walk(n.Root(), func(e *xdm.Node) {
		if found == nil && e.Name.Local == local {
			found = e
		}
	})
	return found
}

// decryptIn parses out, decrypts its EncryptedData under key and returns
// the plaintext.
func decryptIn(t *testing.T, out, key []byte) string {
	t.Helper()
	doc := covParse(t, string(out))
	pt, err := xenc.DecryptData(firstNamed(doc, "EncryptedData"), key, xenc.DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return string(pt)
}

// Section 4.5.3.1: an element in no namespace, under a parent with a
// default namespace, carries xmlns="" in its plaintext; decrypted and
// replaced, it stays in no namespace. The other cases are unchanged.
func TestDefaultNamespacePlaintext(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	for _, c := range []struct {
		name, doc, want string
	}{
		{"no namespace under a default", `<Document xmlns="http://example.org/"><ToBeEncrypted xmlns="" a="1"><c/></ToBeEncrypted></Document>`,
			`<ToBeEncrypted xmlns="" a="1"><c></c></ToBeEncrypted>`},
		{"prefixed, no default under a default", `<Document xmlns="http://example.org/"><p:T xmlns="" xmlns:p="urn:p"><c/></p:T></Document>`,
			`<p:T xmlns="" xmlns:p="urn:p"><c></c></p:T>`},
		{"empty element", `<Document xmlns="http://example.org/"><E xmlns=""/></Document>`, `<E xmlns=""></E>`},
		{"same default", `<Document xmlns="http://example.org/"><T/></Document>`, `<T xmlns="http://example.org/"></T>`},
		{"no default anywhere", `<Document><T/></Document>`, `<T></T>`},
	} {
		t.Run(c.name, func(t *testing.T) {
			doc := covParse(t, c.doc)
			out, err := xenc.EncryptElement(doc, doc.ChildElements()[0], key, as4Opts(t))
			if err != nil {
				t.Fatal(err)
			}
			if got := decryptIn(t, out, key); got != c.want {
				t.Fatalf("plaintext %s, want %s", got, c.want)
			}
		})
	}
}

// Section 4.3: element and content plaintext must be NFC, and is refused
// rather than normalized.
func TestNotNFCRefused(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	// "e" followed by U+0301 COMBINING ACUTE ACCENT is NFD for U+00E9.
	for name, src := range map[string]string{
		"text":      "<r><a>café</a></r>",
		"attribute": "<r><a b=\"é\"/></r>",
	} {
		t.Run(name, func(t *testing.T) {
			doc := covParse(t, src)
			if _, err := xenc.EncryptElement(doc, doc.ChildElements()[0], key, as4Opts(t)); !errors.Is(err, xmlsec.ErrNotNFC) {
				t.Fatalf("element: %v", err)
			}
			if _, err := xenc.EncryptContent(doc, doc, key, as4Opts(t)); !errors.Is(err, xmlsec.ErrNotNFC) {
				t.Fatalf("content: %v", err)
			}
		})
	}
	doc := covParse(t, "<r><a>café</a></r>")
	if _, err := xenc.EncryptElement(doc, doc.ChildElements()[0], key, as4Opts(t)); err != nil {
		t.Fatalf("NFC refused: %v", err)
	}
}

func TestEncryptContent(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	src := `<S:Envelope xmlns:S="` + soap12 + `"><S:Body xmlns="urn:d" wsu:Id="b" xmlns:wsu="urn:wsu">` +
		`text &amp; &lt;<!--c--><?pi x?><a xmlns="" q="1"><b/></a><c/>tail</S:Body></S:Envelope>`
	doc := covParse(t, src)
	body := doc.ChildElements()[0]
	opts := as4Opts(t)
	opts.DataID = "ED-c"
	out, err := xenc.EncryptContent(doc, body, key, opts)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10}); !strings.Contains(string(again), "tail") {
		t.Fatal("doc modified")
	}
	enc := covParse(t, string(out))
	ebody := enc.ChildElements()[0]
	// The Body keeps its attributes and holds only the EncryptedData.
	if ebody.AttrValue("") != "" || len(ebody.Children) != 1 || !ebody.Children[0].IsElement(xmlsec.NSXEnc, "EncryptedData") ||
		ebody.Children[0].AttrValue("Type") != xenc.TypeContent || ebody.Children[0].AttrValue("Id") != "ED-c" ||
		!strings.Contains(string(out), `wsu:Id="b"`) {
		t.Fatalf("encrypted:\n%s", out)
	}
	want := `text &amp; &lt;<!--c--><?pi x?><a xmlns="" xmlns:S="` + soap12 + `" xmlns:wsu="urn:wsu" q="1"><b></b></a>` +
		`<c xmlns="urn:d" xmlns:S="` + soap12 + `" xmlns:wsu="urn:wsu"></c>tail`
	if got := decryptIn(t, out, key); got != want {
		t.Fatalf("plaintext\n%s\nwant\n%s", got, want)
	}

	// Empty content encrypts to an empty plaintext.
	doc = covParse(t, `<r><e/></r>`)
	if out, err = xenc.EncryptContent(doc, doc.ChildElements()[0], key, as4Opts(t)); err != nil || decryptIn(t, out, key) != "" {
		t.Fatalf("empty: %v", err)
	}
}

const (
	soap11 = "http://schemas.xmlsoap.org/soap/envelope/"
	soap12 = "http://www.w3.org/2003/05/soap-envelope"
)

func TestEncryptContentErrors(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	doc := covParse(t, `<S:Envelope xmlns:S="`+soap11+`"><S:Header><h/></S:Header><S:Body><b/></S:Body></S:Envelope>`)
	rel := covParse(t, `<r><c><rel:x xmlns:rel="rel"/></c></r>`)
	env := doc
	hdr, body := env.ChildElements()[0], env.ChildElements()[1]
	for name, c := range map[string]struct {
		target *xdm.Node
		opts   func(*xenc.EncryptOptions)
	}{
		"Envelope content":  {env, nil},
		"Header content":    {hdr, nil},
		"not in doc":        {covParse(t, `<o/>`), nil},
		"bad DataID":        {hdr.ChildElements()[0], func(o *xenc.EncryptOptions) { o.DataID = "1" }},
		"unknown algorithm": {hdr.ChildElements()[0], func(o *xenc.EncryptOptions) { o.DataAlgorithm = "urn:x" }},
	} {
		t.Run(name, func(t *testing.T) {
			opts := as4Opts(t)
			if c.opts != nil {
				c.opts(&opts)
			}
			if out, err := xenc.EncryptContent(env, c.target, key, opts); err == nil || out != nil {
				t.Fatalf("got %v", err)
			}
		})
	}
	if _, err := xenc.EncryptContent(rel, rel.ChildElements()[0], key, as4Opts(t)); err == nil {
		t.Fatal("child with no canonical form encrypted")
	}
	// A header block's content, and the Body's, may be encrypted.
	for _, target := range []*xdm.Node{hdr.ChildElements()[0], body.ChildElements()[0]} {
		if _, err := xenc.EncryptContent(env, target, key, as4Opts(t)); err != nil {
			t.Fatal(err)
		}
	}
}

// WS-Security 1.1.1 section 9.4 and WS-I BSP R3228, R5614: Envelope,
// Header and Body are never encrypted, and a header block only as an
// EncryptedHeader.
func TestEncryptElementSOAPGuard(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	for _, ns := range []string{soap11, soap12} {
		doc := covParse(t, `<S:Envelope xmlns:S="`+ns+`"><S:Header><h><x/></h></S:Header><S:Body><b/></S:Body></S:Envelope>`)
		env := doc
		hdr, body := env.ChildElements()[0], env.ChildElements()[1]
		for name, target := range map[string]*xdm.Node{"Header": hdr, "Body": body, "header block": hdr.ChildElements()[0]} {
			if _, err := xenc.EncryptElement(doc, target, key, as4Opts(t)); err == nil {
				t.Errorf("%s %s encrypted", ns, name)
			}
		}
		// Below a header block, and in the Body, elements may be encrypted.
		for _, target := range []*xdm.Node{hdr.ChildElements()[0].ChildElements()[0], body.ChildElements()[0]} {
			if _, err := xenc.EncryptElement(doc, target, key, as4Opts(t)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The Envelope as document element is refused too, by the parent check
	// or the guard, whichever comes first.
	doc := covParse(t, `<S:Envelope xmlns:S="`+soap12+`"><S:Body/></S:Envelope>`)
	if _, err := xenc.EncryptElement(doc.Parent, doc, key, as4Opts(t)); err == nil {
		t.Fatal("Envelope encrypted")
	}
}

func TestDataIDMustBeNCName(t *testing.T) {
	key := make([]byte, 16)
	doc := covParse(t, `<r><a/></r>`)
	for _, id := range []string{"1a", "a:b", "a b", "#a"} {
		opts := as4Opts(t)
		opts.DataID = id
		if _, err := xenc.EncryptElement(doc.Parent, doc.ChildElements()[0], key, opts); err == nil {
			t.Errorf("element %q accepted", id)
		}
		if _, _, err := xenc.EncryptAttachment(&xmlsec.Attachment{ID: "a"}, key, xmlsec.TransformAttachmentContentOnly, opts); err == nil {
			t.Errorf("attachment %q accepted", id)
		}
	}
}

// Section 3.2: an EncryptedData EncryptionMethod may hold only a KeySize
// consistent with the algorithm.
func TestDataEncryptionMethodChildren(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	doc := covParse(t, `<r><a>x</a></r>`)
	out, err := xenc.EncryptElement(doc.Parent, doc.ChildElements()[0], key, as4Opts(t))
	if err != nil {
		t.Fatal(err)
	}
	const em = `<xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128GCM + `">`
	with := func(children string) *xdm.Node {
		s := strings.Replace(string(out), em+`</xenc:EncryptionMethod>`, em+children+`</xenc:EncryptionMethod>`, 1)
		return firstNamed(covParse(t, s), "EncryptedData")
	}
	for name, children := range map[string]string{
		"KeySize 256":       `<xenc:KeySize>256</xenc:KeySize>`,
		"KeySize not a int": `<xenc:KeySize>x</xenc:KeySize>`,
		"KeySize twice":     `<xenc:KeySize>128</xenc:KeySize><xenc:KeySize>128</xenc:KeySize>`,
		"OAEPparams":        `<xenc:OAEPparams>AA==</xenc:OAEPparams>`,
		"DigestMethod":      `<ds:DigestMethod xmlns:ds="` + xmlsec.NSDSig + `" Algorithm="` + xmlsec.DigestSHA256 + `"/>`,
		"unknown":           `<x:Y xmlns:x="urn:x"/>`,
	} {
		if _, err := xenc.DecryptData(with(children), key, xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, ks := range []string{"128", " 128 ", "+128", "0128"} {
		if _, err := xenc.DecryptData(with(`<xenc:KeySize>`+ks+`</xenc:KeySize>`), key, xenc.DecryptOptions{}); err != nil && !strings.Contains(err.Error(), "KeySize") {
			t.Errorf("KeySize %q: %v", ks, err)
		}
	}
	if pt, err := xenc.DecryptData(with(`<xenc:KeySize>128</xenc:KeySize>`), key, xenc.DecryptOptions{}); err != nil || string(pt) != "<a>x</a>" {
		t.Fatalf("consistent KeySize: %s, %v", pt, err)
	}
}

// Section 3.3.1: a same-document CipherReference, "#id" or "", with the
// base64 transform.
func TestSameDocumentCipherReference(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	ct := sealGCM(key, "secret")
	b64 := base64.StdEncoding.EncodeToString(ct)
	ref := func(uri, transforms string) string {
		return covED(`Type="`+xenc.TypeElement+`"`, covEM(xmlsec.EncAES128GCM)+
			`<xenc:CipherData><xenc:CipherReference URI="`+uri+`">`+transforms+`</xenc:CipherReference></xenc:CipherData>`)
	}
	tr := func(algs ...string) string {
		s := `<xenc:Transforms>`
		for _, a := range algs {
			s += `<ds:Transform xmlns:ds="` + xmlsec.NSDSig + `" Algorithm="` + a + `"/>`
		}
		return s + `</xenc:Transforms>`
	}
	base64T := tr(xmlsec.TransformBase64)
	wrap := func(ed string) string {
		return `<r xmlns:wsu="urn:wsu"><v Id="cv">` + b64[:10] + "\n  " + b64[10:] + `</v>` + ed + `</r>`
	}
	for name, doc := range map[string]string{
		"#id":          wrap(ref("#cv", base64T)),
		"whole doc":    `<r>` + b64 + ref("", base64T) + `</r>`,
		"xml:id":       `<r><v xml:id="cv">` + b64 + `</v>` + ref("#cv", base64T) + `</r>`,
		"inline value": `<r>` + covED(``, covEM(xmlsec.EncAES128GCM)+`<xenc:CipherData><xenc:CipherValue>`+b64+`</xenc:CipherValue></xenc:CipherData>`) + `</r>`,
	} {
		t.Run(name, func(t *testing.T) {
			pt, err := xenc.DecryptData(firstNamed(covParse(t, doc), "EncryptedData"), key, xenc.DecryptOptions{})
			if err != nil || string(pt) != "secret" {
				t.Fatalf("%s, %v", pt, err)
			}
		})
	}
	for name, c := range map[string]struct {
		doc  string
		want error
	}{
		"no transforms":      {wrap(ref("#cv", ``)), xmlsec.ErrUnsupportedAlgorithm},
		"two transforms":     {wrap(ref("#cv", tr(xmlsec.TransformBase64, xmlsec.TransformBase64))), xmlsec.ErrUnsupportedAlgorithm},
		"c14n transform":     {wrap(ref("#cv", tr(string(c14n.Exclusive10)))), xmlsec.ErrUnsupportedAlgorithm},
		"XPath":              {wrap(ref("#cv", tr(xmlsec.TransformXPath, xmlsec.TransformBase64))), xmlsec.ErrTransformRefused},
		"XSLT":               {wrap(ref("#cv", tr(xmlsec.TransformXSLT))), xmlsec.ErrTransformRefused},
		"XPath Filter 2":     {wrap(ref("#cv", tr(xmlsec.TransformXPathFilter2))), xmlsec.ErrTransformRefused},
		"missing id":         {wrap(ref("#nope", base64T)), xmlsec.ErrIDNotFound},
		"duplicate id":       {wrap(ref("#cv", base64T) + `<w wsu:Id="cv" xmlns:wsu="` + "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" + `"/>`), xmlsec.ErrAmbiguousID},
		"xpointer":           {wrap(ref("#xpointer(id('cv'))", base64T)), xmlsec.ErrIDNotFound},
		"http":               {wrap(ref("http://example.com/cv", base64T)), xmlsec.ErrMalformed},
		"file":               {wrap(ref("file:///etc/passwd", base64T)), xmlsec.ErrMalformed},
		"cid":                {wrap(ref("cid:a", base64T)), xmlsec.ErrMalformed},
		"not base64":         {`<r><v Id="cv">!!</v>` + ref("#cv", base64T) + `</r>`, xmlsec.ErrMalformed},
		"other child":        {wrap(ref("#cv", `<x:Y xmlns:x="urn:x"/>`)), xmlsec.ErrMalformed},
		"transform params":   {wrap(ref("#cv", `<xenc:Transforms><ds:Transform xmlns:ds="`+xmlsec.NSDSig+`" Algorithm="`+xmlsec.TransformBase64+`"><p/></ds:Transform></xenc:Transforms>`)), xmlsec.ErrMalformed},
		"not ds:Transform":   {wrap(ref("#cv", `<xenc:Transforms><xenc:Transform Algorithm="`+xmlsec.TransformBase64+`"/></xenc:Transforms>`)), xmlsec.ErrMalformed},
		"two CipherRef kids": {wrap(ref("#cv", base64T+base64T)), xmlsec.ErrMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			pt, err := xenc.DecryptData(firstNamed(covParse(t, c.doc), "EncryptedData"), key, xenc.DecryptOptions{})
			if !errors.Is(err, c.want) || pt != nil {
				t.Fatalf("got %s, %v; want %v", pt, err, c.want)
			}
		})
	}
}

// Section 3.3.1: an external CipherReference is fetched only through
// DecryptOptions.ResolveURI, its octets being the ciphertext or, with the
// base64 transform, its encoding.
func TestExternalCipherReference(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	ct := sealGCM(key, "secret")
	b64 := base64.StdEncoding.EncodeToString(ct)
	const uri = "http://example.invalid/ct"
	ref := func(uri, transforms string) string {
		return covED(`Type="`+xenc.TypeElement+`"`, covEM(xmlsec.EncAES128GCM)+
			`<xenc:CipherData><xenc:CipherReference URI="`+uri+`">`+transforms+`</xenc:CipherReference></xenc:CipherData>`)
	}
	tr := func(algs ...string) string {
		s := `<xenc:Transforms>`
		for _, a := range algs {
			s += `<ds:Transform xmlns:ds="` + xmlsec.NSDSig + `" Algorithm="` + a + `"/>`
		}
		return s + `</xenc:Transforms>`
	}
	errGone := errors.New("gone")
	serve := func(b []byte, err error) (xmlsec.URIResolver, *[]string) {
		var calls []string
		return func(u string) ([]byte, error) { calls = append(calls, u); return b, err }, &calls
	}
	for name, c := range map[string]struct {
		ed      string
		body    []byte
		err     error
		want    error // nil: decrypts to "secret"
		fetched bool
	}{
		"raw octets":         {ref(uri, ``), ct, nil, nil, true},
		"base64":             {ref(uri, tr(xmlsec.TransformBase64)), []byte(b64[:10] + "\r\n " + b64[10:]), nil, nil, true},
		"not base64":         {ref(uri, tr(xmlsec.TransformBase64)), []byte("!!"), nil, xmlsec.ErrMalformed, true},
		"resolver fails":     {ref(uri, ``), nil, errGone, errGone, true},
		"two transforms":     {ref(uri, tr(xmlsec.TransformBase64, xmlsec.TransformBase64)), ct, nil, xmlsec.ErrUnsupportedAlgorithm, false},
		"c14n transform":     {ref(uri, tr(string(c14n.Exclusive10))), ct, nil, xmlsec.ErrUnsupportedAlgorithm, false},
		"XPath":              {ref(uri, tr(xmlsec.TransformXPath, xmlsec.TransformBase64)), ct, nil, xmlsec.ErrTransformRefused, false},
		"relative":           {ref("data/ct", ``), ct, nil, xmlsec.ErrMalformed, false},
		"unparsable":         {ref("http://[::1", ``), ct, nil, xmlsec.ErrMalformed, false},
		"cid":                {ref("cid:a", ``), ct, nil, xmlsec.ErrMalformed, false},
		"algorithm refused":  {covED(``, covEM(xmlsec.EncAES128CBC)+`<xenc:CipherData><xenc:CipherReference URI="`+uri+`"/></xenc:CipherData>`), ct, nil, xmlsec.ErrAlgorithmNotAllowed, false},
		"same-document kept": {`<r><v Id="cv">` + b64 + `</v>` + ref("#cv", tr(xmlsec.TransformBase64)) + `</r>`, nil, nil, nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			resolve, calls := serve(c.body, c.err)
			pt, err := xenc.DecryptData(firstNamed(covParse(t, c.ed), "EncryptedData"), key, xenc.DecryptOptions{ResolveURI: resolve})
			switch {
			case c.want == nil && (err != nil || string(pt) != "secret"):
				t.Fatalf("%s, %v", pt, err)
			case c.want != nil && !errors.Is(err, c.want):
				t.Fatalf("got %v, want %v", err, c.want)
			case c.err != nil && !errors.Is(err, xmlsec.ErrDereference):
				t.Fatalf("resolver error not wrapped: %v", err)
			case c.fetched != (len(*calls) == 1):
				t.Fatalf("resolver calls %v", *calls)
			}
		})
	}
}
