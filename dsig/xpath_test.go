package dsig_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// xpDoc has an element with wsu:Id "a", a namespaced element x:drop that the
// filters below remove, and a comment.
const xpDoc = `<r xmlns:x="urn:x" xmlns:wsu="` + xmlsec.NSWSU + `">` +
	`<a wsu:Id="a" at="1">keep<b>inner</b><x:drop>in a</x:drop></a><x:drop>gone</x:drop><!--c--></r>`

var (
	xpEnv   = dsig.TransformSpec{Algorithm: xmlsec.TransformEnvelopedSignature}
	xpExc   = dsig.TransformSpec{Algorithm: string(c14n.Exclusive10)}
	xpIncl  = dsig.TransformSpec{Algorithm: string(c14n.Inclusive10)}
	xpNS    = map[string]string{"x": "urn:x"}
	xpDSNS  = map[string]string{"ds": xmlsec.NSDSig}
	xpNoX   = "not(ancestor-or-self::x:drop)"
	xpThis  = "count(ancestor-or-self::ds:Signature | here()/ancestor::ds:Signature[1]) > count(ancestor-or-self::ds:Signature)"
	xpXML   = "not(ancestor-or-self::*[@xml:lang = 'fr'])"
	xpAllow = []dsig.XPathExpression{{Expr: xpNoX, Namespaces: xpNS}, {Expr: xpThis, Namespaces: xpDSNS}, {Expr: "true()"}, {Expr: xpXML}}
)

func xp(expr string, ns map[string]string) dsig.TransformSpec {
	return dsig.TransformSpec{Algorithm: xmlsec.TransformXPath, XPath: expr, XPathNamespaces: ns}
}

func filter2(ns map[string]string, pairs ...string) dsig.TransformSpec {
	t := dsig.TransformSpec{Algorithm: xmlsec.TransformXPathFilter2, XPathNamespaces: ns}
	for i := 0; i < len(pairs); i += 2 {
		t.XPathFilters = append(t.XPathFilters, dsig.XPathFilter{Filter: pairs[i], Expr: pairs[i+1]})
	}
	return t
}

// signInPlace signs doc under its document element with one reference and
// returns the signed document, re-parsed, and its signature.
func signInPlace(t *testing.T, doc, uri string, ts ...dsig.TransformSpec) (*xdm.Node, *xdm.Node, error) {
	t.Helper()
	d := parse(t, []byte(doc))
	_, err := dsig.Sign(d, newKey(t, rsaKey), dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References:                []dsig.Reference{{URI: uri, Transforms: ts, DigestAlgorithm: xmlsec.DigestSHA256}},
		Parent:                    xmltree.DocumentElement(d),
	})
	if err != nil {
		return nil, nil, err
	}
	signed := parse(t, serialize(t, d))
	return signed, findSignature(signed), nil
}

func mustSignInPlace(t *testing.T, doc, uri string, ts ...dsig.TransformSpec) (*xdm.Node, *xdm.Node) {
	t.Helper()
	d, sig, err := signInPlace(t, doc, uri, ts...)
	if err != nil {
		t.Fatal(err)
	}
	return d, sig
}

func xpVerify(t *testing.T, doc, sig *xdm.Node, opts dsig.VerifyOptions) (*dsig.Coverage, error) {
	t.Helper()
	opts.Certificate = newKey(t, rsaKey).Certificate
	return dsig.Verify(doc, sig, opts)
}

// replaceText changes the first text node equal to old, to tamper with a
// signed document.
func replaceText(doc *xdm.Node, old, new string) {
	var walk func(n *xdm.Node) bool
	walk = func(n *xdm.Node) bool {
		if n.Kind == xdm.KindText && n.Value == old {
			n.Value = new
			return true
		}
		for _, c := range n.Children {
			if walk(c) {
				return true
			}
		}
		return false
	}
	walk(doc)
}

func TestXPathTransform(t *testing.T) {
	allow := dsig.VerifyOptions{AllowedXPathExpressions: xpAllow}
	cases := []struct {
		name    string
		uri     string
		ts      []dsig.TransformSpec
		whole   bool     // Coverage.WholeDocumentSigned
		ids     []string // Coverage.SignedElementIDs
		covered string   // text whose change must break the signature
		free    string   // text a filter dropped, which may change
	}{
		{"enveloped then XPath", "", []dsig.TransformSpec{xpEnv, xp(xpNoX, xpNS), xpExc}, false, nil, "keep", "gone"},
		{"XPath then enveloped", "", []dsig.TransformSpec{xpEnv, xp(xpNoX, xpNS), xpEnv, xpIncl}, false, nil, "inner", "gone"},
		{"here() removes only this signature", "", []dsig.TransformSpec{xpEnv, xp(xpThis, xpDSNS), xpExc}, true, nil, "gone", ""},
		{"XPath keeping everything", "#a", []dsig.TransformSpec{xp("true()", nil), xpExc}, false, []string{"a"}, "inner", ""},
		{"XPath dropping part of the target", "#a", []dsig.TransformSpec{xp(xpNoX, xpNS), xpExc}, false, nil, "inner", "in a"},
		{"xml prefix", "#a", []dsig.TransformSpec{xp(xpXML, nil), xpExc}, false, []string{"a"}, "inner", ""},
		{"two XPath transforms", "", []dsig.TransformSpec{xpEnv, xp("true()", nil), xp(xpNoX, xpNS), xpExc}, false, nil, "keep", "gone"},
		{"XPath over reparsed octets", "", []dsig.TransformSpec{xpEnv, xpExc, xp(xpNoX, xpNS), xpExc}, false, nil, "keep", "gone"},
		{"XPath over reparsed octets keeping everything", "#a", []dsig.TransformSpec{xpExc, xp("true()", nil), xpExc}, false, []string{"a"}, "keep", ""},
		{"implicit canonicalization", "#a", []dsig.TransformSpec{xp("true()", nil)}, false, []string{"a"}, "keep", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "implicit canonicalization" {
				// Sign never ends on a node set; Verify completes one with
				// Canonical XML 1.0, which the signer must have used.
				c.ts = []dsig.TransformSpec{xp("true()", nil), xpIncl}
			}
			doc, sig := mustSignInPlace(t, xpDoc, c.uri, c.ts...)
			ts := find(sig, xmlsec.NSDSig, "Transforms")
			switch c.name {
			case "implicit canonicalization":
				ts.Children = ts.Children[:1]
				resign(sig)
			case "here() removes only this signature":
				// Sign puts enveloped-signature first on a whole-document
				// reference; a received one may rely on here() alone.
				ts.Children = ts.Children[1:]
				resign(sig)
			}
			if _, err := xpVerify(t, doc, sig, dsig.VerifyOptions{}); !errors.Is(err, xmlsec.ErrTransformRefused) {
				t.Fatalf("not opted in: got %v", err)
			}
			cov, err := xpVerify(t, doc, sig, allow)
			if err != nil {
				t.Fatal(err)
			}
			if cov.WholeDocumentSigned != c.whole || strings.Join(cov.SignedElementIDs, ",") != strings.Join(c.ids, ",") ||
				len(cov.References) != 1 {
				t.Fatalf("coverage whole=%v ids=%v refs=%d", cov.WholeDocumentSigned, cov.SignedElementIDs, len(cov.References))
			}
			if c.free != "" {
				replaceText(doc, c.free, "changed")
				if _, err := xpVerify(t, doc, sig, allow); err != nil {
					t.Fatalf("a dropped node was digested: %v", err)
				}
			}
			replaceText(doc, c.covered, "changed")
			if _, err := xpVerify(t, doc, sig, allow); !errors.Is(err, xmlsec.ErrDigestMismatch) {
				t.Fatalf("tampered: got %v", err)
			}
		})
	}
}

// find returns the first element of n's subtree with the given name.
func find(n *xdm.Node, uri, local string) *xdm.Node {
	var got *xdm.Node
	xmltree.Walk(n, func(e *xdm.Node) {
		if got == nil && e.IsElement(uri, local) {
			got = e
		}
	})
	return got
}

// A filter that drops the element a reference names takes it out of
// Coverage, and Covers reports it uncovered.
func TestXPathFilteredElementNotCovered(t *testing.T) {
	expr := "not(ancestor-or-self::*[@wsu:Id='a'])"
	ns := map[string]string{"wsu": xmlsec.NSWSU}
	for name, tr := range map[string]dsig.TransformSpec{
		"XPath":            xp(expr, ns),
		"XPath Filter 2.0": filter2(ns, "subtract", "//*[@wsu:Id='a']"),
	} {
		t.Run(name, func(t *testing.T) {
			doc, sig := mustSignInPlace(t, xpDoc, "#a", tr, xpExc)
			cov, err := xpVerify(t, doc, sig, dsig.VerifyOptions{AllowedXPathExpressions: []dsig.XPathExpression{
				{Expr: expr, Namespaces: ns}, {Expr: "//*[@wsu:Id='a']", Namespaces: ns}}})
			if err != nil {
				t.Fatal(err)
			}
			if cov.Covers("a") || len(cov.SignedElements) != 0 || cov.WholeDocumentSigned {
				t.Fatalf("filtered-out element reported covered: %+v", cov)
			}
			// It was not digested: changing it leaves the signature valid.
			replaceText(doc, "inner", "attacker")
			if _, err := xpVerify(t, doc, sig, dsig.VerifyOptions{AllowedXPathExpressions: []dsig.XPathExpression{
				{Expr: expr, Namespaces: ns}, {Expr: "//*[@wsu:Id='a']", Namespaces: ns}}}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestXPathFilter2Transform(t *testing.T) {
	allow := dsig.VerifyOptions{AllowedXPathExpressions: []dsig.XPathExpression{
		{Expr: "/", Namespaces: nil},
		{Expr: "//x:drop", Namespaces: xpNS},
		{Expr: "//b", Namespaces: nil},
		{Expr: "//ds:Signature", Namespaces: xpDSNS},
		{Expr: "//namespace::x", Namespaces: nil},
		{Expr: "here()/ancestor::ds:Signature[1]", Namespaces: xpDSNS},
	}}
	cases := []struct {
		name    string
		filters []string
		whole   bool
		covered string
		free    string
	}{
		{"subtract", []string{"subtract", "//x:drop"}, false, "keep", "gone"},
		{"intersect", []string{"intersect", "//b"}, false, "inner", "keep"},
		{"intersect then union", []string{"intersect", "//b", "union", "//x:drop"}, false, "gone", "keep"},
		{"intersect then subtract", []string{"intersect", "/", "subtract", "//x:drop"}, false, "keep", "gone"},
		{"namespace nodes", []string{"subtract", "//namespace::x"}, false, "keep", ""},
		{"here()", []string{"subtract", "here()/ancestor::ds:Signature[1]"}, true, "gone", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, sig := mustSignInPlace(t, xpDoc, "", xpEnv, filter2(map[string]string{"x": "urn:x", "ds": xmlsec.NSDSig}, c.filters...), xpExc)
			cov, err := xpVerify(t, doc, sig, allow)
			if err != nil {
				t.Fatal(err)
			}
			if cov.WholeDocumentSigned != c.whole {
				t.Fatalf("whole = %v", cov.WholeDocumentSigned)
			}
			got := cov.References[0].Transforms[1]
			if len(got.XPathFilters) != len(c.filters)/2 || got.XPathFilters[0].Filter != c.filters[0] {
				t.Fatalf("reported filters %+v", got.XPathFilters)
			}
			if c.free != "" {
				replaceText(doc, c.free, "changed")
				if _, err := xpVerify(t, doc, sig, allow); err != nil {
					t.Fatalf("a dropped node was digested: %v", err)
				}
			}
			replaceText(doc, c.covered, "changed")
			if _, err := xpVerify(t, doc, sig, allow); !errors.Is(err, xmlsec.ErrDigestMismatch) {
				t.Fatalf("tampered: got %v", err)
			}
		})
	}
}

func TestXPathSignErrors(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		ts   []dsig.TransformSpec
		want error
	}{
		{"XPath syntax", xpDoc, []dsig.TransformSpec{xpEnv, xp("(", nil), xpExc}, xmlsec.ErrMalformed},
		{"unbound prefix", xpDoc, []dsig.TransformSpec{xpEnv, xp("self::q:a", nil), xpExc}, xmlsec.ErrMalformed},
		{"dynamic error", xpDoc, []dsig.TransformSpec{xpEnv, xp("xs:integer('x')", map[string]string{"xs": "http://www.w3.org/2001/XMLSchema"}), xpExc}, xmlsec.ErrMalformed},
		{"prefix bound to an empty URI", xpDoc, []dsig.TransformSpec{xpEnv, xp("true()", map[string]string{"p": ""}), xpExc}, xmlsec.ErrMalformed},
		{"prefix xml", xpDoc, []dsig.TransformSpec{xpEnv, xp("true()", map[string]string{"xml": xdm.NSXML}), xpExc}, xmlsec.ErrMalformed},
		{"prefix rebinding ds", xpDoc, []dsig.TransformSpec{xpEnv, xp("true()", map[string]string{"ds": "urn:other"}), xpExc}, xmlsec.ErrMalformed},
		{"prefix rebinding dsig-xpath", xpDoc, []dsig.TransformSpec{xpEnv, filter2(map[string]string{"dsig-xpath": "urn:other"}, "union", "/"), xpExc}, xmlsec.ErrMalformed},
		{"unknown filter", xpDoc, []dsig.TransformSpec{xpEnv, filter2(nil, "difference", "/"), xpExc}, xmlsec.ErrMalformed},
		{"empty filter expression", xpDoc, []dsig.TransformSpec{xpEnv, filter2(nil, "union", " "), xpExc}, xmlsec.ErrMalformed},
		{"filter syntax", xpDoc, []dsig.TransformSpec{xpEnv, filter2(nil, "union", "("), xpExc}, xmlsec.ErrMalformed},
		{"filter selects a number", xpDoc, []dsig.TransformSpec{xpEnv, filter2(nil, "union", "count(//a)"), xpExc}, xmlsec.ErrMalformed},
		{"filter dynamic error", xpDoc, []dsig.TransformSpec{xpEnv, filter2(nil, "union", "//a[1 div 0 = error()]"), xpExc}, xmlsec.ErrMalformed},
		{"octets that are not XML", xpDoc, []dsig.TransformSpec{xpEnv, {Algorithm: xmlsec.TransformBase64}, xp("true()", nil), xpExc}, xmlsec.ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := signInPlace(t, c.doc, "", c.ts...); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

// here() is the ds:XPath element, so a detached signature, which is not in
// the document, cannot use it (XML-DSig 6.6.3.1).
func TestXPathHereDetached(t *testing.T) {
	doc := parse(t, []byte(xpDoc))
	_, err := dsig.Sign(doc, newKey(t, rsaKey), dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References:                []dsig.Reference{{URI: "#a", Transforms: []dsig.TransformSpec{xp("here()", nil), xpExc}, DigestAlgorithm: xmlsec.DigestSHA256}},
	})
	if !errors.Is(err, xmlsec.ErrMalformed) || !strings.Contains(err.Error(), "here()") {
		t.Fatalf("got %v", err)
	}
}

// Received transforms: what is refused, and when.
func TestXPathVerifyAdmission(t *testing.T) {
	doc, sig := mustSignInPlace(t, xpDoc, "", xpEnv, xp(xpNoX, xpNS), xpExc)
	tr := find(sig, xmlsec.NSDSig, "Transform").Parent.ChildElements()[1]
	xpath := tr.ChildElements()[0]
	opts := dsig.VerifyOptions{AllowedXPathExpressions: xpAllow}

	if _, err := xpVerify(t, doc, sig, dsig.VerifyOptions{AllowedXSLTStylesheets: []*xdm.Node{xpath}}); !errors.Is(err, xmlsec.ErrTransformRefused) {
		t.Fatalf("XSLT allow-list admits XPath: %v", err)
	}
	if _, err := xpVerify(t, doc, sig, dsig.VerifyOptions{AllowedXPathExpressions: []dsig.XPathExpression{{Expr: "true()"}}}); !errors.Is(err, xmlsec.ErrTransformRefused) {
		t.Fatalf("expression not in the list: %v", err)
	}
	// The same text with x bound elsewhere where it stands.
	if _, err := xpVerify(t, doc, sig, dsig.VerifyOptions{AllowedXPathExpressions: []dsig.XPathExpression{{Expr: xpNoX, Namespaces: map[string]string{"x": "urn:other"}}}}); !errors.Is(err, xmlsec.ErrTransformRefused) {
		t.Fatalf("prefix rebinding: %v", err)
	}
	// Surrounding whitespace is not part of the match.
	opts.AllowedXPathExpressions = append([]dsig.XPathExpression{{Expr: " \n" + xpNoX + "\t", Namespaces: xpNS}}, xpAllow...)
	if _, err := xpVerify(t, doc, sig, opts); err != nil {
		t.Fatal(err)
	}

	edits := []struct {
		name string
		edit func()
		want error
	}{
		{"element child", func() { xmltree.Element(xpath, "", "", "e") }, xmlsec.ErrMalformed},
		{"second XPath", func() { tr.AppendChild(xpath) }, xmlsec.ErrMalformed},
		{"no XPath", func() { tr.Children = nil }, xmlsec.ErrMalformed},
		{"wrong element", func() { xpath.Name.Local = "Expr" }, xmlsec.ErrMalformed},
	}
	for _, e := range edits {
		t.Run(e.name, func(t *testing.T) {
			doc, sig := mustSignInPlace(t, xpDoc, "", xpEnv, xp(xpNoX, xpNS), xpExc)
			tr = find(sig, xmlsec.NSDSig, "Transform").Parent.ChildElements()[1]
			xpath = tr.ChildElements()[0]
			e.edit()
			if _, err := xpVerify(t, doc, sig, dsig.VerifyOptions{AllowedXPathExpressions: xpAllow}); !errors.Is(err, e.want) {
				t.Fatalf("got %v, want %v", err, e.want)
			}
		})
	}
}

func TestXPathFilter2VerifyAdmission(t *testing.T) {
	sign := func() (*xdm.Node, *xdm.Node, *xdm.Node) {
		doc, sig := mustSignInPlace(t, xpDoc, "", xpEnv, filter2(nil, "subtract", "//b", "union", "//b"), xpExc)
		return doc, sig, find(sig, xmlsec.NSDSig, "Transform").Parent.ChildElements()[1]
	}
	allow := []dsig.XPathExpression{{Expr: "//b"}}
	cases := []struct {
		name  string
		edit  func(tr *xdm.Node)
		allow []dsig.XPathExpression
		want  error
	}{
		{"unchanged", func(*xdm.Node) {}, allow, nil},
		{"bad Filter", func(tr *xdm.Node) { tr.ChildElements()[1].Attr("", "Filter").Value = "xor" }, allow, xmlsec.ErrMalformed},
		{"no XPath", func(tr *xdm.Node) { tr.Children = nil }, allow, xmlsec.ErrMalformed},
		{"ds:XPath", func(tr *xdm.Node) { tr.ChildElements()[0].Name.URI = xmlsec.NSDSig }, allow, xmlsec.ErrMalformed},
		{"one expression not allowed", func(tr *xdm.Node) { replaceText(tr.ChildElements()[1], "//b", "//a") }, allow, xmlsec.ErrTransformRefused},
		{"conflicting bindings", func(tr *xdm.Node) {
			tr.ChildElements()[0].AddNamespace("p", "urn:1")
			tr.ChildElements()[1].AddNamespace("p", "urn:2")
		}, []dsig.XPathExpression{{Expr: "//b", Namespaces: map[string]string{"p": "urn:1"}}, {Expr: "//b", Namespaces: map[string]string{"p": "urn:2"}}}, xmlsec.ErrTransformRefused},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, sig, tr := sign()
			c.edit(tr)
			_, err := xpVerify(t, doc, sig, dsig.VerifyOptions{AllowedXPathExpressions: c.allow})
			if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

// A reference without URI whose XPath drops part of the octets reports
// OmittedURISigned false.
func TestXPathOmittedURICoverage(t *testing.T) {
	const obj = `<o><k>1</k><d>2</d></o>`
	for _, c := range []struct {
		expr, digested string
		want           bool
	}{{"true()", obj, true}, {"not(ancestor-or-self::d)", `<o><k>1</k></o>`, false}} {
		doc, sig := mustSignInPlace(t, xpDoc, "", xpEnv, xpExc)
		ref := find(sig, xmlsec.NSDSig, "Reference")
		ref.Attrs = nil
		ts := find(ref, xmlsec.NSDSig, "Transforms")
		ts.Children = nil
		tr := xmltree.Element(ts, "ds", xmlsec.NSDSig, "Transform")
		xmltree.SetAttr(tr, "", "", "Algorithm", xmlsec.TransformXPath)
		xmltree.Text(xmltree.Element(tr, "ds", xmlsec.NSDSig, "XPath"), c.expr)
		tr = xmltree.Element(ts, "ds", xmlsec.NSDSig, "Transform")
		xmltree.SetAttr(tr, "", "", "Algorithm", string(c14n.Exclusive10))
		sum := sha256.Sum256([]byte(c.digested))
		dv := find(ref, xmlsec.NSDSig, "DigestValue")
		dv.Children = nil
		xmltree.Text(dv, base64.StdEncoding.EncodeToString(sum[:]))
		if !resign(sig) {
			t.Fatal("resign")
		}
		cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{
			Certificate:             newKey(t, rsaKey).Certificate,
			AllowedXPathExpressions: []dsig.XPathExpression{{Expr: c.expr}},
			ResolveOmittedURI:       func() ([]byte, error) { return []byte(obj), nil },
		})
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if cov.OmittedURISigned != c.want {
			t.Fatalf("%s: OmittedURISigned = %v", c.expr, cov.OmittedURISigned)
		}
	}
}

// The XPath elements may bind a prefix the document binds otherwise.
func TestXPathShadowedPrefixes(t *testing.T) {
	const doc = `<r xmlns:x="urn:elsewhere" xmlns:dsig-xpath="urn:other"><x:drop>d</x:drop><k>keep</k></r>`
	for _, tr := range []dsig.TransformSpec{xp(xpNoX, xpNS), filter2(xpNS, "subtract", "//x:drop")} {
		d, sig := mustSignInPlace(t, doc, "", xpEnv, tr, xpExc)
		_, err := xpVerify(t, d, sig, dsig.VerifyOptions{AllowedXPathExpressions: []dsig.XPathExpression{
			{Expr: xpNoX, Namespaces: xpNS}, {Expr: "//x:drop", Namespaces: xpNS}}})
		if err != nil {
			t.Fatalf("%s: %v", tr.Algorithm, err)
		}
	}
}
