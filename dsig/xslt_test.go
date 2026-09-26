package dsig_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// xsltSheet writes the text of a and the number of x:drop elements, which
// it names through a q: prefix used only inside an XPath expression.
const xsltSheet = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:q="urn:x" version="1.0">` +
	`<xsl:output method="xml" omit-xml-declaration="yes"/>` +
	`<xsl:template match="/"><out><xsl:value-of select="//a/text()"/>|<xsl:value-of select="count(//q:drop)"/></out></xsl:template>` +
	`</xsl:stylesheet>`

func stylesheet(t *testing.T, s string) *xdm.Node {
	t.Helper()
	return xmltree.DocumentElement(parse(t, []byte(s)))
}

func xsltSpec(s *xdm.Node) dsig.TransformSpec {
	return dsig.TransformSpec{Algorithm: xmlsec.TransformXSLT, Stylesheet: s}
}

func TestXSLTTransform(t *testing.T) {
	cases := []struct {
		name string
		ts   func(s *xdm.Node) []dsig.TransformSpec
	}{
		{"node set input", func(s *xdm.Node) []dsig.TransformSpec { return []dsig.TransformSpec{xpEnv, xsltSpec(s), xpExc} }},
		{"octet input", func(s *xdm.Node) []dsig.TransformSpec { return []dsig.TransformSpec{xpEnv, xpExc, xsltSpec(s)} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, sig := mustSignInPlace(t, xpDoc, "", c.ts(stylesheet(t, xsltSheet))...)
			allowed := stylesheet(t, xsltSheet)
			opts := dsig.VerifyOptions{AllowedXSLTStylesheets: []*xdm.Node{stylesheet(t, `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"/>`), allowed}}

			if _, err := xpVerify(t, doc, sig, dsig.VerifyOptions{}); !errors.Is(err, xmlsec.ErrTransformRefused) {
				t.Fatalf("not opted in: %v", err)
			}
			cov, err := xpVerify(t, doc, sig, opts)
			if err != nil {
				t.Fatal(err)
			}
			// The output is new content: nothing of the document is covered.
			if cov.WholeDocumentSigned || len(cov.SignedElements) != 0 || len(cov.References) != 1 {
				t.Fatalf("coverage %+v", cov)
			}
			for _, got := range cov.References[0].Transforms {
				if got.Algorithm == xmlsec.TransformXSLT && got.Stylesheet != allowed {
					t.Fatal("Coverage does not report the allowed stylesheet")
				}
			}
			// What the stylesheet does not read may change; what it reads may not.
			replaceText(doc, "inner", "changed")
			if _, err := xpVerify(t, doc, sig, opts); err != nil {
				t.Fatalf("unread content digested: %v", err)
			}
			replaceText(doc, "keep", "changed")
			if _, err := xpVerify(t, doc, sig, opts); !errors.Is(err, xmlsec.ErrDigestMismatch) {
				t.Fatalf("tampered: %v", err)
			}
		})
	}
}

func TestXSLTVerifyAdmission(t *testing.T) {
	sign := func() (*xdm.Node, *xdm.Node, *xdm.Node) {
		doc, sig := mustSignInPlace(t, xpDoc, "", xpEnv, xsltSpec(stylesheet(t, xsltSheet)), xpExc)
		return doc, sig, find(sig, xmlsec.NSDSig, "Transform").Parent.ChildElements()[1]
	}
	cases := []struct {
		name    string
		edit    func(tr *xdm.Node)
		allowed string
		want    error
	}{
		{"another stylesheet", func(*xdm.Node) {}, strings.Replace(xsltSheet, "|", "-", 1), xmlsec.ErrTransformRefused},
		// q is used only inside select: no element or attribute name shows
		// it, so plain Exclusive C14N would not notice the rebinding.
		{"prefix rebinding", func(tr *xdm.Node) {
			for _, ns := range tr.ChildElements()[0].Namespaces {
				if ns.Name.Local == "q" {
					ns.Value = "urn:attacker"
				}
			}
		}, xsltSheet, xmlsec.ErrTransformRefused},
		{"two children", func(tr *xdm.Node) { xmltree.Element(tr, "", "", "x") }, xsltSheet, xmlsec.ErrMalformed},
		{"not a stylesheet", func(tr *xdm.Node) { tr.ChildElements()[0].Name.Local = "template" }, xsltSheet, xmlsec.ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, sig, tr := sign()
			c.edit(tr)
			_, err := xpVerify(t, doc, sig, dsig.VerifyOptions{AllowedXSLTStylesheets: []*xdm.Node{stylesheet(t, c.allowed)}})
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

// The stylesheet reads nothing but its input, and its errors fail the
// transform.
func TestXSLTSandbox(t *testing.T) {
	sheet := func(version, body string) string {
		return `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="` + version + `">` + body + `</xsl:stylesheet>`
	}
	cases := []struct {
		name, doc, sheet string
		want             error
	}{
		{"document()", xpDoc, sheet("1.0", `<xsl:template match="/"><o><xsl:copy-of select="document('file:///etc/hosts')"/></o></xsl:template>`), xmlsec.ErrMalformed},
		{"xsl:include", xpDoc, sheet("1.0", `<xsl:include href="file:///etc/x.xsl"/>`), xmlsec.ErrMalformed},
		{"xsl:import", xpDoc, sheet("1.0", `<xsl:import href="http://127.0.0.1:1/x.xsl"/>`), xmlsec.ErrMalformed},
		{"unparsed-text()", xpDoc, sheet("2.0", `<xsl:template match="/"><o><xsl:value-of select="unparsed-text('file:///etc/hosts')"/></o></xsl:template>`), xmlsec.ErrMalformed},
		{"doc()", xpDoc, sheet("2.0", `<xsl:template match="/"><o><xsl:copy-of select="doc('http://127.0.0.1:1/')"/></o></xsl:template>`), xmlsec.ErrMalformed},
		{"terminating message", xpDoc, sheet("1.0", `<xsl:template match="/"><xsl:message terminate="yes">no</xsl:message></xsl:template>`), xmlsec.ErrMalformed},
		{"serialization error", xpDoc, sheet("1.0", `<xsl:output method="xml" encoding="x-no-such-charset"/><xsl:template match="/"><o/></xsl:template>`), xmlsec.ErrMalformed},
		{"input with no canonical form", `<r xmlns:p="relative"><p:a/></r>`, sheet("1.0", `<xsl:template match="/"><o/></xsl:template>`), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := signInPlace(t, c.doc, "", xpEnv, xsltSpec(stylesheet(t, c.sheet)), xpExc)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestXSLTInputNotXML(t *testing.T) {
	_, _, err := signInPlace(t, xpDoc, "", xpEnv, dsig.TransformSpec{Algorithm: xmlsec.TransformBase64},
		xsltSpec(stylesheet(t, xsltSheet)), xpExc)
	if !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("got %v", err)
	}
}

func TestXSLTSignNeedsStylesheet(t *testing.T) {
	_, _, err := signInPlace(t, xpDoc, "", xpEnv, xsltSpec(stylesheet(t, `<x/>`)), xpExc)
	if !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("got %v", err)
	}
}

// The stylesheet keeps its meaning inside ds:Transform: its own bindings,
// one rebinding ds, a nested declaration, and no default namespace where
// the signature's parent has one.
func TestXSLTStylesheetNamespaces(t *testing.T) {
	const doc = `<r xmlns="urn:d"><a>keep</a></r>`
	const sheet = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ds="urn:other" xmlns:d="urn:d" version="1.0">` +
		`<xsl:template match="/" xmlns:p="urn:p"><out><p:x/><ds:y/><xsl:value-of select="//d:a"/></out></xsl:template></xsl:stylesheet>`
	d, sig := mustSignInPlace(t, doc, "", xpEnv, xsltSpec(stylesheet(t, sheet)), xpExc)
	opts := dsig.VerifyOptions{AllowedXSLTStylesheets: []*xdm.Node{stylesheet(t, sheet)}}
	if _, err := xpVerify(t, d, sig, opts); err != nil {
		t.Fatal(err)
	}
	replaceText(d, "keep", "changed")
	if _, err := xpVerify(t, d, sig, opts); !errors.Is(err, xmlsec.ErrDigestMismatch) {
		t.Fatalf("tampered: %v", err)
	}
}
