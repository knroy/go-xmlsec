package security

import (
	"errors"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

const transformDoc = `<r xmlns:x="urn:x"><a>pay 10</a><x:note>n</x:note></r>`

// signTransform signs transformDoc in place, the signer's own choice of
// transforms, and returns the signed document re-parsed.
func signTransform(t *testing.T, kp xmlsec.KeyProvider, ts ...dsig.TransformSpec) (doc, sig *xdm.Node) {
	t.Helper()
	tree, err := xmlsec.Parse([]byte(transformDoc))
	if err != nil {
		t.Fatal(err)
	}
	ts = append([]dsig.TransformSpec{{Algorithm: xmlsec.TransformEnvelopedSignature}}, ts...)
	ts = append(ts, dsig.TransformSpec{Algorithm: string(c14n.Exclusive10)})
	signed, err := dsig.SignEnveloped(tree.Root, kp, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References:                []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: ts}},
		KeyInfo:                   dsig.KeyInfoX509Data,
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := xmlsec.Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	sig, _, _, _ = elements(parsed.Root)
	return parsed.Root, sig
}

// An attacker-supplied expression or stylesheet that is not in the caller's
// allow-list is refused with ErrTransformRefused before any cryptographic
// work, and so before it is compiled or evaluated: here the signature is by
// the attacker's key, and the refusal comes ahead of the key mismatch. The
// stylesheet would fetch from a local listener if it ran.
func TestAttackerProgramRefusedBeforeEvaluation(t *testing.T) {
	url, hits := listener(t)
	victim := keyPair(t, rsaKey(t))
	attacker := keyPair(t, rsaKey(t))
	evil, err := xmlsec.Parse([]byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">` +
		`<xsl:template match="/"><o><xsl:copy-of select="document('` + url + `/xslt')"/></o></xsl:template></xsl:stylesheet>`))
	if err != nil {
		t.Fatal(err)
	}
	benign, err := xmlsec.Parse([]byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">` +
		`<xsl:template match="/"><o/></xsl:template></xsl:stylesheet>`))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]dsig.TransformSpec{
		"XPath":            {Algorithm: xmlsec.TransformXPath, XPath: "count(//node()) > 0"},
		"XPath Filter 2.0": {Algorithm: xmlsec.TransformXPathFilter2, XPathFilters: []dsig.XPathFilter{{Filter: "union", Expr: "//*"}}},
	}
	for name, tr := range cases {
		t.Run(name, func(t *testing.T) {
			doc, sig := signTransform(t, attacker, tr)
			for _, opts := range []dsig.VerifyOptions{
				{Certificate: victim.Certificate},
				{Certificate: victim.Certificate, AllowedXPathExpressions: []dsig.XPathExpression{{Expr: "true()"}}},
			} {
				if _, err := dsig.Verify(doc, sig, opts); !errors.Is(err, xmlsec.ErrTransformRefused) {
					t.Fatalf("got %v", err)
				}
			}
		})
	}
	t.Run("XSLT", func(t *testing.T) {
		// Signing runs the stylesheet, which fails on document(); the
		// attacker's message is built by hand from a benign one instead.
		doc, sig := signTransform(t, attacker, dsig.TransformSpec{Algorithm: xmlsec.TransformXSLT, Stylesheet: xmltree.DocumentElement(benign.Root)})
		var tr *xdm.Node
		xmltree.Walk(sig, func(e *xdm.Node) {
			if e.IsElement(xmlsec.NSDSig, "Transform") && e.AttrValue("Algorithm") == xmlsec.TransformXSLT {
				tr = e
			}
		})
		tr.Children = nil
		tr.AppendChild(xmltree.DocumentElement(evil.Root))
		for _, opts := range []dsig.VerifyOptions{
			{Certificate: victim.Certificate},
			{Certificate: victim.Certificate, AllowedXSLTStylesheets: []*xdm.Node{xmltree.DocumentElement(benign.Root)}},
		} {
			if _, err := dsig.Verify(doc, sig, opts); !errors.Is(err, xmlsec.ErrTransformRefused) {
				t.Fatalf("got %v", err)
			}
		}
	})
	if n := hits.Load(); n != 0 {
		t.Fatalf("%d network fetches", n)
	}
}

// Prefix rebinding: the attacker keeps the allowed expression text but
// binds its prefix to another namespace, so that the filter would drop
// nothing the verifier expects dropped, or something it expects kept. The
// match requires the allow-list entry's bindings where the expression
// stands, so it is refused.
func TestXPathPrefixRebindingRefused(t *testing.T) {
	kp := keyPair(t, rsaKey(t))
	x := map[string]string{"x": "urn:x"}
	attackerX := map[string]string{"x": "urn:attacker"}
	cases := []struct {
		name  string
		tr    dsig.TransformSpec
		allow dsig.XPathExpression
	}{
		{"XPath", dsig.TransformSpec{Algorithm: xmlsec.TransformXPath, XPath: "not(ancestor-or-self::x:note)", XPathNamespaces: attackerX},
			dsig.XPathExpression{Expr: "not(ancestor-or-self::x:note)", Namespaces: x}},
		{"XPath Filter 2.0", dsig.TransformSpec{Algorithm: xmlsec.TransformXPathFilter2, XPathNamespaces: attackerX,
			XPathFilters: []dsig.XPathFilter{{Filter: "subtract", Expr: "//x:note"}}},
			dsig.XPathExpression{Expr: "//x:note", Namespaces: x}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, sig := signTransform(t, kp, c.tr)
			_, err := dsig.Verify(doc, sig, dsig.VerifyOptions{Certificate: kp.Certificate, AllowedXPathExpressions: []dsig.XPathExpression{c.allow}})
			if !errors.Is(err, xmlsec.ErrTransformRefused) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// Even an allowed stylesheet reads nothing: no document(), no include.
func TestAllowedXSLTFetchesNothing(t *testing.T) {
	url, hits := listener(t)
	file, _ := secret(t)
	kp := keyPair(t, rsaKey(t))
	for _, body := range []string{
		`<xsl:template match="/"><o><xsl:copy-of select="document('` + url + `/d')"/></o></xsl:template>`,
		`<xsl:template match="/"><o><xsl:copy-of select="document('` + file + `')"/></o></xsl:template>`,
		`<xsl:include href="` + url + `/i"/>`,
		`<xsl:import href="` + file + `"/>`,
	} {
		s, err := xmlsec.Parse([]byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">` + body + `</xsl:stylesheet>`))
		if err != nil {
			t.Fatal(err)
		}
		tree, err := xmlsec.Parse([]byte(transformDoc))
		if err != nil {
			t.Fatal(err)
		}
		_, err = dsig.SignEnveloped(tree.Root, kp, dsig.SignOptions{
			SignatureAlgorithm:        xmlsec.SigRSASHA256,
			CanonicalizationAlgorithm: string(c14n.Exclusive10),
			References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
				{Algorithm: xmlsec.TransformEnvelopedSignature},
				{Algorithm: xmlsec.TransformXSLT, Stylesheet: xmltree.DocumentElement(s.Root)},
				{Algorithm: string(c14n.Exclusive10)}}}},
		})
		if !errors.Is(err, xmlsec.ErrMalformed) {
			t.Fatalf("%s: got %v", body, err)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("%d network fetches", n)
	}
}
