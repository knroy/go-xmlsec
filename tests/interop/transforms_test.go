//go:build interop

package interop

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

const transformDoc = `<r xmlns:x="urn:x"><a>keep<b>inner</b></a><x:drop>gone</x:drop><c>tail</c></r>`

const transformSheet = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:q="urn:x" version="1.0">` +
	`<xsl:output method="xml" omit-xml-declaration="yes"/>` +
	`<xsl:template match="/"><out n="{count(//q:drop)}"><xsl:value-of select="/r/a"/></out></xsl:template>` +
	`</xsl:stylesheet>`

// The XPath, XPath Filter 2.0 and XSLT transforms against Santuario, both
// ways: Santuario verifies our signature, we verify Santuario's, and the
// two digests are equal, which for SHA-256 means the transform output
// octets are byte-identical. Tampering with what the transform keeps
// breaks both; what it drops is free to change.
//
// here() is not compared: Santuario 4 evaluates XPath with the JDK's
// engine, which reports "Could not find function: here", and Santuario no
// longer supports Xalan's. The stylesheet declares its own prefix for
// urn:x: Santuario compiles the stylesheet element without the namespace
// declarations of its ancestors, so it must not rely on the document's.
func TestSantuarioTransforms(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	x := map[string]string{"x": "urn:x"}
	sheet := parse(t, []byte(transformSheet))

	cases := []struct {
		name     string
		spec     dsig.TransformSpec
		args     []string // Santuario's sign-transform arguments
		covered  string   // text whose change breaks the signature
		free     string   // text the transform drops
		emptySet bool     // the transform output is empty
	}{
		{"XPath", dsig.TransformSpec{Algorithm: xmlsec.TransformXPath, XPath: "not(ancestor-or-self::x:drop)", XPathNamespaces: x},
			[]string{"xpath", "not(ancestor-or-self::x:drop)", "x", "urn:x"}, "inner", "gone", false},
		// The absolute form: //ancestor-or-self::x:drop selects from the
		// root whatever the context node, so not() is false everywhere and
		// the node set is empty. Both implementations agree.
		{"XPath absolute", dsig.TransformSpec{Algorithm: xmlsec.TransformXPath, XPath: "not(//ancestor-or-self::x:drop)", XPathNamespaces: x},
			[]string{"xpath", "not(//ancestor-or-self::x:drop)", "x", "urn:x"}, "", "keep", true},
		{"Filter 2.0 subtract", dsig.TransformSpec{Algorithm: xmlsec.TransformXPathFilter2, XPathNamespaces: x,
			XPathFilters: []dsig.XPathFilter{{Filter: "subtract", Expr: "//x:drop"}}},
			[]string{"filter2", "subtract", "//x:drop", "x", "urn:x"}, "tail", "gone", false},
		{"Filter 2.0 intersect", dsig.TransformSpec{Algorithm: xmlsec.TransformXPathFilter2,
			XPathFilters: []dsig.XPathFilter{{Filter: "intersect", Expr: "//a"}}},
			[]string{"filter2", "intersect", "//a"}, "inner", "tail", false},
		{"Filter 2.0 union", dsig.TransformSpec{Algorithm: xmlsec.TransformXPathFilter2,
			XPathFilters: []dsig.XPathFilter{{Filter: "union", Expr: "//a"}}},
			[]string{"filter2", "union", "//a"}, "tail", "", false},
		{"XSLT", dsig.TransformSpec{Algorithm: xmlsec.TransformXSLT, Stylesheet: xmltree.DocumentElement(sheet)},
			[]string{"xslt", tempFile(t, "sheet.xml", []byte(transformSheet))}, "keep", "tail", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			verifyCmd := "verify"
			opts := dsig.VerifyOptions{Certificate: kp.provider.Certificate}
			if c.spec.Algorithm == xmlsec.TransformXSLT {
				// Santuario's secure validation refuses XSLT outright.
				verifyCmd = "verify-insecure"
				opts.AllowedXSLTStylesheets = []*xdm.Node{xmltree.DocumentElement(parse(t, []byte(transformSheet)))}
			} else {
				expr := c.spec.XPath
				if c.spec.XPathFilters != nil {
					expr = c.spec.XPathFilters[0].Expr
				}
				opts.AllowedXPathExpressions = []dsig.XPathExpression{{Expr: expr, Namespaces: c.spec.XPathNamespaces}}
			}
			tamper := func(b []byte, text string) []byte {
				return bytes.Replace(b, []byte(">"+text+"<"), []byte(">changed<"), 1)
			}

			ours, err := dsig.SignEnveloped(parse(t, []byte(transformDoc)), kp.provider, dsig.SignOptions{
				SignatureAlgorithm:        xmlsec.SigRSASHA256,
				CanonicalizationAlgorithm: string(c14n.Exclusive10),
				References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
					{Algorithm: xmlsec.TransformEnvelopedSignature}, c.spec, {Algorithm: string(c14n.Exclusive10)}}}},
				KeyInfo: dsig.KeyInfoX509Data,
			})
			if err != nil {
				t.Fatal(err)
			}
			mustSantuario(t, verifyCmd, tempFile(t, "ours.xml", ours), kp.certPEM)

			out := filepath.Join(t.TempDir(), "out.xml")
			mustSantuario(t, append([]string{"sign-transform", tempFile(t, "in.xml", []byte(transformDoc)), kp.keyPEM, kp.certPEM, out}, c.args...)...)
			theirs := readFile(t, out)
			verify := func(b []byte) error {
				d := parse(t, b)
				_, err := dsig.Verify(d, find(d, xmlsec.NSDSig, "Signature"), opts)
				return err
			}
			if err := verify(theirs); err != nil {
				t.Fatalf("%v\n%s", err, theirs)
			}

			_, ourDigests := signatureValue(t, ours)
			_, theirDigests := signatureValue(t, theirs)
			if !bytes.Equal(ourDigests[0], theirDigests[0]) {
				t.Fatalf("transform output differs from Santuario's\nours:\n%s\nSantuario:\n%s", ours, theirs)
			}
			if empty := sha256.Sum256(nil); c.emptySet != bytes.Equal(ourDigests[0], empty[:]) {
				t.Fatalf("empty node set: got %v, want %v", !c.emptySet, c.emptySet)
			}

			if c.free != "" {
				mustSantuario(t, verifyCmd, tempFile(t, "free.xml", tamper(ours, c.free)), kp.certPEM)
				if err := verify(tamper(theirs, c.free)); err != nil {
					t.Fatalf("dropped content was digested: %v", err)
				}
			}
			if c.covered != "" {
				if out, err := santuario(t, verifyCmd, tempFile(t, "tampered.xml", tamper(ours, c.covered)), kp.certPEM); err == nil {
					t.Fatalf("Santuario accepted a tampered document:\n%s", out)
				}
				if err := verify(tamper(theirs, c.covered)); !errors.Is(err, xmlsec.ErrDigestMismatch) {
					t.Fatalf("tampered: %v", err)
				}
			}
		})
	}
}

// here() against xmlsec1, which implements it (Santuario 4 does not): it
// verifies our XPath and XPath Filter 2.0 signatures whose expressions
// locate the signature through here().
func TestXmlsec1VerifiesOurHere(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	ds := map[string]string{"ds": xmlsec.NSDSig}
	for name, spec := range map[string]dsig.TransformSpec{
		"XPath": {Algorithm: xmlsec.TransformXPath, XPathNamespaces: ds,
			XPath: "count(ancestor-or-self::ds:Signature | here()/ancestor::ds:Signature[1]) > count(ancestor-or-self::ds:Signature)"},
		"Filter 2.0": {Algorithm: xmlsec.TransformXPathFilter2, XPathNamespaces: ds,
			XPathFilters: []dsig.XPathFilter{{Filter: "subtract", Expr: "here()/ancestor::ds:Signature[1]"}}},
	} {
		t.Run(name, func(t *testing.T) {
			signed, err := dsig.SignEnveloped(parse(t, []byte(transformDoc)), kp.provider, dsig.SignOptions{
				SignatureAlgorithm:        xmlsec.SigRSASHA256,
				CanonicalizationAlgorithm: string(c14n.Exclusive10),
				References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
					{Algorithm: xmlsec.TransformEnvelopedSignature}, spec, {Algorithm: string(c14n.Exclusive10)}}}},
				KeyInfo: dsig.KeyInfoX509Data,
			})
			if err != nil {
				t.Fatal(err)
			}
			run(t, "--verify", "--trusted-pem", kp.certPEM, tempFile(t, "signed.xml", signed))
			tampered := bytes.Replace(signed, []byte(">gone<"), []byte(">changed<"), 1)
			if out, err := runErr(t, "--verify", "--trusted-pem", kp.certPEM, tempFile(t, "tampered.xml", tampered)); err == nil {
				t.Fatalf("xmlsec1 accepted a tampered document:\n%s", out)
			}
		})
	}
}
