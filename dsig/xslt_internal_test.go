package dsig

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
)

// The XSLT output is bounded.
func TestXSLTOutputBound(t *testing.T) {
	defer func(n int) { maxXSLTOutput = n }(maxXSLTOutput)
	maxXSLTOutput = 8

	sheet, err := xmlsec.Parse([]byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">` +
		`<xsl:template match="/"><out>more than eight bytes</out></xsl:template></xsl:stylesheet>`))
	if err != nil {
		t.Fatal(err)
	}
	tr := xdm.NewNode(xdm.KindElement, xdm.QName{}, "")
	tr.AppendCopy(xmltree.DocumentElement(sheet.Root))
	// Streamed into the digest as the last transform, and collected before
	// another.
	xsl := TransformSpec{Algorithm: xmlsec.TransformXSLT, el: tr}
	for _, ts := range [][]TransformSpec{{xsl}, {xsl, {Algorithm: xmlsec.TransformBase64}}} {
		d := data{octets: []byte(`<a/>`)}
		if err := d.digest(sha256.New(), nil, "", ts, false); !errors.Is(err, xmlsec.ErrLimitExceeded) {
			t.Fatalf("%d transforms: %v", len(ts), err)
		}
	}
}

// The XSLT input is parsed with xmlsec.Parse's limits: too deep is refused
// as ErrLimitExceeded, and still as ErrMalformed, as before it streamed.
func TestXSLTInputLimit(t *testing.T) {
	sheet, err := xmlsec.Parse([]byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">` +
		`<xsl:template match="/"><out/></xsl:template></xsl:stylesheet>`))
	if err != nil {
		t.Fatal(err)
	}
	tr := xdm.NewNode(xdm.KindElement, xdm.QName{}, "")
	tr.AppendCopy(xmltree.DocumentElement(sheet.Root))
	deep := strings.Repeat("<a>", xmlsec.MaxParseDepth+1) + strings.Repeat("</a>", xmlsec.MaxParseDepth+1)
	d := data{octets: []byte(deep)}
	err = d.digest(sha256.New(), nil, "", []TransformSpec{{Algorithm: xmlsec.TransformXSLT, el: tr}}, false)
	if !errors.Is(err, xmlsec.ErrLimitExceeded) || !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatal(err)
	}
}

// The stylesheet is compiled with the namespaces in scope where it stands: a
// literal result element under a prefix ds:Transform declares, and the
// unused one beside it, are written as the signer's compile wrote them.
func TestXSLTInheritedNamespaces(t *testing.T) {
	doc, err := xmlsec.Parse([]byte(`<ds:Transform xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:p="urn:p" xmlns:q="urn:q">` +
		`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">` +
		`<xsl:template match="/"><p:out/></xsl:template></xsl:stylesheet></ds:Transform>`))
	if err != nil {
		t.Fatal(err)
	}
	d := data{octets: []byte(`<a/>`)}
	if err := d.transformXSLT(TransformSpec{Algorithm: xmlsec.TransformXSLT, el: xmltree.DocumentElement(doc.Root)}, nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`xmlns:p="urn:p"`, `xmlns:q="urn:q"`, `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`} {
		if !strings.Contains(string(d.octets), want) {
			t.Fatalf("%s lacks %s", d.octets, want)
		}
	}
}
