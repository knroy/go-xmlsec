package dsig

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
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
	tr := &xdm.Node{Kind: xdm.KindElement}
	tr.AppendChild(xmltree.DocumentElement(sheet.Root))
	d := data{octets: []byte(`<a/>`)}
	err = d.digest(sha256.New(), nil, "", []TransformSpec{{Algorithm: xmlsec.TransformXSLT, el: tr}}, false)
	if !errors.Is(err, xmlsec.ErrLimitExceeded) {
		t.Fatalf("got %v", err)
	}
}
