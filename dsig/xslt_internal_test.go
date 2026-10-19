package dsig

import (
	"crypto/sha256"
	"errors"
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
	d := data{octets: []byte(`<a/>`)}
	err = d.digest(sha256.New(), nil, "", []TransformSpec{{Algorithm: xmlsec.TransformXSLT, el: tr}}, false)
	if !errors.Is(err, xmlsec.ErrLimitExceeded) {
		t.Fatalf("got %v", err)
	}
}
