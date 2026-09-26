package dsig

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xml/xslt"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

const nsXSL = "http://www.w3.org/1999/XSL/Transform"

// maxXSLTOutput bounds the octets an XSLT transform may produce: the
// largest document xmlsec.Parse accepts. A variable for the tests.
var maxXSLTOutput = xmlsec.MaxParseBytes

// isStylesheet reports whether e is an xsl:stylesheet or xsl:transform.
func isStylesheet(e *xdm.Node) bool {
	return e != nil && (e.IsElement(nsXSL, "stylesheet") || e.IsElement(nsXSL, "transform"))
}

// sameStylesheet reports whether the received stylesheet got is the allowed
// one: equal under Exclusive C14N with every prefix the allowed stylesheet
// binds rendered, so a prefix its XPath expressions use cannot be rebound
// even where no element or attribute name shows it.
func sameStylesheet(allowed, got *xdm.Node) bool {
	var prefixes []string
	xmltree.Walk(allowed, func(e *xdm.Node) {
		for p := range e.InScopeNamespaces() {
			if !slices.Contains(prefixes, p) {
				prefixes = append(prefixes, p)
			}
		}
	})
	eq, err := c14n.Equal(allowed, got, c14n.Options{Algorithm: c14n.Exclusive10, InclusiveNamespacePrefixes: prefixes})
	return err == nil && eq
}

// copyStylesheet appends a copy of s to tr. The copy declares every
// binding in scope where s stands, and undeclares a default namespace s
// does not have, so that it means the same inside ds:Transform.
func copyStylesheet(tr, s *xdm.Node) {
	var cp func(parent, n *xdm.Node)
	cp = func(parent, n *xdm.Node) {
		if n.Kind != xdm.KindElement {
			// text, comment or processing instruction
			parent.AppendChild(&xdm.Node{Kind: n.Kind, Name: n.Name, Value: n.Value})
			return
		}
		e := xmltree.Element(parent, n.Name.Prefix, n.Name.URI, n.Name.Local)
		for _, ns := range n.Namespaces {
			e.AddNamespace(ns.Name.Local, ns.Value)
		}
		for _, a := range n.Attrs {
			xmltree.SetAttr(e, a.Name.Prefix, a.Name.URI, a.Name.Local, a.Value)
		}
		for _, c := range n.Children {
			cp(e, c)
		}
	}
	cp(tr, s)
	top := tr.Children[len(tr.Children)-1]
	scope := maps.Clone(s.InScopeNamespaces())
	if _, ok := scope[""]; !ok {
		scope[""] = ""
	}
	for p, u := range scope {
		if got, _ := top.LookupPrefix(p); p != "xml" && got != u {
			top.AddNamespace(p, u)
		}
	}
}

// transformXSLT applies an XSLT transform (XML-DSig 6.6.5): a node set is
// first canonicalized, the octets are parsed, and the stylesheet's output
// is the transform's octets. The stylesheet runs sandboxed: no module,
// schema or package resolver, so xsl:include, xsl:import and their kin load
// nothing, and no document, collection, text or environment resolver, so
// document(), fn:doc and the rest read nothing. The output is bounded by
// the largest document xmlsec.Parse accepts.
func (d *data) transformXSLT(t TransformSpec) error {
	src := d.octets
	if d.ns != nil {
		b, err := c14n.BytesNodeSet(d.ns, c14n.Options{Algorithm: c14n.Inclusive10})
		if err != nil {
			return err
		}
		src = b
	}
	in, err := xmlsec.Parse(src)
	if err != nil {
		return fmt.Errorf("%w: parsing the XSLT transform input: %w", xmlsec.ErrMalformed, err)
	}
	// The stylesheet is compiled where it stands inside ds:Transform, as the
	// signer's was: a literal result element copies the namespaces in scope
	// there. Verify has matched it against an allowed stylesheet.
	sheet, err := xslt.Compile(t.el.ChildElements()[0], xslt.CompileOptions{})
	if err != nil {
		return fmt.Errorf("%w: compiling the stylesheet: %v", xmlsec.ErrMalformed, err)
	}
	res, err := sheet.Transform(context.Background(), in.Root, xslt.TransformOptions{})
	if err != nil {
		return fmt.Errorf("%w: XSLT transform: %v", xmlsec.ErrMalformed, err)
	}
	w := &boundedWriter{max: maxXSLTOutput}
	if err := res.Serialize(w); err != nil {
		if w.over {
			return fmt.Errorf("%w: XSLT output over %d bytes", xmlsec.ErrLimitExceeded, w.max)
		}
		return fmt.Errorf("%w: XSLT output: %v", xmlsec.ErrMalformed, err)
	}
	// The output is new content, not nodes of the document.
	d.ns, d.octets, d.opaque = nil, w.b, true
	return nil
}

// boundedWriter collects at most max bytes.
type boundedWriter struct {
	b    []byte
	max  int
	over bool
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if len(w.b)+len(p) > w.max {
		w.over = true
		return 0, xmlsec.ErrLimitExceeded
	}
	w.b = append(w.b, p...)
	return len(p), nil
}
