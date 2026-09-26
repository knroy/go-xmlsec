package xenc

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xml/xpath"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xpathfilter"
)

// xpathBase64 is the transform chain of Example 13: an XPath selecting the
// text that holds the ciphertext's base64 encoding, then base64.
var xpathBase64 = []string{xmlsec.TransformXPath, xmlsec.TransformBase64}

// externalURI returns the URI to pass to opts.ResolveURI for a
// CipherReference URI, or "" for a same-document reference. A relative URI
// is resolved against opts.BaseURI, never against xml:base. Anything else
// is refused.
func externalURI(uri string, opts DecryptOptions) (string, error) {
	if uri == "" || uri[0] == '#' {
		return "", nil
	}
	if opts.ResolveURI != nil && !strings.HasPrefix(uri, "cid:") {
		if u, err := url.Parse(uri); err == nil {
			if u.IsAbs() {
				return uri, nil
			}
			if opts.BaseURI != "" {
				base, err := url.Parse(opts.BaseURI)
				if err != nil || !base.IsAbs() {
					return "", fmt.Errorf("xenc: DecryptOptions.BaseURI %q is not an absolute URI", opts.BaseURI)
				}
				return base.ResolveReference(u).String(), nil
			}
		}
	}
	return "", malformed("CipherReference URI %q: only a same-document reference is dereferenced here", uri)
}

// xpathStep is an allowed XPath transform of a CipherReference: the
// caller's expression compiled, and the ds:XPath element that carried it,
// which here() returns.
type xpathStep struct {
	expr *xpath.Compiled
	here *xdm.Node
}

// cipherTransforms returns the Algorithm of each ds:Transform in a
// CipherReference's xenc:Transforms, and the XPath transform if allowed
// lets one through. XSLT, XPath Filter 2.0, and an XPath whose expression
// allowed does not list are xmlsec.ErrTransformRefused. Nothing is
// dereferenced or evaluated.
func cipherTransforms(cr *xdm.Node, allowed []dsig.XPathExpression) ([]string, *xpathStep, error) {
	var algs []string
	var xp *xpathStep
	for i, k := range cr.ChildElements() {
		if i > 0 || !k.IsElement(xmlsec.NSXEnc, "Transforms") {
			return nil, nil, malformed("xenc:CipherReference may hold only one xenc:Transforms")
		}
		for _, t := range k.ChildElements() {
			alg := t.AttrValue("Algorithm")
			switch {
			case alg == xmlsec.TransformXPath && len(allowed) > 0 && t.IsElement(xmlsec.NSDSig, "Transform"):
				var err error
				if xp, err = admitXPath(t, allowed); err != nil {
					return nil, nil, err
				}
			case alg == xmlsec.TransformXSLT || alg == xmlsec.TransformXPath || alg == xmlsec.TransformXPathFilter2:
				return nil, nil, fmt.Errorf("%w: %s", xmlsec.ErrTransformRefused, alg)
			case !t.IsElement(xmlsec.NSDSig, "Transform") || len(t.ChildElements()) > 0:
				return nil, nil, malformed("xenc:Transforms must hold ds:Transform elements without parameters")
			}
			algs = append(algs, alg)
		}
	}
	return algs, xp, nil
}

// admitXPath checks the ds:XPath of an XPath transform against allowed, as
// dsig does, and compiles the matching entry: never the received text.
func admitXPath(t *xdm.Node, allowed []dsig.XPathExpression) (*xpathStep, error) {
	kids := t.ChildElements()
	if len(kids) != 1 || !kids[0].IsElement(xmlsec.NSDSig, "XPath") || len(kids[0].ChildElements()) > 0 {
		return nil, malformed("an XPath transform must hold one ds:XPath")
	}
	for _, e := range allowed {
		if xpathfilter.Allowed(kids[0], e.Expr, e.Namespaces) {
			c, err := xpathfilter.Compile(e.Expr, e.Namespaces)
			if err != nil {
				return nil, err
			}
			return &xpathStep{expr: c, here: kids[0]}, nil
		}
	}
	return nil, fmt.Errorf("%w: %s: expression %q not in DecryptOptions.AllowedXPathExpressions",
		xmlsec.ErrTransformRefused, xmlsec.TransformXPath, strings.TrimSpace(kids[0].StringValue()))
}

// decode applies the XPath transform and then base64 to the node set of
// top's subtree. Base64 reads a node set's text nodes (XML-DSig 6.6.2), so
// the expression is evaluated for text nodes only, which leaves the same
// text as filtering every node would; the selected text is concatenated in
// document order, as xmlsec1 and Santuario do.
func (x *xpathStep) decode(top *xdm.Node) ([]byte, error) {
	lib := xpathfilter.Library(x.here, top.Root())
	var b strings.Builder
	var err error
	var walk func(n *xdm.Node)
	walk = func(n *xdm.Node) {
		// ponytail: one evaluation per text node, bounded by
		// xmlsec.MaxParseNodes; the allow-list keeps the expression the
		// caller's own.
		for _, c := range n.Children {
			if err != nil {
				return
			}
			if c.Kind == xdm.KindText {
				var keep bool
				if keep, err = x.expr.EvalBool(xpath.NewContext(c, lib).WithFocus(c, 1, 1)); keep {
					b.WriteString(c.Value)
				}
			}
			walk(c)
		}
	}
	walk(top)
	if err != nil {
		return nil, fmt.Errorf("%w: evaluating the CipherReference XPath: %v", xmlsec.ErrMalformed, err)
	}
	return decode64(b.String())
}
