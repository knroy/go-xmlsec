package dsig

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xml/xpath"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// XPathExpression is an XPath or XPath Filter 2.0 expression a verifier
// accepts (VerifyOptions.AllowedXPathExpressions): the expression text and
// the namespace bindings it is compiled with.
type XPathExpression struct {
	// Expr is compared with the received expression after surrounding
	// whitespace is trimmed from both.
	Expr string

	// Namespaces maps each prefix Expr uses to its namespace URI. A received
	// expression matches only if every one of these prefixes is bound to the
	// same URI where it stands, and it is compiled with these bindings, never
	// with the received document's.
	Namespaces map[string]string
}

// XPathFilter is one dsig-xpath:XPath element of an XPath Filter 2.0
// transform.
type XPathFilter struct {
	// Filter is "intersect", "subtract" or "union".
	Filter string

	// Expr is the XPath expression; it must select nodes.
	Expr string
}

// isProgramTransform reports whether alg carries an expression or
// stylesheet: the transforms Verify evaluates only when a caller allows the
// exact program.
func isProgramTransform(alg string) bool {
	return alg == xmlsec.TransformXPath || alg == xmlsec.TransformXPathFilter2 || alg == xmlsec.TransformXSLT
}

var filterOps = []string{"intersect", "subtract", "union"}

// admitTransform checks a received XPath, XPath Filter 2.0 or XSLT
// transform against the caller's allow-lists, and fills t with the program
// that was allowed, which is what digesting then evaluates. It compiles and
// evaluates nothing: a program no allow-list names is refused before it
// costs anything.
func admitTransform(t *TransformSpec, opts VerifyOptions) error {
	refused := fmt.Errorf("%w: %s", xmlsec.ErrTransformRefused, t.Algorithm)
	kids := t.el.ChildElements()
	switch t.Algorithm {
	case xmlsec.TransformXSLT:
		if len(opts.AllowedXSLTStylesheets) == 0 {
			return refused
		}
		// XML-DSig 6.6.5: the stylesheet is the sole child of ds:Transform.
		if len(kids) != 1 || !isStylesheet(kids[0]) {
			return malformed("an XSLT transform must hold one xsl:stylesheet")
		}
		for _, s := range opts.AllowedXSLTStylesheets {
			if sameStylesheet(s, kids[0]) {
				t.Stylesheet = s
				return nil
			}
		}
		return fmt.Errorf("%w: stylesheet not in VerifyOptions.AllowedXSLTStylesheets", refused)
	}

	if len(opts.AllowedXPathExpressions) == 0 {
		return refused
	}
	local, uri, n := "XPath", xmlsec.NSDSig, 1
	if t.Algorithm == xmlsec.TransformXPathFilter2 {
		uri, n = xmlsec.TransformXPathFilter2, len(kids)
	}
	if len(kids) != n || n == 0 {
		return malformed("%s needs its XPath element", t.Algorithm)
	}
	ns := map[string]string{}
	for _, k := range kids {
		if !k.IsElement(uri, local) || len(k.ChildElements()) > 0 {
			return malformed("unexpected %s under ds:Transform %s", k.Name.Local, t.Algorithm)
		}
		e, ok := allowedExpression(k, opts.AllowedXPathExpressions)
		if !ok {
			return fmt.Errorf("%w: expression %q not in VerifyOptions.AllowedXPathExpressions", refused, strings.TrimSpace(k.StringValue()))
		}
		for p, u := range e.Namespaces {
			if got, ok := ns[p]; ok && got != u {
				return fmt.Errorf("%w: prefix %q bound to two namespaces", refused, p)
			}
			ns[p] = u
		}
		if t.Algorithm == xmlsec.TransformXPath {
			t.XPath = e.Expr
			break
		}
		f := k.AttrValue("Filter")
		if !slices.Contains(filterOps, f) {
			return malformed("XPath Filter 2.0 Filter %q", f)
		}
		t.XPathFilters = append(t.XPathFilters, XPathFilter{Filter: f, Expr: e.Expr})
	}
	t.XPathNamespaces = ns
	return nil
}

// allowedExpression returns the entry of list that the XPath element x
// carries: the same trimmed text, with each of the entry's prefixes bound to
// the same URI in x's scope.
func allowedExpression(x *xdm.Node, list []XPathExpression) (XPathExpression, bool) {
	got := strings.TrimSpace(x.StringValue())
	for _, e := range list {
		if strings.TrimSpace(e.Expr) != got {
			continue
		}
		bound := true
		for p, u := range e.Namespaces {
			if v, ok := x.LookupPrefix(p); !ok || v != u {
				bound = false
			}
		}
		if bound {
			return e, true
		}
	}
	return XPathExpression{}, false
}

// xpathElements appends to tr the ds:XPath or dsig-xpath:XPath elements
// that carry t's expressions, each declaring t.XPathNamespaces.
func xpathElements(tr *xdm.Node, t TransformSpec) error {
	type x struct{ filter, expr string }
	var list []x
	prefix, uri := "ds", xmlsec.NSDSig
	if t.Algorithm == xmlsec.TransformXPath {
		list = []x{{"", t.XPath}}
	} else {
		prefix, uri = "dsig-xpath", xmlsec.TransformXPathFilter2
		for _, f := range t.XPathFilters {
			list = append(list, x{f.Filter, f.Expr})
		}
	}
	if u, ok := t.XPathNamespaces[prefix]; ok && u != uri {
		return malformed("XPathNamespaces rebinds %q, the prefix of the XPath element", prefix)
	}
	// A binding may shadow one of the document's: the element holds only
	// the expression.
	bind := func(e *xdm.Node, p, u string) {
		if got, ok := e.LookupPrefix(p); !ok || got != u {
			e.AddNamespace(p, u)
		}
	}
	for _, l := range list {
		e := xmltree.Element(tr, prefix, uri, "XPath")
		bind(e, prefix, uri)
		for _, p := range slices.Sorted(maps.Keys(t.XPathNamespaces)) {
			bind(e, p, t.XPathNamespaces[p])
		}
		if l.filter != "" {
			xmltree.SetAttr(e, "", "", "Filter", l.filter)
		}
		xmltree.Text(e, l.expr)
	}
	return nil
}

// checkXPathSpec refuses an XPath or XPath Filter 2.0 TransformSpec that
// would produce an invalid transform element.
func checkXPathSpec(t TransformSpec) error {
	for p, u := range t.XPathNamespaces {
		if !xdm.IsNCName(p) || p == "xml" || p == "xmlns" || u == "" {
			return malformed("XPathNamespaces binding %q to %q", p, u)
		}
	}
	if t.Algorithm == xmlsec.TransformXPath {
		if strings.TrimSpace(t.XPath) == "" {
			return malformed("an XPath transform needs TransformSpec.XPath")
		}
		return nil
	}
	if len(t.XPathFilters) == 0 {
		return malformed("an XPath Filter 2.0 transform needs TransformSpec.XPathFilters")
	}
	for _, f := range t.XPathFilters {
		if !slices.Contains(filterOps, f.Filter) || strings.TrimSpace(f.Expr) == "" {
			return malformed("XPath Filter 2.0 filter %q with expression %q", f.Filter, f.Expr)
		}
	}
	return nil
}

// prefixMap resolves an expression's prefixes from its bindings alone.
type prefixMap map[string]string

func (m prefixMap) ResolvePrefix(p string) (string, bool) {
	if p == "xml" {
		return xdm.NSXML, true
	}
	u, ok := m[p]
	return u, ok
}
func (prefixMap) DefaultElementNamespace() string  { return "" }
func (prefixMap) DefaultFunctionNamespace() string { return xdm.NSFN }

// compileXPath compiles an XML-DSig expression, which is XPath 1.0, under
// XPath 1.0 compatibility mode.
func compileXPath(expr string, ns map[string]string) (*xpath.Compiled, error) {
	c, err := xpath.CompileWith(strings.TrimSpace(expr), xpath.CompileOptions{Namespaces: prefixMap(ns)})
	if err != nil {
		return nil, fmt.Errorf("%w: XPath %q: %v", xmlsec.ErrMalformed, expr, err)
	}
	return c.WithCompatMode(true), nil
}

// library is the XPath 1.0 core function library plus XML-DSig's here()
// (6.6.3.1): the element bearing the expression, which must be in the
// document being evaluated.
func library(here, doc *xdm.Node) xpath.FunctionLibrary {
	lib := xpath.NewLibrary(xpath.Builtins())
	lib.Add(xpath.Function{Name: xdm.QName{URI: xdm.NSFN, Local: "here"}, Call: func(*xpath.Context, []xdm.Sequence) (xdm.Sequence, error) {
		if here.Root() != doc {
			return nil, fmt.Errorf("%w: here() outside the document the expression is evaluated against", xmlsec.ErrMalformed)
		}
		return xdm.Sequence{here}, nil
	}})
	return lib
}

type nsKey struct {
	elem   *xdm.Node
	prefix string
}

// filtered is the node set an XPath or XPath Filter 2.0 transform outputs.
// It decides namespace-node membership itself (c14n.NamespaceSet), since
// both transforms filter namespace nodes like any other.
type filtered struct {
	root  *xdm.Node
	nodes map[*xdm.Node]bool
	ns    map[nsKey]bool
}

func (s filtered) Root() *xdm.Node           { return s.root }
func (s filtered) Contains(n *xdm.Node) bool { return s.nodes[n] }
func (s filtered) ContainsNamespace(e *xdm.Node, prefix string) bool {
	return s.ns[nsKey{e, prefix}]
}

// without removes the subtree of sig, for an enveloped-signature transform
// that follows.
func (s filtered) without(sig *xdm.Node) filtered {
	maps.DeleteFunc(s.nodes, func(n *xdm.Node, _ bool) bool { return within(n, sig) })
	maps.DeleteFunc(s.ns, func(k nsKey, _ bool) bool { return within(k.elem, sig) })
	return s
}

// member reports whether n, any node kind including a namespace node, is in
// the data's node set.
func (d *data) member(n *xdm.Node) bool {
	switch {
	case d.stripComments && n.Kind == xdm.KindComment:
		return false
	case n.Kind == xdm.KindNamespace:
		if s, ok := d.ns.(c14n.NamespaceSet); ok {
			return s.ContainsNamespace(n.Parent, n.Name.Local)
		}
		return d.ns.Contains(n.Parent)
	}
	return d.ns.Contains(n)
}

// filter applies an XPath (XML-DSig 6.6.3) or XPath Filter 2.0 transform:
// the output is the input nodes the expression keeps. Nodes it drops are
// recorded in d.cut, except those of sig, so that Coverage reports only
// what was digested.
func (d *data) filter(t TransformSpec, sig *xdm.Node) error {
	if d.ns == nil {
		// 6.6.3: octets become a node set with comments.
		tree, err := xmlsec.Parse(d.octets)
		if err != nil {
			return fmt.Errorf("%w: parsing octets for %s: %w", xmlsec.ErrMalformed, t.Algorithm, err)
		}
		d.ns, d.stripComments, d.reparsed = c14n.Document(tree.Root), false, true
	}
	doc := d.ns.Root().Root()
	// here() is the XPath element bearing each expression: Sign and
	// admitTransform both leave exactly one per expression.
	here := t.el.ChildElements()

	var keep func(*xdm.Node) (bool, error)
	if t.Algorithm == xmlsec.TransformXPath {
		c, err := compileXPath(t.XPath, t.XPathNamespaces)
		if err != nil {
			return err
		}
		lib := library(here[0], doc)
		keep = func(n *xdm.Node) (bool, error) { return c.EvalBool(xpath.NewContext(n, lib).WithFocus(n, 1, 1)) }
	} else {
		sets := make([]selection, len(t.XPathFilters))
		for i, f := range t.XPathFilters {
			var err error
			if sets[i], err = selectFilter(f.Expr, t.XPathNamespaces, library(here[i], doc), doc); err != nil {
				return err
			}
		}
		keep = func(n *xdm.Node) (bool, error) {
			// XPath Filter 2.0 section 3.4: the filter node set starts as the
			// whole document, and the output is its intersection with the input.
			in := true
			for i, f := range t.XPathFilters {
				s := sets[i].expanded(n)
				switch f.Filter {
				case "intersect":
					in = in && s
				case "subtract":
					in = in && !s
				default: // union
					in = in || s
				}
			}
			return in, nil
		}
	}

	// ponytail: the expression runs once per input node, O(nodes x
	// expression), bounded only by xmlsec.MaxParseNodes, MaxTransformsPerReference
	// and the reference count; the allow-list keeps the expression the
	// caller's own. Add a node budget if an allowed expression is ever costly.
	out := filtered{root: d.ns.Root(), nodes: map[*xdm.Node]bool{}, ns: map[nsKey]bool{}}
	var err error
	var walk func(n *xdm.Node)
	visit := func(n *xdm.Node) {
		if err != nil || !d.member(n) {
			return
		}
		var k bool
		if k, err = keep(n); err != nil {
			err = fmt.Errorf("%w: evaluating %s: %v", xmlsec.ErrMalformed, t.Algorithm, err)
			return
		}
		switch {
		case !k:
			if !within(n, sig) {
				d.cut = append(d.cut, n)
			}
		case n.Kind == xdm.KindNamespace:
			out.ns[nsKey{n.Parent, n.Name.Local}] = true
		default:
			out.nodes[n] = true
		}
	}
	walk = func(n *xdm.Node) {
		visit(n)
		if n.Kind == xdm.KindElement {
			for _, ns := range xpath.NamespaceNodesOf(n) {
				visit(ns)
			}
			for _, a := range n.Attrs {
				visit(a)
			}
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(out.root)
	if err != nil {
		return err
	}
	if d.reparsed && len(d.cut) > 0 {
		// Dropped nodes of a tree parsed from octets are no node of the
		// document: nothing it holds can be reported as covered.
		d.opaque = true
	}
	d.ns = out
	return nil
}

// selection is the node set one XPath Filter 2.0 expression selects.
type selection struct {
	nodes map[*xdm.Node]bool
	ns    map[nsKey]bool
}

// selectFilter evaluates an XPath Filter 2.0 expression with the document
// root as context node (section 3.2).
func selectFilter(expr string, ns map[string]string, lib xpath.FunctionLibrary, doc *xdm.Node) (selection, error) {
	s := selection{nodes: map[*xdm.Node]bool{}, ns: map[nsKey]bool{}}
	c, err := compileXPath(expr, ns)
	if err != nil {
		return s, err
	}
	seq, err := c.Eval(xpath.NewContext(doc, lib).WithFocus(doc, 1, 1))
	if err != nil {
		return s, fmt.Errorf("%w: evaluating XPath Filter 2.0 %q: %v", xmlsec.ErrMalformed, expr, err)
	}
	for _, it := range seq {
		n, ok := it.(*xdm.Node)
		switch {
		case !ok:
			return s, malformed("XPath Filter 2.0 %q selects a non-node", expr)
		case n.Kind == xdm.KindNamespace:
			s.ns[nsKey{n.Parent, n.Name.Local}] = true
		default:
			s.nodes[n] = true
		}
	}
	return s, nil
}

// expanded reports whether n is in the subtree expansion of s: in s, or
// with an ancestor in s (section 3.4).
func (s selection) expanded(n *xdm.Node) bool {
	if n.Kind == xdm.KindNamespace && s.ns[nsKey{n.Parent, n.Name.Local}] {
		return true
	}
	// ponytail: an ancestor walk per node per filter, O(nodes x depth); mark
	// subtrees top-down if deep documents ever make it show.
	for ; n != nil; n = n.Parent {
		if s.nodes[n] {
			return true
		}
	}
	return false
}

// within reports whether x is top or one of its descendants, attributes and
// namespace nodes included.
func within(x, top *xdm.Node) bool {
	for ; x != nil && top != nil; x = x.Parent {
		if x == top {
			return true
		}
	}
	return false
}
