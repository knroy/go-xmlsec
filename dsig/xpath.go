package dsig

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xml/v2/xpath"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
	"github.com/knroy/go-xmlsec/v2/internal/xpathfilter"
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
			return malformed("unexpected %s under ds:Transform %s", k.Name().Local, t.Algorithm)
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
	for _, e := range list {
		if xpathfilter.Allowed(x, e.Expr, e.Namespaces) {
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

// namespaceDecisionsPerNode is how many namespace nodes an XPath or XPath
// Filter 2.0 transform decides, beyond minNamespaceDecisions, per other node
// of its input (element, attribute, text, comment or processing
// instruction); more are refused with xmlsec.ErrLimitExceeded. Each element
// has a namespace node per binding in scope, so this is the average number
// of bindings an element may have in scope per node of its own. An element
// holding text is two nodes, three with the whitespace that indents it, and
// each attribute adds one: real documents, such as UBL or XBRL whose roots
// declare up to a few hundred prefixes, stay below it.
const namespaceDecisionsPerNode = 256

// minNamespaceDecisions is the namespace nodes a transform may decide
// whatever its input, so a small document with many declarations passes.
const minNamespaceDecisions = 4096

type nsKey struct {
	elem   *xdm.Node
	prefix string
}

// filtered is the node set an XPath or XPath Filter 2.0 transform outputs.
// It decides namespace-node membership itself (c14n.NamespaceSet), since
// both transforms filter namespace nodes like any other.
//
// kept has a bit for each node of root's subtree, by Index from root's. A
// namespace node, which has no index, is in the set when its element is,
// unless ns lists it: ns holds only the namespace nodes that differ from
// their element, which in practice is few or none.
type filtered struct {
	root *xdm.Node
	kept []uint64
	ns   map[nsKey]bool
}

func newFiltered(root *xdm.Node) filtered {
	return filtered{root: root, kept: make([]uint64, (root.SubtreeEnd()-root.Index()+63)/64), ns: map[nsKey]bool{}}
}

func (s filtered) Root() *xdm.Node { return s.root }

func (s filtered) Contains(n *xdm.Node) bool {
	// A namespace node's -1 gives a negative i.
	i := n.Index() - s.root.Index()
	return i >= 0 && i < len(s.kept)*64 && s.kept[i/64]&(1<<(i%64)) != 0
}

func (s filtered) ContainsNamespace(e *xdm.Node, prefix string) bool {
	return s.Contains(e) != s.ns[nsKey{e, prefix}]
}

// add puts n, not a namespace node, in s; within the subtree of root, which
// is where filter walks.
func (s filtered) add(n *xdm.Node) {
	i := n.Index() - s.root.Index()
	s.kept[i/64] |= 1 << (i % 64)
}

// setNamespace records whether e's namespace node for prefix is in s, once
// e's own membership is decided.
func (s filtered) setNamespace(e *xdm.Node, prefix string, in bool) {
	if in != s.Contains(e) {
		s.ns[nsKey{e, prefix}] = true
	}
}

// without removes the subtree of sig, for an enveloped-signature transform
// that follows.
func (s filtered) without(sig *xdm.Node) filtered {
	if within(sig, s.root) || within(s.root, sig) {
		// One tree: the subtrees' index ranges overlap where they nest.
		lo, hi := max(sig.Index()-s.root.Index(), 0), min(sig.SubtreeEnd()-s.root.Index(), len(s.kept)*64)
		for i := lo; i < hi; i++ {
			s.kept[i/64] &^= 1 << (i % 64)
		}
	}
	maps.DeleteFunc(s.ns, func(k nsKey, _ bool) bool { return within(k.elem, sig) })
	return s
}

// member reports whether n, not a namespace node, is in the data's node
// set.
func (d *data) member(n *xdm.Node) bool {
	return !(d.stripComments && n.Kind() == xdm.KindComment) && d.ns.Contains(n)
}

// memberNamespace reports whether e's namespace node for prefix is in the
// data's node set.
func (d *data) memberNamespace(e *xdm.Node, prefix string) bool {
	if s, ok := d.ns.(c14n.NamespaceSet); ok {
		return s.ContainsNamespace(e, prefix)
	}
	return d.ns.Contains(e)
}

// filter applies an XPath (XML-DSig 6.6.3) or XPath Filter 2.0 transform:
// the output is the input nodes the expression keeps. Dropping any but
// those of sig, or any at all of an input within sig, sets d.cut, so that
// Coverage reports only what was digested.
func (d *data) filter(t TransformSpec, sig *xdm.Node) error {
	if d.ns == nil {
		// 6.6.3: octets become a node set with comments.
		tree, err := xmlsec.Parse(d.octets)
		if err != nil {
			return fmt.Errorf("%w: parsing octets for %s: %w", xmlsec.ErrMalformed, t.Algorithm, err)
		}
		d.ns, d.octets, d.stripComments, d.reparsed = c14n.Document(tree.Root), nil, false, true
	}
	doc := d.ns.Root().Root()
	// here() is the XPath element bearing each expression: Sign and
	// admitTransform both leave exactly one per expression.
	here := t.el.ChildElements()

	var keep func(*xdm.Node) (bool, error)
	// keepNS decides e's namespace node for prefix without making it, where
	// the transform needs no node; nil where it does.
	var keepNS func(e *xdm.Node, prefix string) bool
	if t.Algorithm == xmlsec.TransformXPath {
		c, err := xpathfilter.Compile(t.XPath, t.XPathNamespaces)
		if err != nil {
			return err
		}
		// One context for the transform, refocused in place per node rather
		// than copied by WithFocus: each Eval resets the item and byte
		// budgets, a function call restores the depth it raises on return,
		// and nothing keeps the context past EvalBool, whose result is a
		// boolean, so no evaluation sees another's focus.
		ctx := xpath.NewContext(doc, xpathfilter.Library(here[0], doc))
		keep = func(n *xdm.Node) (bool, error) {
			ctx.Item = n
			return c.EvalBool(ctx)
		}
	} else {
		sets := make([]selection, len(t.XPathFilters))
		for i, f := range t.XPathFilters {
			var err error
			if sets[i], err = selectFilter(f.Expr, t.XPathNamespaces, xpathfilter.Library(here[i], doc), doc); err != nil {
				return err
			}
		}
		// XPath Filter 2.0 section 3.4: the filter node set starts as the
		// whole document, and the output is its intersection with the input.
		combine := func(selected func(selection) bool) bool {
			in := true
			for i, f := range t.XPathFilters {
				s := selected(sets[i])
				switch f.Filter {
				case "intersect":
					in = in && s
				case "subtract":
					in = in && !s
				default: // union
					in = in || s
				}
			}
			return in
		}
		keep = func(n *xdm.Node) (bool, error) {
			return combine(func(s selection) bool { return s.expanded(n) }), nil
		}
		keepNS = func(e *xdm.Node, prefix string) bool {
			return combine(func(s selection) bool { return s.ns[nsKey{e, prefix}] || s.expanded(e) })
		}
	}

	// The expression runs once per input node, namespace nodes included,
	// O(nodes x expression); the allow-list keeps the expression the
	// caller's own. Every element has a namespace node for each binding in
	// scope, inherited ones included (XPath data model), so K declarations
	// on the root and M elements give K x M of them from K+M parsed nodes:
	// budget keeps their count linear in the input's other nodes.
	out := newFiltered(d.ns.Root())
	budget := minNamespaceDecisions
	var count func(n *xdm.Node)
	count = func(n *xdm.Node) {
		for a := range n.Attrs() {
			if d.member(a) {
				budget += namespaceDecisionsPerNode
			}
		}
		if d.member(n) {
			budget += namespaceDecisionsPerNode
		}
		for c := range n.Children() {
			count(c)
		}
	}
	count(out.root)
	limit := budget
	// The signature's own nodes are exempt from setting d.cut, unless the
	// input lies within the signature: then they are the target.
	inSig := within(out.root, sig)
	var err error
	// decide reports whether the transform keeps n, which is in the input,
	// and sets d.cut if not; for a namespace node, n is its element, which
	// is within the same subtrees.
	decide := func(n *xdm.Node, keep func() (bool, error)) bool {
		k, e := keep()
		if e != nil {
			err = fmt.Errorf("%w: evaluating %s: %v", xmlsec.ErrMalformed, t.Algorithm, e)
			return false
		}
		if !k && (inSig || !within(n, sig)) {
			d.cut = true
		}
		return k
	}
	// decideNS is decide for a namespace node of n, within the budget.
	decideNS := func(n *xdm.Node, keep func() (bool, error)) bool {
		if budget--; budget < 0 {
			err = fmt.Errorf("%w: %s over more than %d namespace nodes", xmlsec.ErrLimitExceeded, t.Algorithm, limit)
			return false
		}
		return decide(n, keep)
	}
	visit := func(n *xdm.Node) {
		if err == nil && d.member(n) && decide(n, func() (bool, error) { return keep(n) }) {
			out.add(n)
		}
	}
	var walk func(n *xdm.Node)
	walk = func(n *xdm.Node) {
		if err != nil {
			return
		}
		visit(n)
		if n.Kind() == xdm.KindElement {
			// After n itself: setNamespace compares with n's membership.
			if keepNS == nil {
				for _, ns := range xpath.NamespaceNodesOf(n) {
					p := ns.Name().Local
					out.setNamespace(n, p, err == nil && d.memberNamespace(n, p) && decideNS(n, func() (bool, error) { return keep(ns) }))
				}
			} else {
				for p := range n.InScopeNamespaceBindings() {
					out.setNamespace(n, p, err == nil && d.memberNamespace(n, p) && decideNS(n, func() (bool, error) { return keepNS(n, p), nil }))
				}
			}
			for a := range n.Attrs() {
				visit(a)
			}
		}
		for c := range n.Children() {
			walk(c)
		}
	}
	walk(out.root)
	if err != nil {
		return err
	}
	if d.reparsed && d.cut {
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
	c, err := xpathfilter.Compile(expr, ns)
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
		case n.Kind() == xdm.KindNamespace:
			s.ns[nsKey{n.Parent(), n.Name().Local}] = true
		default:
			s.nodes[n] = true
		}
	}
	return s, nil
}

// expanded reports whether n, not a namespace node, is in the subtree
// expansion of s: in s, or with an ancestor in s (section 3.4).
func (s selection) expanded(n *xdm.Node) bool {
	// ponytail: an ancestor walk per node per filter, O(nodes x depth); mark
	// subtrees top-down if deep documents ever make it show.
	for ; n != nil; n = n.Parent() {
		if s.nodes[n] {
			return true
		}
	}
	return false
}

// within reports whether x is top or one of its descendants, attributes and
// namespace nodes included.
func within(x, top *xdm.Node) bool {
	for ; x != nil && top != nil; x = x.Parent() {
		if x == top {
			return true
		}
	}
	return false
}
