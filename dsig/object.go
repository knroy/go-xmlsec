package dsig

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// Object is a ds:Object that Sign emits in the signature, after
// ds:SignatureValue and ds:KeyInfo (XML-DSig 4.6). A reference to "#"+ID
// covers it, which is how an enveloping signature signs its content.
type Object struct {
	// ID, if set, becomes the Id attribute. It must be an NCName.
	ID string

	// MimeType, if set, becomes the MimeType attribute: advisory, never
	// checked (XML-DSig 4.6).
	MimeType string

	// Encoding, if set, becomes the Encoding attribute. It must be a URI.
	Encoding string

	// Content is copied into the ds:Object in order: elements, with the
	// namespace bindings in scope where they stand, text, comments and
	// processing instructions. The nodes themselves are not modified.
	Content []*xdm.Node
}

// SignatureProperty is a ds:SignatureProperty (XML-DSig 5.2), assertion
// about the signature such as a timestamp. Sign emits every one of
// SignOptions.Properties in one ds:SignatureProperties, inside a ds:Object
// after those of SignOptions.Objects. It is signed only when a reference
// covers it: to "#"+ID, with ID set.
type SignatureProperty struct {
	// ID, if set, becomes the Id attribute. It must be an NCName.
	ID string

	// Target is the URI of the ds:Signature the property is about. Empty
	// means "#"+SignOptions.SignatureID, which must then be set.
	Target string

	// Content is copied as for Object.Content. It must hold at least one
	// element, and every element must be in a namespace other than the XML
	// Signature one (the schema's ##other).
	Content []*xdm.Node
}

// isURI reports whether s may stand in an attribute of type anyURI.
func isURI(s string) bool {
	_, err := url.Parse(s)
	return err == nil && !strings.ContainsFunc(s, unicode.IsSpace)
}

// checkContent refuses a content node Sign cannot copy.
func checkContent(what string, content []*xdm.Node) error {
	for _, n := range content {
		if n == nil || n.Kind < xdm.KindElement || n.Kind == xdm.KindAttribute || n.Kind > xdm.KindPI {
			return fmt.Errorf("%w: %s content must be elements, text, comments or processing instructions", xmlsec.ErrMalformed, what)
		}
	}
	return nil
}

// checkObjects refuses Objects and Properties that would make the signature
// schema invalid.
func checkObjects(opts SignOptions) error {
	for _, o := range opts.Objects {
		switch {
		case o.ID != "" && !xdm.IsNCName(o.ID):
			return fmt.Errorf("%w: Object.ID %q is not an NCName", xmlsec.ErrMalformed, o.ID)
		case o.Encoding != "" && !isURI(o.Encoding):
			return fmt.Errorf("%w: Object.Encoding %q is not a URI", xmlsec.ErrMalformed, o.Encoding)
		}
		if err := checkContent("Object", o.Content); err != nil {
			return err
		}
	}
	for _, p := range opts.Properties {
		switch {
		case p.ID != "" && !xdm.IsNCName(p.ID):
			return fmt.Errorf("%w: SignatureProperty.ID %q is not an NCName", xmlsec.ErrMalformed, p.ID)
		case p.Target == "" && opts.SignatureID == "":
			return fmt.Errorf("%w: a SignatureProperty without Target needs SignOptions.SignatureID", xmlsec.ErrMalformed)
		case !isURI(p.Target):
			return fmt.Errorf("%w: SignatureProperty.Target %q is not a URI", xmlsec.ErrMalformed, p.Target)
		}
		if err := checkContent("SignatureProperty", p.Content); err != nil {
			return err
		}
		elements := 0
		for _, n := range p.Content {
			if n.Kind != xdm.KindElement {
				continue
			}
			if n.Name.URI == "" || n.Name.URI == xmlsec.NSDSig {
				return fmt.Errorf("%w: SignatureProperty content %s must be in a namespace other than XML Signature's", xmlsec.ErrMalformed, n.Name.Local)
			}
			elements++
		}
		if elements == 0 {
			return fmt.Errorf("%w: SignatureProperty content needs an element", xmlsec.ErrMalformed)
		}
	}
	return nil
}

// addObjects appends the ds:Object elements of opts to sig.
func addObjects(sig *xdm.Node, opts SignOptions) {
	for _, o := range opts.Objects {
		obj := xmltree.Element(sig, "ds", xmlsec.NSDSig, "Object")
		setOptional(obj, "Id", o.ID)
		setOptional(obj, "MimeType", o.MimeType)
		setOptional(obj, "Encoding", o.Encoding)
		copyContent(obj, o.Content)
	}
	if len(opts.Properties) == 0 {
		return
	}
	sps := xmltree.Element(xmltree.Element(sig, "ds", xmlsec.NSDSig, "Object"), "ds", xmlsec.NSDSig, "SignatureProperties")
	for _, p := range opts.Properties {
		sp := xmltree.Element(sps, "ds", xmlsec.NSDSig, "SignatureProperty")
		setOptional(sp, "Id", p.ID)
		target := p.Target
		if target == "" {
			target = "#" + opts.SignatureID
		}
		xmltree.SetAttr(sp, "", "", "Target", target)
		copyContent(sp, p.Content)
	}
}

func setOptional(e *xdm.Node, name, value string) {
	if value != "" {
		xmltree.SetAttr(e, "", "", name, value)
	}
}

// copyContent appends copies of content to parent; checkContent has
// admitted every node.
func copyContent(parent *xdm.Node, content []*xdm.Node) {
	for _, n := range content {
		if n.Kind == xdm.KindElement {
			copyStylesheet(parent, n) // copies any element with its in-scope bindings
			continue
		}
		parent.AppendChild(&xdm.Node{Kind: n.Kind, Name: n.Name, Value: n.Value})
	}
}

// ownID reports whether e is an element of the signature sig whose
// unqualified Id the XML Signature schema declares an ID and a reference
// from that signature may name: a ds:Object or ds:KeyInfo child of sig, a
// ds:Manifest or ds:SignatureProperties in such an Object, or a
// ds:SignatureProperty in those. They count as IDs for sig's own
// references, as a schema-aware processor would count them, without
// IDAttrDSig and so without every unqualified Id in the document.
func ownID(sig, e *xdm.Node) bool {
	if sig == nil || e.Name.URI != xmlsec.NSDSig {
		return false
	}
	p := e.Parent
	switch e.Name.Local {
	case "Object", "KeyInfo":
		return p == sig
	case "Manifest", "SignatureProperties":
		return p != nil && p.IsElement(xmlsec.NSDSig, "Object") && p.Parent == sig
	case "SignatureProperty":
		return p != nil && p.IsElement(xmlsec.NSDSig, "SignatureProperties") && ownID(sig, p)
	}
	return false
}

// dsigID is the unqualified Id attribute.
var dsigID = xdm.QName{Local: "Id"}

// findID resolves a same-document "#id" as wss.FindByID does, over doc and
// also over sig when sig is not yet in doc (a detached signature being
// built), counting the Id of sig's own elements (ownID) as an ID too. An
// id carried more than once, by any counted attribute, is refused.
func findID(doc, sig *xdm.Node, id string, extra []xdm.QName) (*xdm.Node, error) {
	counted := append([]xdm.QName{{URI: xmlsec.NSWSU, Local: "Id"}, {URI: xdm.NSXML, Local: "id"}}, extra...)
	var found *xdm.Node
	n := 0
	visit := func(e *xdm.Node) {
		for _, a := range e.Attrs {
			if a.Value == id && (slices.ContainsFunc(counted, a.Name.Equal) || a.Name.Equal(dsigID) && ownID(sig, e)) {
				found = e
				n++
			}
		}
	}
	xmltree.Walk(doc.Root(), visit)
	if sig != nil && sig.Root() != doc.Root() {
		xmltree.Walk(sig, visit)
	}
	switch n {
	case 0:
		return nil, fmt.Errorf("%w: %q", xmlsec.ErrIDNotFound, id)
	case 1:
		return found, nil
	}
	return nil, fmt.Errorf("%w: %q appears %d times", xmlsec.ErrAmbiguousID, id, n)
}
