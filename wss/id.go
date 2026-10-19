package wss

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"slices"

	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
)

// randReader is replaced by tests that need deterministic IDs.
var randReader io.Reader = rand.Reader

// isDefaultID reports whether an attribute is wsu:Id or xml:id.
func isDefaultID(n xdm.QName) bool {
	return n.URI == xmlsec.NSWSU && n.Local == "Id" || n.URI == xdm.NSXML && n.Local == "id"
}

// isAnyID reports whether an attribute is wsu:Id, xml:id, or an
// unqualified Id or ID: every attribute this module may resolve as an ID,
// by default or through FindByID with the dsig and SAML names.
func isAnyID(n xdm.QName) bool {
	return isDefaultID(n) || n.URI == "" && (n.Local == "Id" || n.Local == "ID")
}

// FindByID returns the element bearing the given wsu:Id or xml:id, or one
// of extra: attributes that also count as IDs, such as the unqualified ID
// of a SAML assertion. extra adds to wsu:Id and xml:id and never replaces
// them. Names match on namespace URI and local name, prefix ignored; an
// unprefixed attribute has no namespace, so xdm.QName{Local: "ID"} is the
// SAML attribute.
//
// It returns xmlsec.ErrAmbiguousID if more than one element carries the ID,
// which is malformed input and is also an XML Signature Wrapping technique:
// duplicating an ID so that the verifier and the application resolve it to
// different elements. It never returns the first match. Every counted
// attribute forms one set: an id value carried by any two of them, on one
// element or on two, is ambiguous. Each attribute added widens what an
// attacker can use to duplicate an ID, so add only what the profile defines
// as an ID.
func FindByID(doc *xdm.Node, id string, extra ...xdm.QName) (*xdm.Node, error) {
	if doc == nil {
		return nil, fmt.Errorf("%w: %q: no document", xmlsec.ErrIDNotFound, id)
	}
	var found *xdm.Node
	n := 0
	xmltree.Walk(doc.Root(), func(e *xdm.Node) {
		for a := range e.Attrs() {
			if a.Value() == id && (isDefaultID(a.Name()) || slices.ContainsFunc(extra, a.Name().Equal)) {
				found = e
				n++
			}
		}
	})
	switch n {
	case 0:
		return nil, fmt.Errorf("%w: %q", xmlsec.ErrIDNotFound, id)
	case 1:
		return found, nil
	}
	return nil, fmt.Errorf("%w: %q appears %d times", xmlsec.ErrAmbiguousID, id, n)
}

// AssignID gives an element an ID if it does not already have one, and
// returns the ID.
//
// The ID is a wsu:Id, except on an element in the XML Signature or XML
// Encryption namespaces (ds:, dsig11:, xenc:, xenc11:), whose schemas
// define an unqualified Id attribute and do not admit wsu:Id. There the
// unqualified Id is used, or set, as the WS-I Basic Security Profile
// requires of a reference to such an element (R3003, R3004). Resolving that
// reference needs dsig.IDAttrDSig in SignOptions.IDAttributes and
// VerifyOptions.IDAttributes, and on the receiving side in whatever
// registers IDs.
//
// An element that already carries an xml:id keeps it, and that is returned:
// SOAP Message Security 1.1.1 section 4 forbids a wsu:Id beside it.
//
// Generated IDs are "id-" plus 32 hex characters from crypto/rand, unique
// within the document. The prefix keeps the value an NCName.
func AssignID(doc *xmlsec.Document, el *xdm.Node) (string, error) {
	return assignID(doc, el, "")
}

// AssignIDWith is AssignID with the ID supplied by the caller instead of
// minted from crypto/rand, for output that must be byte-reproducible, such
// as a golden file or a differential against another implementation: an ID
// is inside the signed octets. id must be an NCName (xmlsec.ErrMalformed)
// that no counted ID attribute in doc already carries
// (xmlsec.ErrAmbiguousID). An element that already has an ID keeps it, and
// that ID is returned, as with AssignID.
func AssignIDWith(doc *xmlsec.Document, el *xdm.Node, id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("%w: AssignIDWith needs an ID", xmlsec.ErrMalformed)
	}
	return assignID(doc, el, id)
}

// assignID is AssignID with id, or a minted ID when id is empty.
func assignID(doc *xmlsec.Document, el *xdm.Node, id string) (string, error) {
	d := xmltree.DocOf(doc)
	if d == nil {
		return "", fmt.Errorf("%w: AssignID needs a Document", xmlsec.ErrMalformed)
	}
	if el == nil || el.Kind() != xdm.KindElement {
		return "", fmt.Errorf("%w: AssignID needs an element", xmlsec.ErrMalformed)
	}
	if el = d.Node(el); el == nil {
		return "", fmt.Errorf("%w: AssignID: the element is not in the document", xmlsec.ErrMalformed)
	}
	if got, ok := existingID(el); ok {
		return got, nil
	}
	id, err := idFor(d.Root(), id)
	if err != nil {
		return "", err
	}
	e, err := idEdits(el, id)
	if err != nil {
		return "", err
	}
	// el is in the latest tree, so the edit needs no rekeying.
	root, m := xmltree.Rebuild(d.Root(), &e)
	d.Commit(root, m)
	return id, nil
}

// WithID is AssignID for an element that is not in a document, such as a
// wsse:SecurityTokenReference for dsig.SignOptions.KeyInfoElement that a
// reference through the STR Dereference Transform names. It returns a copy
// of el, a detached element, carrying the ID as AssignID would set it, and
// the ID: id, which must be an NCName, or a minted one when id is empty. An
// element that already has an ID is returned as it is, with that ID. With
// no document to search, uniqueness is the caller's: a duplicate is refused
// on verification, with xmlsec.ErrAmbiguousID.
func WithID(el *xdm.Node, id string) (*xdm.Node, string, error) {
	if el == nil || el.Kind() != xdm.KindElement || el.Parent() != nil {
		return nil, "", fmt.Errorf("%w: WithID needs a detached element", xmlsec.ErrMalformed)
	}
	if got, ok := existingID(el); ok {
		return el, got, nil
	}
	id, err := idFor(el, id)
	if err != nil {
		return nil, "", err
	}
	e, err := idEdits(el, id)
	if err != nil {
		return nil, "", err
	}
	c, _ := xmltree.Rebuild(el, &e)
	return c, id, nil
}

// unqualifiedID reports whether el's ID is the unqualified Id its XML
// Signature or XML Encryption schema defines, rather than wsu:Id.
func unqualifiedID(el *xdm.Node) bool {
	switch el.Name().URI {
	case xmlsec.NSDSig, xmlsec.NSDSig11, xmlsec.NSXEnc, xmlsec.NSXEnc11:
		return true
	}
	return false
}

// existingID returns the ID el already carries, if any.
func existingID(el *xdm.Node) (string, bool) {
	a := el.Attr(xmlsec.NSWSU, "Id")
	if a == nil {
		// SOAP Message Security 1.1.1 section 4: an element MUST NOT carry
		// both a wsu:Id and an xml:id, so an xml:id is the element's ID.
		a = el.Attr(xdm.NSXML, "id")
	}
	if unqualifiedID(el) {
		a = el.Attr("", "Id")
	}
	if a == nil {
		return "", false
	}
	return a.Value(), true
}

// idEdits are the edits that give el the ID id.
func idEdits(el *xdm.Node, id string) (xmltree.Edits, error) {
	var e xmltree.Edits
	if unqualifiedID(el) {
		e.SetAttr(el, xdm.QName{Local: "Id"}, id)
		return e, nil
	}
	need, err := xmltree.NeedsDeclaration(el, "wsu", xmlsec.NSWSU)
	if err != nil {
		return e, err
	}
	if need {
		e.Declare(el, "wsu", xmlsec.NSWSU)
	}
	e.SetAttr(el, xdm.QName{Prefix: "wsu", URI: xmlsec.NSWSU, Local: "Id"}, id)
	return e, nil
}

// idFor returns id for a new element of doc, checked, or a minted ID when
// id is empty.
func idFor(doc *xdm.Node, id string) (string, error) {
	if id == "" {
		return newID(doc)
	}
	if !xdm.IsNCName(id) {
		return "", fmt.Errorf("%w: ID %q is not an NCName", xmlsec.ErrMalformed, id)
	}
	if usedIDs(doc)[id] {
		return "", fmt.Errorf("%w: %q is already in use", xmlsec.ErrAmbiguousID, id)
	}
	return id, nil
}

// usedIDs returns every value of an attribute this module may resolve as an
// ID, anywhere in doc.
func usedIDs(doc *xdm.Node) map[string]bool {
	used := map[string]bool{}
	if doc != nil {
		xmltree.Walk(doc.Root(), func(e *xdm.Node) {
			for a := range e.Attrs() {
				if isAnyID(a.Name()) {
					used[a.Value()] = true
				}
			}
		})
	}
	return used
}

// newID returns an ID not used anywhere in doc.
func newID(doc *xdm.Node) (string, error) {
	used := usedIDs(doc)
	for {
		var b [16]byte
		if _, err := io.ReadFull(randReader, b[:]); err != nil {
			return "", err
		}
		if id := "id-" + hex.EncodeToString(b[:]); !used[id] {
			return id, nil
		}
	}
}
