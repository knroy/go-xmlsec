package wss

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"slices"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// randReader is replaced by tests that need deterministic IDs.
var randReader io.Reader = rand.Reader

// isDefaultID reports whether an attribute is wsu:Id or xml:id.
func isDefaultID(n xdm.QName) bool {
	return n.URI == NSWSU && n.Local == "Id" || n.URI == NSXML && n.Local == "id"
}

// isAnyID reports whether an attribute is wsu:Id, xml:id, or an
// unqualified Id or ID: every attribute this module may resolve as an ID,
// by default or through FindByIDAttributes with the dsig and SAML names.
func isAnyID(n xdm.QName) bool {
	return isDefaultID(n) || n.URI == "" && (n.Local == "Id" || n.Local == "ID")
}

// FindByID returns the element bearing the given wsu:Id or xml:id.
//
// It returns xmlsec.ErrAmbiguousID if more than one element carries the ID,
// which is malformed input and is also an XML Signature Wrapping technique:
// duplicating an ID so that the verifier and the application resolve it to
// different elements. It never returns the first match. xdm.ElementByID is
// deliberately not used: it returns the first match.
func FindByID(doc *xdm.Node, id string) (*xdm.Node, error) {
	return FindByIDAttributes(doc, id)
}

// FindByIDAttributes is FindByID with extra attributes that also count as
// IDs, such as the unqualified ID of a SAML assertion. wsu:Id and xml:id
// always count; extra adds to them and never replaces them. Names match on
// namespace URI and local name, prefix ignored; an unprefixed attribute has
// no namespace, so xdm.QName{Local: "ID"} is the SAML attribute.
//
// Every counted attribute forms one set: an id value carried by any two of
// them, on one element or on two, is xmlsec.ErrAmbiguousID. Each attribute
// added widens what an attacker can use to duplicate an ID, so add only
// what the profile defines as an ID.
func FindByIDAttributes(doc *xdm.Node, id string, extra ...xdm.QName) (*xdm.Node, error) {
	if doc == nil {
		return nil, fmt.Errorf("%w: %q: no document", xmlsec.ErrIDNotFound, id)
	}
	var found *xdm.Node
	n := 0
	xmltree.Walk(doc.Root(), func(e *xdm.Node) {
		for _, a := range e.Attrs {
			if a.Value == id && (isDefaultID(a.Name) || slices.ContainsFunc(extra, a.Name.Equal)) {
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
// Generated IDs are "id-" plus 32 hex characters from crypto/rand, unique
// within the document. The prefix keeps the value an NCName.
func AssignID(doc *xdm.Node, el *xdm.Node) (string, error) {
	if el == nil || el.Kind != xdm.KindElement {
		return "", fmt.Errorf("%w: AssignID needs an element", xmlsec.ErrMalformed)
	}
	unqualified := false
	switch el.Name.URI {
	case nsDSig, nsDSig11, nsXEnc, nsXEnc11:
		unqualified = true
	}
	a := el.Attr(NSWSU, "Id")
	if unqualified {
		a = el.Attr("", "Id")
	}
	if a != nil {
		return a.Value, nil
	}
	id, err := newID(doc)
	if err != nil {
		return "", err
	}
	if unqualified {
		xmltree.SetAttr(el, "", "", "Id", id)
		return id, nil
	}
	if err := setWSUID(el, id); err != nil {
		return "", err
	}
	return id, nil
}

func setWSUID(el *xdm.Node, id string) error {
	if err := xmltree.Declare(el, "wsu", NSWSU); err != nil {
		return err
	}
	xmltree.SetAttr(el, "wsu", NSWSU, "Id", id)
	return nil
}

// newID returns an ID not used anywhere in doc.
func newID(doc *xdm.Node) (string, error) {
	used := map[string]bool{}
	if doc != nil {
		xmltree.Walk(doc.Root(), func(e *xdm.Node) {
			for _, a := range e.Attrs {
				if isAnyID(a.Name) {
					used[a.Value] = true
				}
			}
		})
	}
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
