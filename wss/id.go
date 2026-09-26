package wss

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// randReader is replaced by tests that need deterministic IDs.
var randReader io.Reader = rand.Reader

// ids returns the element's wsu:Id and xml:id values.
func ids(e *xdm.Node) []string {
	var out []string
	for _, a := range e.Attrs {
		if a.Name.URI == NSWSU && a.Name.Local == "Id" ||
			a.Name.URI == NSXML && a.Name.Local == "id" {
			out = append(out, a.Value)
		}
	}
	return out
}

// FindByID returns the element bearing the given wsu:Id or xml:id.
//
// It returns xmlsec.ErrAmbiguousID if more than one element carries the ID,
// which is malformed input and is also an XML Signature Wrapping technique:
// duplicating an ID so that the verifier and the application resolve it to
// different elements. It never returns the first match. xdm.ElementByID is
// deliberately not used: it returns the first match.
func FindByID(doc *xdm.Node, id string) (*xdm.Node, error) {
	if doc == nil {
		return nil, fmt.Errorf("%w: %q: no document", xmlsec.ErrIDNotFound, id)
	}
	var found *xdm.Node
	n := 0
	xmltree.Walk(doc.Root(), func(e *xdm.Node) {
		for _, v := range ids(e) {
			if v == id {
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

// AssignID sets a wsu:Id on an element if it does not already have one, and
// returns the ID.
//
// Generated IDs are "id-" plus 32 hex characters from crypto/rand, unique
// within the document. The prefix keeps the value an NCName.
func AssignID(doc *xdm.Node, el *xdm.Node) (string, error) {
	if el == nil || el.Kind != xdm.KindElement {
		return "", fmt.Errorf("%w: AssignID needs an element", xmlsec.ErrMalformed)
	}
	if a := el.Attr(NSWSU, "Id"); a != nil {
		return a.Value, nil
	}
	id, err := newID(doc)
	if err != nil {
		return "", err
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
			for _, v := range ids(e) {
				used[v] = true
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
