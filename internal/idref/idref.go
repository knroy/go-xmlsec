// Package idref resolves same-document "#id" references for packages that
// cannot import wss, with the rule wss.FindByID applies: an ID
// carried more than once is refused, never resolved to its first match.
package idref

import (
	"fmt"
	"slices"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// Find returns the one element of n's document carrying id in wsu:Id,
// xml:id or one of extra. Every counted attribute forms one set: the value
// on any two of them is xmlsec.ErrAmbiguousID.
func Find(n *xdm.Node, id string, extra ...xdm.QName) (*xdm.Node, error) {
	counted := append([]xdm.QName{{URI: xmlsec.NSWSU, Local: "Id"}, {URI: xdm.NSXML, Local: "id"}}, extra...)
	var found *xdm.Node
	count := 0
	xmltree.Walk(n.Root(), func(e *xdm.Node) {
		for _, a := range e.Attrs {
			if a.Value == id && slices.ContainsFunc(counted, a.Name.Equal) {
				found = e
				count++
			}
		}
	})
	switch count {
	case 0:
		return nil, fmt.Errorf("%w: %q", xmlsec.ErrIDNotFound, id)
	case 1:
		return found, nil
	}
	return nil, fmt.Errorf("%w: %q appears %d times", xmlsec.ErrAmbiguousID, id, count)
}
