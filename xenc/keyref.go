package xenc

import (
	"fmt"
	"slices"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// AddKeyReference adds an xenc:KeyReference to the EncryptedKey's
// xenc:ReferenceList, creating the list if needed (section 3.6). id is the
// Id of an xenc:EncryptedKey whose key encryption key this one carries, so
// that FindEncryptedKey on that EncryptedKey finds this one; it must be an
// NCName.
func (ek *EncryptedKey) AddKeyReference(id string) error {
	if !xdm.IsNCName(id) {
		return fmt.Errorf("xenc: key reference %q is not an NCName", id)
	}
	var list *xdm.Node
	for _, k := range ek.Element.ChildElements() {
		if k.IsElement(xmlsec.NSXEnc, "ReferenceList") {
			list = k
		}
	}
	if list == nil {
		list = element(ek.Element, "ReferenceList")
		// Schema order: ReferenceList before CarriedKeyName.
		kids := ek.Element.Children
		if i := slices.IndexFunc(kids, func(n *xdm.Node) bool { return n.IsElement(xmlsec.NSXEnc, "CarriedKeyName") }); i >= 0 {
			copy(kids[i+1:], kids[i:len(kids)-1])
			kids[i] = list
		}
	}
	xmltree.SetAttr(element(list, "KeyReference"), "", "", "URI", "#"+id)
	return nil
}
