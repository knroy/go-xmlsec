package xenc

import (
	"fmt"

	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
)

// AddKeyReference adds an xenc:KeyReference to the EncryptedKey's
// xenc:ReferenceList, creating the list if needed (section 3.6). id is the
// Id of an xenc:EncryptedKey whose key encryption key this one carries, so
// that FindEncryptedKey on that EncryptedKey finds this one; it must be an
// NCName.
func (ek *EncryptedKey) AddKeyReference(id string) error {
	if err := ek.check(); err != nil {
		return err
	}
	if !xdm.IsNCName(id) {
		return fmt.Errorf("xenc: key reference %q is not an NCName", id)
	}
	ek.addReference("KeyReference", id)
	return nil
}

// addReference adds an xenc:DataReference or xenc:KeyReference (local) to
// "#"+id to ek's xenc:ReferenceList, creating the list in its schema place
// if there is none. ek.Element becomes a new element.
func (ek *EncryptedKey) addReference(local, id string) {
	ref := element(nil, local)
	xmltree.SetAttr(ref, "", "", "URI", "#"+id)
	for _, k := range ek.Element.ChildElements() {
		if k.IsElement(xmlsec.NSXEnc, "ReferenceList") {
			var e xmltree.Edits
			e.Insert(k, k.NumChildren(), ref)
			ek.Element, _ = xmltree.Rebuild(ek.Element, &e)
			return
		}
	}
	list := element(nil, "ReferenceList")
	list.AppendCopy(ref)
	ek.Element = withChild(ek.Element, list)
}
