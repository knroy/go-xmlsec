package xenc

import (
	"fmt"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/idref"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// idAttr is the Id attribute of XML Encryption elements, which counts as an
// ID beside wsu:Id and xml:id when resolving "#id".
var idAttr = xdm.QName{Local: "Id"}

// FindEncryptedKey returns the xenc:EncryptedKey holding the key of ed, an
// xenc:EncryptedData, found the ways section 3.5 provides:
//
//   - ed's ds:KeyInfo holds exactly one child: an xenc:EncryptedKey, a
//     same-document ds:RetrievalMethod with Type TypeEncryptedKey whose URI
//     "#id" names an xenc:EncryptedKey (one hop: the target is not followed
//     further), or a ds:KeyName equal to the xenc:CarriedKeyName of exactly
//     one xenc:EncryptedKey in the document;
//   - ed has no ds:KeyInfo: the one xenc:EncryptedKey in the document whose
//     xenc:ReferenceList has an xenc:DataReference to ed's Id, as a
//     WS-Security header carries it.
//
// IDs resolve through Id, wsu:Id and xml:id, and a value carried twice is
// xmlsec.ErrAmbiguousID. More than one candidate EncryptedKey is refused
// the same way. Any other ds:KeyInfo is xmlsec.ErrUnsupportedKeyInfo.
//
// It is opt-in: DecryptData never looks for a key. Decrypt the result with
// DecryptEncryptedKey, UnwrapEncryptedKey or DecryptAgreedKey.
func FindEncryptedKey(ed *xdm.Node) (*xdm.Node, error) {
	if ed == nil || !ed.IsElement(xmlsec.NSXEnc, "EncryptedData") {
		return nil, malformed("not an xenc:EncryptedData")
	}
	var ki *xdm.Node
	for _, k := range ed.ChildElements() {
		if k.IsElement(xmlsec.NSDSig, "KeyInfo") {
			ki = k
		}
	}
	if ki == nil {
		return byReference(ed)
	}
	kids := ki.ChildElements()
	if len(kids) != 1 {
		return nil, fmt.Errorf("%w: ds:KeyInfo must hold exactly one key reference", xmlsec.ErrUnsupportedKeyInfo)
	}
	k := kids[0]
	switch {
	case k.IsElement(xmlsec.NSXEnc, "EncryptedKey"):
		return k, nil
	case k.IsElement(xmlsec.NSDSig, "RetrievalMethod"):
		uri := k.AttrValue("URI")
		if k.AttrValue("Type") != TypeEncryptedKey || !strings.HasPrefix(uri, "#") || len(k.ChildElements()) > 0 {
			return nil, fmt.Errorf("%w: only a same-document ds:RetrievalMethod of Type %s without transforms", xmlsec.ErrUnsupportedKeyInfo, TypeEncryptedKey)
		}
		t, err := idref.Find(ed, uri[1:], idAttr)
		if err != nil {
			return nil, err
		}
		if !t.IsElement(xmlsec.NSXEnc, "EncryptedKey") {
			return nil, malformed("ds:RetrievalMethod %q names a %s, not an xenc:EncryptedKey", uri, t.Name.Local)
		}
		return t, nil
	case k.IsElement(xmlsec.NSDSig, "KeyName"):
		name := k.StringValue()
		return oneKey(ed, "carrying name "+name, func(ek *xdm.Node) bool {
			for _, c := range ek.ChildElements() {
				if c.IsElement(xmlsec.NSXEnc, "CarriedKeyName") && c.StringValue() == name {
					return true
				}
			}
			return false
		})
	}
	return nil, fmt.Errorf("%w: %s in the ds:KeyInfo of an xenc:EncryptedData", xmlsec.ErrUnsupportedKeyInfo, k.Name.Local)
}

// byReference finds the EncryptedKey whose ReferenceList names ed.
func byReference(ed *xdm.Node) (*xdm.Node, error) {
	id := ed.AttrValue("Id")
	if id == "" {
		return nil, fmt.Errorf("%w: an xenc:EncryptedData with neither ds:KeyInfo nor Id", xmlsec.ErrUnsupportedKeyInfo)
	}
	// ed must be the only element carrying its ID, or a DataReference
	// could mean another.
	if _, err := idref.Find(ed, id, idAttr); err != nil {
		return nil, err
	}
	return oneKey(ed, "referencing #"+id, func(ek *xdm.Node) bool {
		for _, c := range ek.ChildElements() {
			if c.IsElement(xmlsec.NSXEnc, "ReferenceList") {
				for _, r := range c.ChildElements() {
					if r.IsElement(xmlsec.NSXEnc, "DataReference") && r.AttrValue("URI") == "#"+id {
						return true
					}
				}
			}
		}
		return false
	})
}

// oneKey returns the one xenc:EncryptedKey in n's document for which match
// is true.
func oneKey(n *xdm.Node, what string, match func(*xdm.Node) bool) (*xdm.Node, error) {
	var found []*xdm.Node
	xmltree.Walk(n.Root(), func(e *xdm.Node) {
		if e.IsElement(xmlsec.NSXEnc, "EncryptedKey") && match(e) {
			found = append(found, e)
		}
	})
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("%w: no xenc:EncryptedKey %s", xmlsec.ErrIDNotFound, what)
	case 1:
		return found[0], nil
	}
	return nil, fmt.Errorf("%w: %d xenc:EncryptedKey elements %s", xmlsec.ErrAmbiguousID, len(found), what)
}
