package xenc

import (
	"slices"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/idref"
)

// ReferencedData returns the xenc:EncryptedData elements that list, an
// xenc:ReferenceList, names by its xenc:DataReference elements, in order:
// what a receiver decrypts for a ReferenceList in a wsse:Security header
// (SOAP Message Security 1.1.1 sections 9.1 and 9.4.2), or in an
// EncryptedKey. Each URI must be a same-document "#id", resolved through
// Id, wsu:Id and xml:id; an ID carried twice is xmlsec.ErrAmbiguousID.
//
// A DataReference may name a wsse11:EncryptedHeader by its wsu:Id (Basic
// Security Profile R5608); its one xenc:EncryptedData is returned, whose
// Parent is the EncryptedHeader to pass to DecryptHeader. Any other target,
// a DataReference listed twice, and a list with no DataReference are
// xmlsec.ErrMalformed. xenc:KeyReference elements are skipped. Find each
// one's key with FindEncryptedKey.
func ReferencedData(list *xdm.Node) ([]*xdm.Node, error) {
	if list == nil || !list.IsElement(xmlsec.NSXEnc, "ReferenceList") {
		return nil, malformed("not an xenc:ReferenceList")
	}
	var out []*xdm.Node
	for _, r := range list.ChildElements() {
		if r.IsElement(xmlsec.NSXEnc, "KeyReference") {
			continue
		}
		if !r.IsElement(xmlsec.NSXEnc, "DataReference") {
			return nil, malformed("%s in an xenc:ReferenceList", r.Name.Local)
		}
		uri := r.AttrValue("URI")
		id, ok := strings.CutPrefix(uri, "#")
		if !ok || id == "" {
			return nil, malformed("xenc:DataReference URI %q is not a local #id", uri)
		}
		t, err := idref.Find(list, id, idAttr)
		if err != nil {
			return nil, err
		}
		if t.IsElement(xmlsec.NSWSSE11, "EncryptedHeader") {
			if kids := t.ChildElements(); len(kids) == 1 {
				t = kids[0]
			}
		}
		if !t.IsElement(xmlsec.NSXEnc, "EncryptedData") {
			return nil, malformed("xenc:DataReference %q names a %s, not an xenc:EncryptedData", uri, t.Name.Local)
		}
		if slices.Contains(out, t) {
			return nil, malformed("xenc:DataReference %q listed twice", uri)
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, malformed("an xenc:ReferenceList without xenc:DataReference")
	}
	return out, nil
}
