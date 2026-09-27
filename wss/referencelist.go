package wss

import (
	"errors"
	"fmt"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// NewReferenceList builds a standalone xenc:ReferenceList with an
// xenc:DataReference URI="#id" for each of ids, for the wsse:Security
// header (SOAP Message Security 1.1.1 sections 9.1 and 9.4.1). Each ID is
// the Id of an xenc:EncryptedData (see xenc.EncryptOptions.DataID) or the
// wsu:Id of a wsse11:EncryptedHeader (Basic Security Profile R5608). List
// every EncryptedData of one encryption step, under one key (R3231, R3205).
//
// It is the symmetric binding's list: each EncryptedData then names its
// key itself, by a ds:KeyInfo (xenc.EncryptOptions.DataKeyInfo, BSP
// R5629). When an xenc:EncryptedKey carries the list instead, use its
// AddDataReference. Place the list with Header.Prepend, after the
// EncryptedKey its EncryptedData reference, so the key precedes it.
//
// The element is detached. At least one ID is required, each an NCName,
// none twice.
func NewReferenceList(ids ...string) (*xdm.Node, error) {
	if len(ids) == 0 {
		return nil, errors.New("wss: NewReferenceList needs at least one ID")
	}
	list := xmltree.Element(nil, "xenc", xmlsec.NSXEnc, "ReferenceList")
	list.AddNamespace("xenc", xmlsec.NSXEnc)
	seen := map[string]bool{}
	for _, id := range ids {
		if !xdm.IsNCName(id) || seen[id] {
			return nil, fmt.Errorf("wss: data reference %q is not an NCName or is listed twice", id)
		}
		seen[id] = true
		xmltree.SetAttr(xmltree.Element(list, "xenc", xmlsec.NSXEnc, "DataReference"), "", "", "URI", "#"+id)
	}
	return list, nil
}
