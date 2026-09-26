package xenc

import (
	"errors"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// EncryptHeader replaces block, a SOAP header block (a direct child of a
// SOAP 1.1 or 1.2 Header), with a wsse11:EncryptedHeader holding an
// xenc:EncryptedData of Type Element encrypted as EncryptElement does, and
// returns the resulting document octets. doc itself is left unmodified.
//
// security is the wsse:Security header whose xenc:ReferenceList or
// xenc:EncryptedKey will reference the EncryptedData. WS-Security 1.1.1
// section 9.4.3 requires that its SOAP mustUnderstand and actor (1.1) or
// role and relay (1.2) attributes be copied to the EncryptedHeader, so a
// SOAP node treats the EncryptedHeader as the security header's own; the
// block's own attributes are encrypted with it, which is the point of
// EncryptedHeader. WSS4J copies them the same way. security must not be
// block.
func EncryptHeader(doc, block, security *xdm.Node, sessionKey []byte, opts EncryptOptions) ([]byte, error) {
	if err := checkTarget(doc, block); err != nil {
		return nil, err
	}
	if !isSOAP(block.Parent, "Header") {
		return nil, errors.New("xenc: EncryptHeader needs a SOAP header block")
	}
	if security == nil || !security.IsElement(nsWSSE, "Security") || security == block || security.Root() != doc.Root() {
		return nil, errors.New("xenc: EncryptHeader needs the referencing wsse:Security header, other than block")
	}
	return replaceElement(doc, block, sessionKey, opts, func(ed *xdm.Node) (*xdm.Node, error) {
		eh := nsElement(nil, "wsse11", NSWSSE11, "EncryptedHeader")
		eh.AppendChild(ed)
		// Declare against what is in scope where eh will sit; emitWith
		// links it there properly.
		eh.Parent = block.Parent
		for _, a := range security.Attrs {
			if (a.Name.URI == nsSOAP11 || a.Name.URI == nsSOAP12) &&
				(a.Name.Local == "mustUnderstand" || a.Name.Local == "actor" || a.Name.Local == "role" || a.Name.Local == "relay") {
				if err := xmltree.Declare(eh, a.Name.Prefix, a.Name.URI); err != nil {
					return nil, err
				}
				xmltree.SetAttr(eh, a.Name.Prefix, a.Name.URI, a.Name.Local, a.Value)
			}
		}
		return eh, nil
	})
}
