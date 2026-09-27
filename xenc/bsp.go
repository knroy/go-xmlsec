package xenc

import (
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
)

// strictKey applies the Basic Security Profile rules of
// DecryptOptions.StrictBSP to el, an xenc:EncryptedKey, when opts asks for
// them. Anything else is left to the caller's own element check.
func strictKey(el *xdm.Node, opts DecryptOptions) error {
	if !opts.StrictBSP || el == nil || !el.IsElement(xmlsec.NSXEnc, "EncryptedKey") {
		return nil
	}
	for _, a := range []struct{ name, rule string }{
		{"Type", "R3209"}, {"MimeType", "R5622"}, {"Encoding", "R5623"}, {"Recipient", "R5602"},
	} {
		if el.Attr("", a.name) != nil {
			return malformed("xenc:EncryptedKey with a %s attribute (BSP %s)", a.name, a.rule)
		}
	}
	return strictKeyInfo(el)
}

// strictData applies the Basic Security Profile rules of
// DecryptOptions.StrictBSP to el, an xenc:EncryptedData, when opts asks
// for them.
func strictData(el *xdm.Node, opts DecryptOptions) error {
	if !opts.StrictBSP || el == nil || !el.IsElement(xmlsec.NSXEnc, "EncryptedData") {
		return nil
	}
	if el.Parent != nil && isSOAP(el.Parent, "Header") {
		return malformed("xenc:EncryptedData as a SOAP header block (BSP R3228)")
	}
	if keyInfo(el) == nil {
		if _, err := byReference(el, "DataReference", encryptedKeyKind); err != nil {
			return malformed("xenc:EncryptedData with no ds:KeyInfo that no one xenc:EncryptedKey names (BSP R5629): %v", err)
		}
	}
	return strictKeyInfo(el)
}

// strictKeyInfo requires el's ds:KeyInfo, if any, to hold exactly one
// wsse:SecurityTokenReference.
func strictKeyInfo(el *xdm.Node) error {
	ki := keyInfo(el)
	if ki == nil {
		return nil
	}
	if kids := ki.ChildElements(); len(kids) != 1 || !kids[0].IsElement(xmlsec.NSWSSE, "SecurityTokenReference") {
		return malformed("the ds:KeyInfo of an %s must hold exactly one wsse:SecurityTokenReference (BSP R5424, R5426)", el.Name.Local)
	}
	return nil
}
