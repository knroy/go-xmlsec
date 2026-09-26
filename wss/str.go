package wss

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// NewSecurityTokenReference builds a wsse:SecurityTokenReference with a
// direct wsse:Reference to a local token by wsu:Id.
//
// This is the only reference form this library emits. Issuer-and-serial and
// thumbprint references are legal WS-Security and are not emitted.
//
// The element is detached; doc is the document it will be placed in.
func NewSecurityTokenReference(doc *xdm.Node, tokenID, valueType string) (*xdm.Node, error) {
	if tokenID == "" {
		return nil, fmt.Errorf("wss: empty token ID")
	}
	str := xmltree.Element(nil, "wsse", NSWSSE, "SecurityTokenReference")
	str.AddNamespace("wsse", NSWSSE)
	ref := xmltree.Element(str, "wsse", NSWSSE, "Reference")
	xmltree.SetAttr(ref, "", "", "URI", "#"+tokenID)
	if valueType != "" {
		xmltree.SetAttr(ref, "", "", "ValueType", valueType)
	}
	return str, nil
}

// ResolveSecurityTokenReference follows a direct-reference
// wsse:SecurityTokenReference to its wsse:BinarySecurityToken in doc and
// returns the certificate it carries. Other reference forms are refused
// with xmlsec.ErrUnsupportedKeyInfo.
func ResolveSecurityTokenReference(doc, str *xdm.Node) (*x509.Certificate, error) {
	if !str.IsElement(NSWSSE, "SecurityTokenReference") {
		return nil, fmt.Errorf("%w: not a wsse:SecurityTokenReference", xmlsec.ErrUnsupportedKeyInfo)
	}
	kids := str.ChildElements()
	if len(kids) != 1 || !kids[0].IsElement(NSWSSE, "Reference") {
		return nil, fmt.Errorf("%w: only a single direct wsse:Reference is accepted", xmlsec.ErrUnsupportedKeyInfo)
	}
	id, ok := strings.CutPrefix(kids[0].AttrValue("URI"), "#")
	if !ok || id == "" {
		return nil, fmt.Errorf("%w: wsse:Reference URI must be a local #id", xmlsec.ErrUnsupportedKeyInfo)
	}
	tok, err := FindByID(doc, id)
	if err != nil {
		return nil, err
	}
	return ParseBinarySecurityToken(tok)
}
