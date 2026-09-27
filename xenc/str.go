package xenc

import (
	"fmt"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/idref"
)

// strEncryptedKey resolves str, a wsse:SecurityTokenReference in the
// ds:KeyInfo of ed, to the xenc:EncryptedKey it names: exactly one
// wsse:Reference with URI "#id" (SOAP Message Security 1.1.1 section 7.7).
// One hop: the target must itself be an xenc:EncryptedKey.
func strEncryptedKey(ed, str *xdm.Node) (*xdm.Node, error) {
	kids := str.ChildElements()
	if len(kids) != 1 || !kids[0].IsElement(xmlsec.NSWSSE, "Reference") {
		return nil, fmt.Errorf("%w: only a wsse:SecurityTokenReference holding one wsse:Reference names an xenc:EncryptedKey", xmlsec.ErrUnsupportedKeyInfo)
	}
	uri := kids[0].AttrValue("URI")
	id, ok := strings.CutPrefix(uri, "#")
	if !ok || id == "" {
		return nil, fmt.Errorf("%w: wsse:Reference URI %q is not a local #id", xmlsec.ErrUnsupportedKeyInfo, uri)
	}
	t, err := idref.Find(ed, id, idAttr)
	if err != nil {
		return nil, err
	}
	if !t.IsElement(xmlsec.NSXEnc, "EncryptedKey") {
		return nil, malformed("wsse:Reference %q names a %s, not an xenc:EncryptedKey", uri, t.Name.Local)
	}
	return t, nil
}
