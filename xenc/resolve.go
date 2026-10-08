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

// keyKind is what FindEncryptedKey or FindDerivedKey looks for: the key
// element, the ds:RetrievalMethod Type that names it, and its child whose
// value a ds:KeyName matches.
type keyKind struct {
	ns, local, typ, nameNS, name string
}

var (
	encryptedKeyKind = keyKind{xmlsec.NSXEnc, "EncryptedKey", TypeEncryptedKey, xmlsec.NSXEnc, "CarriedKeyName"}
	derivedKeyKind   = keyKind{xmlsec.NSXEnc11, "DerivedKey", TypeDerivedKey, xmlsec.NSXEnc11, "DerivedKeyName"}
)

// FindEncryptedKey returns the xenc:EncryptedKey holding the key of el, an
// xenc:EncryptedData or an xenc:EncryptedKey whose key encryption key is
// itself encrypted, found the ways sections 3.5.1 and 3.6 provide:
//
//   - el's ds:KeyInfo holds an xenc:EncryptedKey; a same-document
//     ds:RetrievalMethod with Type TypeEncryptedKey whose URI "#id" names
//     an xenc:EncryptedKey, or several that all name the same one; or a
//     ds:KeyName equal to the xenc:CarriedKeyName of exactly one
//     xenc:EncryptedKey in the document; or a wsse:SecurityTokenReference
//     holding exactly one wsse:Reference whose URI "#id" names an
//     xenc:EncryptedKey (WS-Security's symmetric binding, SOAP Message
//     Security 1.1.1 section 7.7);
//   - el has no ds:KeyInfo: the one xenc:EncryptedKey in the document whose
//     xenc:ReferenceList has an xenc:DataReference (for an EncryptedData)
//     or xenc:KeyReference (for an EncryptedKey) to el's Id, as a
//     WS-Security header carries it.
//
// It takes one hop: the EncryptedKey found is not followed further. To
// walk a chain, call it again on the result, bounding the number of calls:
// a chain can be a cycle. An EncryptedKey naming itself is
// xmlsec.ErrMalformed.
//
// IDs resolve through Id, wsu:Id and xml:id, and a value carried twice is
// xmlsec.ErrAmbiguousID. More than one candidate EncryptedKey is refused
// the same way. Any other ds:KeyInfo, such as an xenc:AgreementMethod or an
// xenc11:DerivedKey, is xmlsec.ErrUnsupportedKeyInfo.
//
// It is opt-in: DecryptData never looks for a key. Decrypt the result with
// DecryptEncryptedKey, UnwrapEncryptedKey, DecryptAgreedKey,
// DecryptAgreedKeyDH or UnwrapEncryptedKeyPassword.
func FindEncryptedKey(el *xdm.Node) (*xdm.Node, error) {
	return findKey(el, encryptedKeyKind)
}

// FindDerivedKey returns the xenc11:DerivedKey describing the key of el, an
// xenc:EncryptedData or xenc:EncryptedKey, found the ways sections 3.5.2
// and 3.6 provide, as FindEncryptedKey finds an EncryptedKey: an
// xenc11:DerivedKey in el's ds:KeyInfo, a same-document ds:RetrievalMethod
// with Type TypeDerivedKey, or the xenc11 namespace's
// "http://www.w3.org/2009/xmlenc11#DerivedKey" that section 3.5.3 names
// (or several naming the same element), a
// ds:KeyName equal to the xenc11:DerivedKeyName of exactly one DerivedKey
// in the document, or, when el has no ds:KeyInfo, the one DerivedKey whose
// xenc:ReferenceList has a DataReference or KeyReference to el's Id.
// Derive the key with DeriveKey.
func FindDerivedKey(el *xdm.Node) (*xdm.Node, error) {
	return findKey(el, derivedKeyKind)
}

// findKey finds the key element of kind k for el.
func findKey(el *xdm.Node, k keyKind) (*xdm.Node, error) {
	ref := "DataReference"
	switch {
	case el != nil && el.IsElement(xmlsec.NSXEnc, "EncryptedData"):
	case el != nil && el.IsElement(xmlsec.NSXEnc, "EncryptedKey"):
		ref = "KeyReference"
	default:
		return nil, malformed("not an xenc:EncryptedData or xenc:EncryptedKey")
	}
	var found *xdm.Node
	var err error
	if ki := keyInfo(el); ki != nil {
		found, err = inKeyInfo(el, ki, k)
	} else {
		found, err = byReference(el, ref, k)
	}
	if err == nil && found == el {
		return nil, malformed("an xenc:EncryptedKey names itself as its key")
	}
	return found, err
}

// inKeyInfo resolves the key of kind k in ki, el's ds:KeyInfo.
func inKeyInfo(el, ki *xdm.Node, k keyKind) (*xdm.Node, error) {
	kids := ki.ChildElements()
	retrievals := len(kids) > 0
	for _, c := range kids {
		retrievals = retrievals && c.IsElement(xmlsec.NSDSig, "RetrievalMethod")
	}
	if retrievals {
		var found *xdm.Node
		for _, c := range kids {
			t, err := retrieve(el, c, k)
			if err != nil {
				return nil, err
			}
			if found != nil && t != found {
				return nil, fmt.Errorf("%w: ds:RetrievalMethod elements naming different %s elements", xmlsec.ErrAmbiguousID, k.local)
			}
			found = t
		}
		return found, nil
	}
	if len(kids) != 1 {
		return nil, fmt.Errorf("%w: ds:KeyInfo must hold exactly one key reference", xmlsec.ErrUnsupportedKeyInfo)
	}
	c := kids[0]
	switch {
	case c.IsElement(k.ns, k.local):
		return c, nil
	case c.IsElement(xmlsec.NSDSig, "KeyName"):
		name := c.StringValue()
		return oneKey(el, k, "named "+name, func(e *xdm.Node) bool {
			for _, n := range e.ChildElements() {
				if n.IsElement(k.nameNS, k.name) && n.StringValue() == name {
					return true
				}
			}
			return false
		})
	case k == encryptedKeyKind && c.IsElement(xmlsec.NSWSSE, "SecurityTokenReference"):
		return strEncryptedKey(el, c)
	}
	return nil, fmt.Errorf("%w: %s in the ds:KeyInfo of an xenc:%s", xmlsec.ErrUnsupportedKeyInfo, c.Name.Local, el.Name.Local)
}

// retrieve resolves rm, a ds:RetrievalMethod, to the key element of kind k
// it names in el's document.
func retrieve(el, rm *xdm.Node, k keyKind) (*xdm.Node, error) {
	uri, typ := rm.AttrValue("URI"), rm.AttrValue("Type")
	if k == derivedKeyKind && typ == typeDerivedKey11 {
		typ = k.typ
	}
	if typ != k.typ || !strings.HasPrefix(uri, "#") || len(rm.ChildElements()) > 0 {
		return nil, fmt.Errorf("%w: only a same-document ds:RetrievalMethod of Type %s without transforms", xmlsec.ErrUnsupportedKeyInfo, k.typ)
	}
	t, err := idref.Find(el, uri[1:], idAttr)
	if err != nil {
		return nil, err
	}
	if !t.IsElement(k.ns, k.local) {
		return nil, malformed("ds:RetrievalMethod %q names a %s, not a %s", uri, t.Name.Local, k.local)
	}
	return t, nil
}

// byReference finds the key element of kind k whose ReferenceList has a
// ref, DataReference or KeyReference, to el.
func byReference(el *xdm.Node, ref string, k keyKind) (*xdm.Node, error) {
	id := el.AttrValue("Id")
	if id == "" {
		return nil, fmt.Errorf("%w: an xenc:%s with neither ds:KeyInfo nor Id", xmlsec.ErrUnsupportedKeyInfo, el.Name.Local)
	}
	// el must be the only element carrying its ID, or a reference could
	// mean another.
	if _, err := idref.Find(el, id, idAttr); err != nil {
		return nil, err
	}
	return oneKey(el, k, "referencing #"+id, func(e *xdm.Node) bool {
		for _, c := range e.ChildElements() {
			if c.IsElement(xmlsec.NSXEnc, "ReferenceList") {
				for _, r := range c.ChildElements() {
					if r.IsElement(xmlsec.NSXEnc, ref) && r.AttrValue("URI") == "#"+id {
						return true
					}
				}
			}
		}
		return false
	})
}

// oneKey returns the one key element of kind k in n's document, other than
// n, for which match is true.
func oneKey(n *xdm.Node, k keyKind, what string, match func(*xdm.Node) bool) (*xdm.Node, error) {
	var found []*xdm.Node
	xmltree.Walk(n.Root(), func(e *xdm.Node) {
		if e != n && e.IsElement(k.ns, k.local) && match(e) {
			found = append(found, e)
		}
	})
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("%w: no %s %s", xmlsec.ErrIDNotFound, k.local, what)
	case 1:
		return found[0], nil
	}
	return nil, fmt.Errorf("%w: %d %s elements %s", xmlsec.ErrAmbiguousID, len(found), k.local, what)
}
