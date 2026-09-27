package wss

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// NewEncryptedKeyReference builds a wsse:SecurityTokenReference to the
// xenc:EncryptedKey in the same message whose Id is ekID (SOAP Message
// Security 1.1.1 section 7.7), under the wsse11:TokenType the Basic Security
// Profile requires (R3069): the element NewSecurityTokenReference builds for
// ekID and the EncryptedKey ValueType, which is what xenc's symmetric
// binding (xenc.EncryptOptions.DataKeyInfo) and WSS4J write. Place it in the
// ds:KeyInfo of a signature or an xenc:EncryptedData keyed by that
// EncryptedKey. ReferencedToken resolves it.
//
// It returns nil for an empty ekID. The element is detached; place it where
// it is used.
func NewEncryptedKeyReference(ekID string) *xdm.Node {
	// Given a ValueType, NewSecurityTokenReference reads no document, and
	// fails only for an empty ID.
	str, _ := NewSecurityTokenReference(nil, ekID, valueTypeEncryptedKey)
	return str
}

// NewEncryptedKeySHA1Reference builds a wsse:SecurityTokenReference naming
// ek, an xenc:EncryptedKey, from a message that does not carry it (SOAP
// Message Security 1.1.1 section 7.7): a wsse:KeyIdentifier holding the
// SHA-1 of the octets of its xenc:CipherValue, base64, with the ValueType,
// EncodingType and wsse11:TokenType the Basic Security Profile requires
// (R3072, R3070, R3071, R3069). An ek without an xenc:CipherValue is refused
// with xmlsec.ErrMalformed.
//
// SHA-1 here is an identifier the specification mandates, as for
// ThumbprintSHA1: it names a key both parties already hold.
//
// The element is detached; place it where it is used.
func NewEncryptedKeySHA1Reference(ek *xdm.Node) (*xdm.Node, error) {
	id, err := encryptedKeySHA1(ek)
	if err != nil {
		return nil, err
	}
	str := encryptedKeySTR()
	ki := xmltree.Element(str, "wsse", xmlsec.NSWSSE, "KeyIdentifier")
	xmltree.SetAttr(ki, "", "", "EncodingType", xmlsec.BSTEncodingBase64)
	xmltree.SetAttr(ki, "", "", "ValueType", valueTypeEncryptedKeySHA1)
	xmltree.Text(ki, base64.StdEncoding.EncodeToString(id))
	return str, nil
}

// MatchEncryptedKeySHA1 reports whether str names ek by an EncryptedKeySHA1
// key identifier: a single wsse:KeyIdentifier of that ValueType, base64
// (EncodingType absent or Base64Binary), whose value is the SHA-1 of the
// octets of ek's xenc:CipherValue, and a wsse11:TokenType, if any, of
// EncryptedKey. Use it to find which EncryptedKey from an earlier message a
// reply keys with; any other form is false.
func MatchEncryptedKeySHA1(str, ek *xdm.Node) bool {
	if str == nil || !str.IsElement(xmlsec.NSWSSE, "SecurityTokenReference") {
		return false
	}
	if tt := str.Attr(xmlsec.NSWSSE11, "TokenType"); tt != nil && tt.Value != valueTypeEncryptedKey {
		return false
	}
	kids := str.ChildElements()
	if len(kids) != 1 || !kids[0].IsElement(xmlsec.NSWSSE, "KeyIdentifier") || kids[0].AttrValue("ValueType") != valueTypeEncryptedKeySHA1 {
		return false
	}
	if enc := kids[0].Attr("", "EncodingType"); enc != nil && enc.Value != xmlsec.BSTEncodingBase64 {
		return false
	}
	got, err := xmltree.Base64(kids[0])
	want, err2 := encryptedKeySHA1(ek)
	return err == nil && err2 == nil && bytes.Equal(got, want)
}

// encryptedKeySTR returns an empty wsse:SecurityTokenReference typed as a
// reference to an EncryptedKey.
func encryptedKeySTR() *xdm.Node {
	str := newSTR()
	str.AddNamespace("wsse11", xmlsec.NSWSSE11)
	xmltree.SetAttr(str, "wsse11", xmlsec.NSWSSE11, "TokenType", valueTypeEncryptedKey)
	return str
}

// encryptedKeySHA1 is the SHA-1 of the octets of ek's
// xenc:CipherData/xenc:CipherValue.
func encryptedKeySHA1(ek *xdm.Node) ([]byte, error) {
	if ek == nil || !ek.IsElement(xmlsec.NSXEnc, "EncryptedKey") {
		return nil, fmt.Errorf("%w: not an xenc:EncryptedKey", xmlsec.ErrMalformed)
	}
	for _, cd := range ek.ChildElements() {
		if !cd.IsElement(xmlsec.NSXEnc, "CipherData") {
			continue
		}
		if cv := cd.ChildElements(); len(cv) == 1 && cv[0].IsElement(xmlsec.NSXEnc, "CipherValue") {
			octets, err := xmltree.Base64(cv[0])
			if err != nil || len(octets) == 0 {
				return nil, fmt.Errorf("%w: xenc:CipherValue is not base64", xmlsec.ErrMalformed)
			}
			return sha1Sum(octets), nil
		}
	}
	return nil, fmt.Errorf("%w: xenc:EncryptedKey has no xenc:CipherValue", xmlsec.ErrMalformed)
}
