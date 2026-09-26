package wss

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// newSTR returns an empty, detached wsse:SecurityTokenReference.
func newSTR() *xdm.Node {
	str := xmltree.Element(nil, "wsse", xmlsec.NSWSSE, "SecurityTokenReference")
	str.AddNamespace("wsse", xmlsec.NSWSSE)
	return str
}

// NewSecurityTokenReference builds a wsse:SecurityTokenReference with a
// direct wsse:Reference to a token in doc by its wsu:Id.
//
// valueType is the token's ValueType, which the Basic Security Profile
// requires on the reference (R3059, R3058). Empty means the ValueType of the
// token in doc bearing tokenID; a token that is not there, or has none, is
// an error. A reference to an X509PKIPathv1 or PKCS7 token also carries the
// wsse11:TokenType BSP requires (R5215, R5212). An X509v3 reference does
// not: neither SOAP Message Security nor BSP asks for it there.
//
// The element is detached; place it where it is used.
func NewSecurityTokenReference(doc *xdm.Node, tokenID, valueType string) (*xdm.Node, error) {
	if tokenID == "" {
		return nil, errors.New("wss: empty token ID")
	}
	if valueType == "" {
		tok, err := FindByID(doc, tokenID)
		if err != nil {
			return nil, fmt.Errorf("wss: no ValueType given: %w", err)
		}
		if valueType = tok.AttrValue("ValueType"); valueType == "" {
			return nil, fmt.Errorf("%w: token %q has no ValueType", xmlsec.ErrUnsupportedKeyInfo, tokenID)
		}
	}
	str := newSTR()
	if valueType == xmlsec.BSTValueTypeX509PKIPath || valueType == xmlsec.BSTValueTypePKCS7 {
		str.AddNamespace("wsse11", xmlsec.NSWSSE11)
		xmltree.SetAttr(str, "wsse11", xmlsec.NSWSSE11, "TokenType", valueType)
	}
	ref := xmltree.Element(str, "wsse", xmlsec.NSWSSE, "Reference")
	xmltree.SetAttr(ref, "", "", "URI", "#"+tokenID)
	xmltree.SetAttr(ref, "", "", "ValueType", valueType)
	return str, nil
}

// thumbprintSHA1 is the SHA-1 of the certificate's DER octets, the
// ThumbprintSHA1 key identifier of SOAP Message Security 1.1.1 and BSP R5210.
// SHA-1 here is an identifier the profile mandates, not a signature or
// digest algorithm: it names a certificate the receiver already holds, and
// the key is always the caller's (see MatchSecurityTokenReference).
func thumbprintSHA1(cert *x509.Certificate) []byte {
	h := crypto.SHA1.New() // linked in by crypto/x509
	h.Write(cert.Raw)
	return h.Sum(nil)
}

// NewKeyIdentifierReference builds a wsse:SecurityTokenReference naming cert
// by a wsse:KeyIdentifier, for a certificate that is not in the message
// (BSP R5209): its X509SubjectKeyIdentifier, or, when the certificate has no
// SubjectKeyIdentifier extension, its ThumbprintSHA1 (X.509 Token Profile
// 1.1.1 section 3.2.1, BSP R5206, R5208, R5210). The identifier is base64,
// with the EncodingType BSP requires (R3070, R3071).
//
// The element is detached; place it where it is used.
func NewKeyIdentifierReference(cert *x509.Certificate) (*xdm.Node, error) {
	if cert == nil || len(cert.Raw) == 0 {
		return nil, errors.New("wss: NewKeyIdentifierReference needs a parsed certificate")
	}
	vt, id := valueTypeSKI, cert.SubjectKeyId
	if len(id) == 0 {
		vt, id = valueTypeThumbprintSHA1, thumbprintSHA1(cert)
	}
	str := newSTR()
	ki := xmltree.Element(str, "wsse", xmlsec.NSWSSE, "KeyIdentifier")
	xmltree.SetAttr(ki, "", "", "EncodingType", xmlsec.BSTEncodingBase64)
	xmltree.SetAttr(ki, "", "", "ValueType", vt)
	xmltree.Text(ki, base64.StdEncoding.EncodeToString(id))
	return str, nil
}

// NewIssuerSerialReference builds a wsse:SecurityTokenReference naming cert
// by ds:X509Data/ds:X509IssuerSerial, for a certificate that is not in the
// message (X.509 Token Profile 1.1.1 section 3.2.3, BSP R5209). The issuer
// is an RFC 4514 string, in the certificate's own attribute order; the
// serial number is decimal.
//
// The element is detached; place it where it is used.
func NewIssuerSerialReference(cert *x509.Certificate) (*xdm.Node, error) {
	var issuer pkix.RDNSequence
	if cert == nil || cert.SerialNumber == nil {
		return nil, errors.New("wss: NewIssuerSerialReference needs a parsed certificate")
	}
	if rest, err := asn1.Unmarshal(cert.RawIssuer, &issuer); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("%w: certificate issuer", xmlsec.ErrMalformed)
	}
	str := newSTR()
	xd := xmltree.Element(str, "ds", xmlsec.NSDSig, "X509Data")
	xd.AddNamespace("ds", xmlsec.NSDSig)
	is := xmltree.Element(xd, "ds", xmlsec.NSDSig, "X509IssuerSerial")
	xmltree.Text(xmltree.Element(is, "ds", xmlsec.NSDSig, "X509IssuerName"), issuer.String())
	xmltree.Text(xmltree.Element(is, "ds", xmlsec.NSDSig, "X509SerialNumber"), cert.SerialNumber.String())
	return str, nil
}

// ResolveSecurityTokenReference follows a direct-reference
// wsse:SecurityTokenReference to its wsse:BinarySecurityToken in doc and
// returns the certificate it carries. Other reference forms are refused
// with xmlsec.ErrUnsupportedKeyInfo.
//
// It is lenient about how the reference is written, as most receivers are;
// ResolveSecurityTokenReferenceStrict adds the Basic Security Profile's
// checks.
func ResolveSecurityTokenReference(doc, str *xdm.Node) (*x509.Certificate, error) {
	tok, err := referencedToken(doc, str)
	if err != nil {
		return nil, err
	}
	return ParseBinarySecurityToken(tok)
}

// ResolveSecurityTokenReferenceStrict is ResolveSecurityTokenReference with
// the Basic Security Profile's rules for the reference, refusing with
// xmlsec.ErrMalformed a reference that:
//
//   - has no ValueType, or one other than the token's (R3059, R3058);
//   - has a wsse11:TokenType other than the token's ValueType, or none when
//     the token is an X509PKIPathv1 or PKCS7 token (SOAP Message Security
//     1.1.1 section 7.1, R3074, R5215, R5212);
//   - is not inside a wsse:Security header whose child is the token
//     (R3066), or precedes the token (R5205).
//
// The rules are about how the message is written, not about which key it
// names: a reference that breaks them still names one token. Use it where a
// profile demands BSP conformance, before dsig.Verify or decryption.
func ResolveSecurityTokenReferenceStrict(doc, str *xdm.Node) (*x509.Certificate, error) {
	tok, err := referencedToken(doc, str)
	if err != nil {
		return nil, err
	}
	vt := tok.AttrValue("ValueType")
	if got := str.ChildElements()[0].AttrValue("ValueType"); got == "" || got != vt {
		return nil, fmt.Errorf("%w: wsse:Reference ValueType %q, token %q (BSP R3059, R3058)", xmlsec.ErrMalformed, got, vt)
	}
	tt := xmltree.AttrValue(str, xmlsec.NSWSSE11, "TokenType")
	if tt != "" && tt != vt || tt == "" && (vt == xmlsec.BSTValueTypeX509PKIPath || vt == xmlsec.BSTValueTypePKCS7) {
		return nil, fmt.Errorf("%w: wsse11:TokenType %q for a %q token (BSP R5215, R5212)", xmlsec.ErrMalformed, tt, vt)
	}
	// The child of the token's header that holds the reference.
	step := str
	for step.Parent != nil && step.Parent != tok.Parent {
		step = step.Parent
	}
	if !tok.Parent.IsElement(xmlsec.NSWSSE, "Security") || step.Parent == nil ||
		slices.Index(step.Parent.Children, step) <= slices.Index(step.Parent.Children, tok) {
		return nil, fmt.Errorf("%w: the token must precede the reference in the same wsse:Security (BSP R5205, R3066)", xmlsec.ErrMalformed)
	}
	return ParseBinarySecurityToken(tok)
}

// referencedToken returns the element a single direct wsse:Reference names.
func referencedToken(doc, str *xdm.Node) (*xdm.Node, error) {
	if doc == nil || str == nil || !str.IsElement(xmlsec.NSWSSE, "SecurityTokenReference") {
		return nil, fmt.Errorf("%w: not a wsse:SecurityTokenReference", xmlsec.ErrUnsupportedKeyInfo)
	}
	kids := str.ChildElements()
	if len(kids) != 1 || !kids[0].IsElement(xmlsec.NSWSSE, "Reference") {
		return nil, fmt.Errorf("%w: only a single direct wsse:Reference is accepted", xmlsec.ErrUnsupportedKeyInfo)
	}
	id, ok := strings.CutPrefix(kids[0].AttrValue("URI"), "#")
	if !ok || id == "" {
		return nil, fmt.Errorf("%w: wsse:Reference URI must be a local #id", xmlsec.ErrUnsupportedKeyInfo)
	}
	return FindByID(doc, id)
}

// MatchSecurityTokenReference reports whether a wsse:SecurityTokenReference
// names cert by one of the forms that identify a certificate the message
// does not carry: a wsse:KeyIdentifier holding its X509SubjectKeyIdentifier
// or ThumbprintSHA1, or ds:X509Data/ds:X509IssuerSerial with its issuer and
// serial number (X.509 Token Profile 1.1.1 section 3.2). Any other form, a
// direct wsse:Reference included, is false; resolve that with
// ResolveSecurityTokenReference.
//
// It never takes a key from the message: cert is the caller's, one it
// already trusts, and a match means only that the message names it. Use it
// to pick which of your own keys decrypts an xenc:EncryptedKey, or to
// confirm that a signature names the certificate you pinned.
//
// Issuer names are compared as distinguished names, attribute by attribute,
// ignoring case and repeated or surrounding spaces, as peers write them
// differently: "CN=a,O=b" and "CN=a, O=b" are the same issuer.
func MatchSecurityTokenReference(str *xdm.Node, cert *x509.Certificate) bool {
	if str == nil || cert == nil || !str.IsElement(xmlsec.NSWSSE, "SecurityTokenReference") {
		return false
	}
	kids := str.ChildElements()
	if len(kids) != 1 {
		return false
	}
	switch k := kids[0]; {
	case k.IsElement(xmlsec.NSWSSE, "KeyIdentifier"):
		// EncodingType is optional in SOAP Message Security; absent means
		// the Base64Binary its ValueTypes use.
		if enc := k.Attr("", "EncodingType"); enc != nil && enc.Value != xmlsec.BSTEncodingBase64 {
			return false
		}
		v, err := xmltree.Base64(k)
		if err != nil || len(v) == 0 {
			return false
		}
		switch k.AttrValue("ValueType") {
		case valueTypeSKI:
			return bytes.Equal(v, cert.SubjectKeyId)
		case valueTypeThumbprintSHA1:
			return bytes.Equal(v, thumbprintSHA1(cert))
		}
	case k.IsElement(xmlsec.NSDSig, "X509Data"):
		d := k.ChildElements()
		if len(d) != 1 || !d[0].IsElement(xmlsec.NSDSig, "X509IssuerSerial") {
			return false
		}
		is := d[0].ChildElements()
		if len(is) != 2 || !is[0].IsElement(xmlsec.NSDSig, "X509IssuerName") || !is[1].IsElement(xmlsec.NSDSig, "X509SerialNumber") {
			return false
		}
		serial, ok := new(big.Int).SetString(strings.TrimSpace(is[1].StringValue()), 10)
		return ok && cert.SerialNumber != nil && serial.Cmp(cert.SerialNumber) == 0 &&
			sameIssuer(is[0].StringValue(), cert.RawIssuer)
	}
	return false
}
