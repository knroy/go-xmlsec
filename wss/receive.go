package wss

import (
	"fmt"
	"slices"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// FindHeader returns the wsse:Security header of a received SOAP message
// that targets actor, the SOAP 1.1 actor or SOAP 1.2 role; empty means none,
// the ultimate receiver, and for SOAP 1.2 the ultimateReceiver role is the
// same recipient. It returns nil and no error when there is none: whether a
// message without one is acceptable is the caller's policy.
//
// More than one header for the same recipient is refused with
// xmlsec.ErrMalformed (SOAP Message Security 1.1.1 section 5, Basic Security
// Profile R3206, R3210): which one a receiver processes would be a choice an
// attacker could make for it. A document element that is not a soapNS
// Envelope is refused too.
func FindHeader(doc *xdm.Node, soapNS, actor string) (*xdm.Node, error) {
	if soapNS != xmlsec.NSSOAP11 && soapNS != xmlsec.NSSOAP12 {
		return nil, fmt.Errorf("wss: unknown SOAP namespace %q", soapNS)
	}
	env := xmltree.DocumentElement(doc)
	if env == nil || !env.IsElement(soapNS, "Envelope") {
		return nil, fmt.Errorf("%w: document element is not a SOAP Envelope", xmlsec.ErrMalformed)
	}
	kids := env.ChildElements()
	if len(kids) == 0 || !kids[0].IsElement(soapNS, "Header") {
		return nil, nil
	}
	switch hs := securityHeaders(kids[0], soapNS, actor); len(hs) {
	case 0:
		return nil, nil
	case 1:
		return hs[0], nil
	}
	return nil, fmt.Errorf("%w: more than one wsse:Security header for actor %q (BSP R3206, R3210)", xmlsec.ErrMalformed, actor)
}

// FindTimestamp returns the wsu:Timestamp child of a wsse:Security header,
// for ParseTimestamp, or nil and no error when there is none. More than one
// is refused with xmlsec.ErrMalformed (SOAP Message Security 1.1.1 section
// 10, Basic Security Profile R3227), as is a security that is not a
// wsse:Security element.
func FindTimestamp(security *xdm.Node) (*xdm.Node, error) {
	if security == nil || !security.IsElement(xmlsec.NSWSSE, "Security") {
		return nil, fmt.Errorf("%w: not a wsse:Security header", xmlsec.ErrMalformed)
	}
	var ts *xdm.Node
	for _, e := range security.ChildElements() {
		if !e.IsElement(xmlsec.NSWSU, "Timestamp") {
			continue
		}
		if ts != nil {
			return nil, fmt.Errorf("%w: more than one wsu:Timestamp (BSP R3227)", xmlsec.ErrMalformed)
		}
		ts = e
	}
	return ts, nil
}

// CheckUniqueIDs refuses with xmlsec.ErrAmbiguousID a document in which an
// ID value is carried more than once by the attributes FindByID counts:
// wsu:Id, xml:id and extra, all forming one set (SOAP Message Security 1.1.1
// section 13.2.7, Basic Security Profile R3204). FindByID already refuses a
// duplicate of the ID it resolves; CheckUniqueIDs refuses the message as a
// whole, before anything is resolved, so that an application locating
// elements by some other means cannot meet a planted duplicate either.
func CheckUniqueIDs(doc *xdm.Node, extra ...xdm.QName) error {
	if doc == nil {
		return fmt.Errorf("%w: no document", xmlsec.ErrMalformed)
	}
	seen := map[string]bool{}
	var dup string
	xmltree.Walk(doc.Root(), func(e *xdm.Node) {
		for _, a := range e.Attrs {
			if dup == "" && (isDefaultID(a.Name) || slices.ContainsFunc(extra, a.Name.Equal)) {
				if seen[a.Value] {
					dup = a.Value
				}
				seen[a.Value] = true
			}
		}
	})
	if dup != "" {
		return fmt.Errorf("%w: %q appears more than once (BSP R3204)", xmlsec.ErrAmbiguousID, dup)
	}
	return nil
}

// CheckSecurityTokenReference applies the Basic Security Profile's rules for
// how a wsse:SecurityTokenReference is written, whatever it names, refusing
// with xmlsec.ErrMalformed one that:
//
//   - holds anything but exactly one reference (R3061), or a ds:KeyName
//     (R3027);
//   - holds a wsse:Reference without a URI (R3062);
//   - holds a wsse:Embedded with anything but one token, or with a
//     reference (R3060, R3056);
//   - holds a wsse:KeyIdentifier without a ValueType (R3054), with one no
//     token profile defines for it (R3063), or, unless it names a SAML
//     assertion, without the Base64Binary EncodingType (R3070, R3071);
//   - carries a wsse11:TokenType that its reference contradicts (SOAP
//     Message Security 1.1.1 section 7.1): a ThumbprintSHA1 or
//     X509SubjectKeyIdentifier for anything but an X509v3 token, an
//     issuer-serial for anything but an X.509 token, an EncryptedKeySHA1
//     for anything but an EncryptedKey, which also requires the TokenType
//     (R3069, R3072).
//
// A key identifier is accepted in the forms the X.509 Token Profile, SOAP
// Message Security and the SAML Token Profile define. It checks syntax only:
// ResolveSecurityTokenReferenceStrict adds the rules that compare a direct
// reference with its token.
func CheckSecurityTokenReference(str *xdm.Node) error {
	if str == nil || !str.IsElement(xmlsec.NSWSSE, "SecurityTokenReference") {
		return fmt.Errorf("%w: not a wsse:SecurityTokenReference", xmlsec.ErrMalformed)
	}
	kids := str.ChildElements()
	if len(kids) != 1 {
		return fmt.Errorf("%w: wsse:SecurityTokenReference must hold exactly one reference (BSP R3061)", xmlsec.ErrMalformed)
	}
	tt := xmltree.AttrValue(str, xmlsec.NSWSSE11, "TokenType")
	x509Types := []string{"", xmlsec.BSTValueTypeX509v3, xmlsec.BSTValueTypeX509PKIPath, xmlsec.BSTValueTypePKCS7}
	switch k := kids[0]; {
	case k.IsElement(xmlsec.NSWSSE, "Reference"):
		if k.Attr("", "URI") == nil {
			return fmt.Errorf("%w: wsse:Reference without a URI (BSP R3062)", xmlsec.ErrMalformed)
		}
	case k.IsElement(xmlsec.NSWSSE, "Embedded"):
		if _, err := embeddedToken(k); err != nil {
			return err
		}
	case k.IsElement(xmlsec.NSWSSE, "KeyIdentifier"):
		return checkKeyIdentifier(k, tt)
	case k.IsElement(xmlsec.NSDSig, "X509Data"):
		if !slices.Contains(x509Types, tt) {
			return fmt.Errorf("%w: an issuer-serial reference with wsse11:TokenType %q", xmlsec.ErrMalformed, tt)
		}
	default:
		// ds:KeyName included (R3027).
		return fmt.Errorf("%w: %s in a wsse:SecurityTokenReference (BSP R3061, R3027)", xmlsec.ErrMalformed, k.Name.Local)
	}
	return nil
}

// checkKeyIdentifier applies CheckSecurityTokenReference's rules to a
// wsse:KeyIdentifier under a reference with TokenType tt.
func checkKeyIdentifier(k *xdm.Node, tt string) error {
	vt := k.AttrValue("ValueType")
	want := []string{""}
	switch vt {
	case "":
		return fmt.Errorf("%w: wsse:KeyIdentifier without a ValueType (BSP R3054)", xmlsec.ErrMalformed)
	case valueTypeSKI, valueTypeThumbprintSHA1:
		want = append(want, xmlsec.BSTValueTypeX509v3)
	case valueTypeEncryptedKeySHA1:
		want = []string{valueTypeEncryptedKey}
	case valueTypeSAMLAssertionID, valueTypeSAML2AssertionID:
		// The SAML Token Profile defines the TokenType of each version;
		// this library reads no SAML token, so any is let through.
		return nil
	default:
		return fmt.Errorf("%w: wsse:KeyIdentifier ValueType %q (BSP R3063)", xmlsec.ErrMalformed, vt)
	}
	if !slices.Contains(want, tt) {
		return fmt.Errorf("%w: a %q key identifier with wsse11:TokenType %q (BSP R3069)", xmlsec.ErrMalformed, vt, tt)
	}
	if enc := k.AttrValue("EncodingType"); enc != xmlsec.BSTEncodingBase64 {
		return fmt.Errorf("%w: wsse:KeyIdentifier EncodingType %q (BSP R3070, R3071)", xmlsec.ErrMalformed, enc)
	}
	return nil
}
