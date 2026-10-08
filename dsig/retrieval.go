package dsig

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
)

// ds:RetrievalMethod Type URIs (XML-DSig 4.5.3).
const (
	typeX509Data           = xmlsec.NSDSig + "X509Data"
	typeRSAKeyValue        = xmlsec.NSDSig + "RSAKeyValue"
	typeDSAKeyValue        = xmlsec.NSDSig + "DSAKeyValue"
	typeRawX509Certificate = xmlsec.NSDSig + "rawX509Certificate"
	typeECKeyValue         = xmlsec.NSDSig11 + "ECKeyValue"
	typeDEREncodedKeyValue = xmlsec.NSDSig11 + "DEREncodedKeyValue"
)

// retrievalTargets are the same-document ds:RetrievalMethod Types followed,
// each with the element it must name.
var retrievalTargets = map[string]xdm.QName{
	typeX509Data:           {URI: xmlsec.NSDSig, Local: "X509Data"},
	typeRSAKeyValue:        {URI: xmlsec.NSDSig, Local: "RSAKeyValue"},
	typeDSAKeyValue:        {URI: xmlsec.NSDSig, Local: "DSAKeyValue"},
	typeECKeyValue:         {URI: xmlsec.NSDSig11, Local: "ECKeyValue"},
	typeDEREncodedKeyValue: {URI: xmlsec.NSDSig11, Local: "DEREncodedKeyValue"},
}

// retrievalMethod resolves a ds:RetrievalMethod (XML-DSig 4.5.3), one hop
// only. Transforms are refused. A same-document URI must name the element
// its Type says, for a Type in retrievalTargets (DSAKeyValue only for a DSA
// signature); without a Type, which is optional, the Type is the one of
// retrievalTargets the named element is. Any other URI is followed only for
// the rawX509Certificate Type, through VerifyOptions.ResolveKeyInfoURI, and
// must be absolute. The
// form reported is the one the target has: KeyInfoX509Data for X509Data or
// a raw certificate, KeyInfoKeyValue for a key value, or
// KeyInfoDEREncodedKeyValue.
func (c *keyContext) retrievalMethod(rm *xdm.Node) (resolvedKey, error) {
	uri := rm.Attr("", "URI")
	typ := rm.AttrValue("Type")
	switch {
	case uri == nil:
		return resolvedKey{}, malformed("ds:RetrievalMethod without URI")
	case len(rm.ChildElements()) > 0:
		return resolvedKey{}, fmt.Errorf("%w: ds:RetrievalMethod with transforms", xmlsec.ErrUnsupportedKeyInfo)
	case !strings.HasPrefix(uri.Value, "#"):
		if typ != typeRawX509Certificate {
			return resolvedKey{}, fmt.Errorf("%w: ds:RetrievalMethod to %q of Type %q; another document is followed only for rawX509Certificate",
				xmlsec.ErrUnsupportedKeyInfo, uri.Value, typ)
		}
		b, err := c.fetch("ds:RetrievalMethod", uri.Value)
		if err != nil {
			return resolvedKey{}, err
		}
		cert, err := x509.ParseCertificate(b)
		if err != nil {
			return resolvedKey{}, malformed("ds:RetrievalMethod %q: %v", uri.Value, err)
		}
		return withKey(cert, KeyInfoX509Data, nil)
	}
	unsupported := func() bool {
		_, ok := retrievalTargets[typ]
		return !ok || typ == typeDSAKeyValue && c.dsaAlg == ""
	}
	if typ != "" && unsupported() {
		return resolvedKey{}, fmt.Errorf("%w: ds:RetrievalMethod Type %q", xmlsec.ErrUnsupportedKeyInfo, typ)
	}
	target, err := c.sameDocument("ds:RetrievalMethod", uri.Value)
	if err != nil {
		return resolvedKey{}, err
	}
	if typ == "" {
		// XML-DSig 4.5.3: Type is optional; the target says what it is.
		for t, q := range retrievalTargets {
			if target.IsElement(q.URI, q.Local) {
				typ = t
			}
		}
		if unsupported() {
			return resolvedKey{}, fmt.Errorf("%w: ds:RetrievalMethod without Type names %s", xmlsec.ErrUnsupportedKeyInfo, target.Name.Local)
		}
	}
	want := retrievalTargets[typ]
	if !target.IsElement(want.URI, want.Local) {
		return resolvedKey{}, malformed("ds:RetrievalMethod %q of Type %q names %s", uri.Value, typ, target.Name.Local)
	}
	var pub crypto.PublicKey
	switch typ {
	case typeX509Data:
		return c.x509Key([]*xdm.Node{target})
	case typeDEREncodedKeyValue:
		pub, err = parseDEREncodedKeyValue(target, c.dsaAlg)
		return resolvedKey{pub: pub, form: KeyInfoDEREncodedKeyValue}, err
	case typeRSAKeyValue:
		pub, err = parseRSAKeyValue(target)
	case typeECKeyValue:
		pub, err = parseECKeyValue(target)
	default:
		pub, err = parseDSAKeyValue(target)
	}
	return resolvedKey{pub: pub, form: KeyInfoKeyValue}, err
}
