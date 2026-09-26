package dsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

// xmlsec.NSDSig11 is the XML Signature 1.1 namespace of dsig11:ECKeyValue,
// dsig11:DEREncodedKeyValue and dsig11:KeyInfoReference.

// minRSABits is the smallest RSA modulus accepted as a raw key, and the
// smallest Sign signs with. crypto/rsa itself refuses only keys under 1024
// bits.
const minRSABits = 2048

// namedCurves are the dsig11:NamedCurve URIs accepted, by curve.
var namedCurves = map[elliptic.Curve]string{
	elliptic.P256(): "urn:oid:1.2.840.10045.3.1.7",
	elliptic.P384(): "urn:oid:1.3.132.0.34",
	elliptic.P521(): "urn:oid:1.3.132.0.35",
}

// resolveKeyInfo reads ds:KeyInfo, returning the key it describes, the
// certificate carrying it when there is one, and its form. Accepted: a
// direct-reference wsse:SecurityTokenReference; ds:X509Data elements carrying
// exactly one ds:X509Certificate between them, optionally beside the subject
// name, issuer-serial or SKI that describe it; a lone ds:KeyValue or
// dsig11:DEREncodedKeyValue holding a raw key; or a lone
// dsig11:KeyInfoReference to a ds:KeyInfo in the same document holding one
// of those. idAttrs are the ID attributes the reference resolves against
// beyond wsu:Id and xml:id. dsaKeyValue admits a ds:DSAKeyValue, which Verify
// sets only for a dsa-sha1 signature, itself only ever explicitly allowed.
func resolveKeyInfo(doc, ki *xdm.Node, idAttrs []xdm.QName, strict, dsaKeyValue bool) (*x509.Certificate, crypto.PublicKey, KeyInfoForm, error) {
	if ki == nil {
		return nil, nil, KeyInfoNone, nil
	}
	kids := ki.ChildElements()
	if len(kids) == 1 && kids[0].IsElement(xmlsec.NSDSig11, "KeyInfoReference") {
		target, err := keyInfoReference(doc, kids[0], idAttrs)
		if err != nil {
			return nil, nil, KeyInfoNone, err
		}
		return resolveKeyInfo(doc, target, idAttrs, strict, dsaKeyValue)
	}
	if len(kids) == 1 {
		switch k := kids[0]; {
		case k.IsElement(xmlsec.NSWSSE, "SecurityTokenReference"):
			resolve := wss.ResolveSecurityTokenReference
			if strict {
				resolve = wss.ResolveSecurityTokenReferenceStrict
			}
			cert, err := resolve(doc, k)
			return withKey(cert, KeyInfoSecurityTokenReference, err)
		case k.IsElement(xmlsec.NSDSig, "KeyValue"):
			pub, err := parseKeyValue(k, dsaKeyValue)
			return nil, pub, KeyInfoKeyValue, err
		case k.IsElement(xmlsec.NSDSig11, "DEREncodedKeyValue"):
			pub, err := parseDEREncodedKeyValue(k)
			return nil, pub, KeyInfoDEREncodedKeyValue, err
		}
	}

	// One or more ds:X509Data carrying exactly one certificate between them.
	// Subject name, issuer-serial and SKI beside it only describe that
	// certificate; they are ignored, and never used to select a key.
	var certEl *xdm.Node
	for _, k := range kids {
		if !k.IsElement(xmlsec.NSDSig, "X509Data") {
			return nil, nil, 0, fmt.Errorf("%w: %s", xmlsec.ErrUnsupportedKeyInfo, k.Name.Local)
		}
		for _, d := range k.ChildElements() {
			switch {
			case d.IsElement(xmlsec.NSDSig, "X509Certificate"):
				if certEl != nil {
					return nil, nil, 0, fmt.Errorf("%w: more than one ds:X509Certificate", xmlsec.ErrUnsupportedKeyInfo)
				}
				certEl = d
			case d.IsElement(xmlsec.NSDSig, "X509SubjectName"), d.IsElement(xmlsec.NSDSig, "X509IssuerSerial"), d.IsElement(xmlsec.NSDSig, "X509SKI"):
			default:
				return nil, nil, 0, fmt.Errorf("%w: %s in ds:X509Data", xmlsec.ErrUnsupportedKeyInfo, d.Name.Local)
			}
		}
	}
	if certEl == nil {
		return nil, nil, 0, fmt.Errorf("%w: no ds:X509Certificate", xmlsec.ErrUnsupportedKeyInfo)
	}
	der, err := xmltree.Base64(certEl)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("%w: ds:X509Certificate: %v", xmlsec.ErrMalformed, err)
	}
	cert, err := x509.ParseCertificate(der)
	return withKey(cert, KeyInfoX509Data, err)
}

// keyInfoReference resolves a dsig11:KeyInfoReference (XML-DSig 4.5.10) to
// the ds:KeyInfo it names. Only a same-document reference to an element by
// ID is followed, refusing duplicate IDs as a ds:Reference does, and the
// target may not itself hold a KeyInfoReference, so references never chain.
func keyInfoReference(doc, ref *xdm.Node, idAttrs []xdm.QName) (*xdm.Node, error) {
	uri := ref.Attr("", "URI")
	if uri == nil || len(ref.ChildElements()) > 0 {
		return nil, malformed("dsig11:KeyInfoReference must have a URI and no children")
	}
	if !strings.HasPrefix(uri.Value, "#") {
		return nil, fmt.Errorf("%w: dsig11:KeyInfoReference to %q; only a same-document ID is followed", xmlsec.ErrUnsupportedKeyInfo, uri.Value)
	}
	id, whole, _, err := sameDocumentTarget(uri.Value)
	if err != nil {
		return nil, err
	}
	if whole {
		return nil, fmt.Errorf("%w: dsig11:KeyInfoReference to the whole document", xmlsec.ErrUnsupportedKeyInfo)
	}
	target, err := wss.FindByID(doc, id, idAttrs...)
	if err != nil {
		return nil, err
	}
	if !target.IsElement(xmlsec.NSDSig, "KeyInfo") {
		return nil, malformed("dsig11:KeyInfoReference %q names %s, not ds:KeyInfo", uri.Value, target.Name.Local)
	}
	for _, k := range target.ChildElements() {
		if k.IsElement(xmlsec.NSDSig11, "KeyInfoReference") {
			return nil, fmt.Errorf("%w: dsig11:KeyInfoReference to a ds:KeyInfo holding another", xmlsec.ErrUnsupportedKeyInfo)
		}
	}
	return target, nil
}

// withKey returns a resolved certificate with its key.
func withKey(cert *x509.Certificate, form KeyInfoForm, err error) (*x509.Certificate, crypto.PublicKey, KeyInfoForm, error) {
	if err != nil {
		return nil, nil, form, err
	}
	return cert, cert.PublicKey, form, nil
}

// parseKeyValue reads ds:KeyValue holding ds:RSAKeyValue or
// dsig11:ECKeyValue, or ds:DSAKeyValue when dsaKeyValue is set. The RFC 4050
// ECDSAKeyValue is refused.
func parseKeyValue(kv *xdm.Node, dsaKeyValue bool) (crypto.PublicKey, error) {
	kids := kv.ChildElements()
	if len(kids) != 1 {
		return nil, malformed("ds:KeyValue must hold exactly one key")
	}
	switch k := kids[0]; {
	case k.IsElement(xmlsec.NSDSig, "RSAKeyValue"):
		return parseRSAKeyValue(k)
	case k.IsElement(xmlsec.NSDSig11, "ECKeyValue"):
		return parseECKeyValue(k)
	case dsaKeyValue && k.IsElement(xmlsec.NSDSig, "DSAKeyValue"):
		return parseDSAKeyValue(k)
	}
	return nil, fmt.Errorf("%w: {%s}%s in ds:KeyValue", xmlsec.ErrUnsupportedKeyInfo, kids[0].Name.URI, kids[0].Name.Local)
}

func parseRSAKeyValue(e *xdm.Node) (crypto.PublicKey, error) {
	kids := e.ChildElements()
	if len(kids) != 2 || !kids[0].IsElement(xmlsec.NSDSig, "Modulus") || !kids[1].IsElement(xmlsec.NSDSig, "Exponent") {
		return nil, malformed("ds:RSAKeyValue must hold ds:Modulus, ds:Exponent")
	}
	n, err := cryptoBinary(kids[0])
	if err != nil {
		return nil, err
	}
	exp, err := cryptoBinary(kids[1])
	if err != nil {
		return nil, err
	}
	if exp.BitLen() > 31 {
		return nil, malformed("ds:Exponent too large")
	}
	k := &rsa.PublicKey{N: n, E: int(exp.Int64())}
	return k, checkRawKey(k)
}

// cryptoBinary decodes a ds:CryptoBinary: base64 of a big-endian unsigned
// integer.
func cryptoBinary(e *xdm.Node) (*big.Int, error) {
	b, err := xmltree.Base64(e)
	if err != nil || len(b) == 0 {
		return nil, malformed("ds:%s is not a base64 integer", e.Name.Local)
	}
	return new(big.Int).SetBytes(b), nil
}

// parseECKeyValue reads dsig11:ECKeyValue with a dsig11:NamedCurve. Explicit
// dsig11:ECParameters are refused: accepting them means validating
// attacker-chosen curve parameters.
func parseECKeyValue(e *xdm.Node) (crypto.PublicKey, error) {
	kids := e.ChildElements()
	if len(kids) != 2 || !kids[1].IsElement(xmlsec.NSDSig11, "PublicKey") {
		return nil, malformed("dsig11:ECKeyValue must hold a curve, then dsig11:PublicKey")
	}
	if !kids[0].IsElement(xmlsec.NSDSig11, "NamedCurve") {
		return nil, fmt.Errorf("%w: %s in dsig11:ECKeyValue; only a named curve is accepted", xmlsec.ErrUnsupportedKeyInfo, kids[0].Name.Local)
	}
	uri := xmltree.AttrValue(kids[0], "", "URI")
	var curve elliptic.Curve
	for c, u := range namedCurves {
		if u == uri {
			curve = c
		}
	}
	if curve == nil {
		return nil, fmt.Errorf("%w: curve %q", xmlsec.ErrUnsupportedKeyInfo, uri)
	}
	pt, err := xmltree.Base64(kids[1])
	if err != nil {
		return nil, malformed("dsig11:PublicKey: %v", err)
	}
	// Refuses anything but an uncompressed point on the curve.
	k, err := ecdsa.ParseUncompressedPublicKey(curve, pt)
	if err != nil {
		return nil, malformed("dsig11:PublicKey: %v", err)
	}
	return k, nil
}

// parseDEREncodedKeyValue reads dsig11:DEREncodedKeyValue: base64 of a DER
// SubjectPublicKeyInfo.
func parseDEREncodedKeyValue(e *xdm.Node) (crypto.PublicKey, error) {
	der, err := xmltree.Base64(e)
	if err != nil {
		return nil, malformed("dsig11:DEREncodedKeyValue: %v", err)
	}
	// Refuses trailing data and off-curve points.
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, malformed("dsig11:DEREncodedKeyValue: %v", err)
	}
	return pub, checkRawKey(pub)
}

// checkRSASize refuses an RSA key under minRSABits: as a raw key from
// ds:KeyInfo, and as any signing key (XML-DSig 6.4.2).
func checkRSASize(k *rsa.PublicKey) error {
	if k.N.BitLen() < minRSABits {
		return fmt.Errorf("%w: %d-bit RSA key; at least %d bits required", xmlsec.ErrUnsupportedKeyInfo, k.N.BitLen(), minRSABits)
	}
	return nil
}

// checkRawKey is the policy for a key that arrives without a certificate,
// and that Sign applies before emitting one: RSA of at least minRSABits with
// an odd modulus and an odd exponent that fits 31 bits, or ECDSA on a curve
// in namedCurves.
func checkRawKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if err := checkRSASize(k); err != nil {
			return err
		}
		if k.N.Bit(0) == 0 || k.E < 3 || k.E&1 == 0 || k.E > 1<<31-1 {
			return malformed("RSA key has an even modulus or an invalid exponent")
		}
		return nil
	case *ecdsa.PublicKey:
		if _, ok := namedCurves[k.Curve]; !ok {
			return fmt.Errorf("%w: ECDSA curve %s", xmlsec.ErrUnsupportedKeyInfo, k.Curve.Params().Name)
		}
		return nil
	}
	return fmt.Errorf("%w: %T key", xmlsec.ErrUnsupportedKeyInfo, pub)
}
