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

// keyContext is what resolving a ds:KeyInfo needs: the document its
// same-document references resolve in, the verification options (with the
// key resolvers cleared when a key is pinned), and dsaAlg, the signature's
// DSA algorithm when it is one, which alone admits a DSA key.
type keyContext struct {
	doc    *xdm.Node
	opts   VerifyOptions
	dsaAlg string
}

// resolvedKey is the key a ds:KeyInfo describes, with what it said beside.
type resolvedKey struct {
	cert          *x509.Certificate
	pub           crypto.PublicKey
	form          KeyInfoForm
	keyName       string
	crls          [][]byte
	intermediates []*x509.Certificate
}

// resolve reads ds:KeyInfo, returning the key it describes. Accepted, with
// at most one ds:KeyName beside, which is reported and otherwise ignored:
// a direct-reference wsse:SecurityTokenReference; ds:X509Data elements
// (x509Key); a ds:KeyValue or dsig11:DEREncodedKeyValue holding a raw key; a
// dsig11:KeyInfoReference to a ds:KeyInfo holding one of those, in the same
// document or, through VerifyOptions.ResolveKeyInfoURI, another; a
// ds:RetrievalMethod (retrievalMethod). A ds:KeyName alone goes to
// VerifyOptions.ResolveKeyName. hopped is set inside a ds:KeyInfo reached
// by reference, where no further reference is followed.
func (c *keyContext) resolve(ki *xdm.Node, hopped bool) (resolvedKey, error) {
	if ki == nil {
		return resolvedKey{form: KeyInfoNone}, nil
	}
	var name *xdm.Node
	var forms []*xdm.Node
	for _, k := range ki.ChildElements() {
		switch {
		case !k.IsElement(xmlsec.NSDSig, "KeyName"):
			forms = append(forms, k)
		case name != nil:
			return resolvedKey{}, fmt.Errorf("%w: more than one ds:KeyName", xmlsec.ErrUnsupportedKeyInfo)
		default:
			name = k
		}
	}
	keyName := ""
	if name != nil {
		keyName = strings.TrimSpace(name.StringValue())
	}
	r, err := c.resolveForms(forms, keyName, hopped)
	if r.keyName == "" {
		r.keyName = keyName
	}
	return r, err
}

func (c *keyContext) resolveForms(forms []*xdm.Node, keyName string, hopped bool) (resolvedKey, error) {
	if len(forms) == 0 {
		if keyName == "" || c.opts.ResolveKeyName == nil {
			return resolvedKey{}, fmt.Errorf("%w: no key in ds:KeyInfo", xmlsec.ErrUnsupportedKeyInfo)
		}
		cert, pub, err := c.opts.ResolveKeyName(keyName)
		switch {
		case err != nil:
			return resolvedKey{}, fmt.Errorf("%w: ResolveKeyName: %w", xmlsec.ErrUnsupportedKeyInfo, err)
		case (cert == nil) == (pub == nil):
			return resolvedKey{}, fmt.Errorf("%w: ResolveKeyName must return a certificate or a key", xmlsec.ErrUnsupportedKeyInfo)
		case cert != nil:
			pub = cert.PublicKey
		}
		return resolvedKey{cert: cert, pub: pub, form: KeyInfoKeyName}, nil
	}
	if len(forms) == 1 {
		switch k := forms[0]; {
		case k.IsElement(xmlsec.NSWSSE, "SecurityTokenReference"):
			cert, err := resolveSTR(c.doc, k, c.opts.StrictSecurityTokenReference || c.opts.StrictBSP, c.opts.ResolveSecurityToken)
			return withKey(cert, KeyInfoSecurityTokenReference, err)
		case k.IsElement(xmlsec.NSDSig, "KeyValue"):
			pub, err := parseKeyValue(k, c.dsaAlg != "")
			return resolvedKey{pub: pub, form: KeyInfoKeyValue}, err
		case k.IsElement(xmlsec.NSDSig11, "DEREncodedKeyValue"):
			pub, err := parseDEREncodedKeyValue(k, c.dsaAlg)
			return resolvedKey{pub: pub, form: KeyInfoDEREncodedKeyValue}, err
		case hopped && (k.IsElement(xmlsec.NSDSig11, "KeyInfoReference") || k.IsElement(xmlsec.NSDSig, "RetrievalMethod")):
			return resolvedKey{}, fmt.Errorf("%w: %s in a ds:KeyInfo reached by reference", xmlsec.ErrUnsupportedKeyInfo, k.Name.Local)
		case k.IsElement(xmlsec.NSDSig11, "KeyInfoReference"):
			tc, target, err := c.keyInfoReference(k)
			if err != nil {
				return resolvedKey{}, err
			}
			return tc.resolve(target, true)
		case k.IsElement(xmlsec.NSDSig, "RetrievalMethod"):
			return c.retrievalMethod(k)
		}
	}
	for _, k := range forms {
		if !k.IsElement(xmlsec.NSDSig, "X509Data") {
			return resolvedKey{}, fmt.Errorf("%w: %s", xmlsec.ErrUnsupportedKeyInfo, k.Name.Local)
		}
	}
	return c.x509Key(forms)
}

// keyInfoReference resolves a dsig11:KeyInfoReference (XML-DSig 4.5.10) to
// the ds:KeyInfo it names, and the context to resolve that in. A
// same-document reference names an element by ID, refusing duplicate IDs as
// a ds:Reference does. Any other goes to VerifyOptions.ResolveKeyInfoURI,
// and must be absolute; the octets are parsed with xmlsec.Parse, and their
// document element must be ds:KeyInfo. Either way the target may not hold
// another reference: references never chain.
func (c *keyContext) keyInfoReference(ref *xdm.Node) (*keyContext, *xdm.Node, error) {
	uri := ref.Attr("", "URI")
	if uri == nil || len(ref.ChildElements()) > 0 {
		return nil, nil, malformed("dsig11:KeyInfoReference must have a URI and no children")
	}
	if !strings.HasPrefix(uri.Value, "#") {
		b, err := c.fetch("dsig11:KeyInfoReference", uri.Value)
		if err != nil {
			return nil, nil, err
		}
		tree, err := xmlsec.Parse(b)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: dsig11:KeyInfoReference %q: %w", xmlsec.ErrMalformed, uri.Value, err)
		}
		target := xmltree.DocumentElement(tree.Root)
		if !target.IsElement(xmlsec.NSDSig, "KeyInfo") {
			return nil, nil, malformed("dsig11:KeyInfoReference %q is %s, not ds:KeyInfo", uri.Value, target.Name.Local)
		}
		tc := *c
		tc.doc = tree.Root
		return &tc, target, nil
	}
	target, err := c.sameDocument("dsig11:KeyInfoReference", uri.Value)
	if err != nil {
		return nil, nil, err
	}
	if !target.IsElement(xmlsec.NSDSig, "KeyInfo") {
		return nil, nil, malformed("dsig11:KeyInfoReference %q names %s, not ds:KeyInfo", uri.Value, target.Name.Local)
	}
	return c, target, nil
}

// sameDocument returns the element a same-document "#id" or
// "#xpointer(id('id'))" URI names, for the element named what.
func (c *keyContext) sameDocument(what, uri string) (*xdm.Node, error) {
	id, whole, _, err := sameDocumentTarget(uri)
	if err != nil {
		return nil, err
	}
	if whole {
		return nil, fmt.Errorf("%w: %s to the whole document", xmlsec.ErrUnsupportedKeyInfo, what)
	}
	return wss.FindByID(c.doc, id, c.opts.IDAttributes...)
}

// fetch returns the octets of an absolute URI through
// VerifyOptions.ResolveKeyInfoURI, for the element named what.
func (c *keyContext) fetch(what, uri string) ([]byte, error) {
	if c.opts.ResolveKeyInfoURI == nil || !isExternal(uri) {
		return nil, fmt.Errorf("%w: %s to %q; only a same-document ID is followed without VerifyOptions.ResolveKeyInfoURI, and a relative URI never is",
			xmlsec.ErrUnsupportedKeyInfo, what, uri)
	}
	b, err := c.opts.ResolveKeyInfoURI(uri)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", xmlsec.ErrDereference, uri, err)
	}
	return b, nil
}

// withKey returns a resolved certificate with its key.
func withKey(cert *x509.Certificate, form KeyInfoForm, err error) (resolvedKey, error) {
	if err != nil {
		return resolvedKey{form: form}, err
	}
	return resolvedKey{cert: cert, pub: cert.PublicKey, form: form}, nil
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
// SubjectPublicKeyInfo. dsaAlg admits a DSA key, checked for it.
func parseDEREncodedKeyValue(e *xdm.Node, dsaAlg string) (crypto.PublicKey, error) {
	der, err := xmltree.Base64(e)
	if err != nil {
		return nil, malformed("dsig11:DEREncodedKeyValue: %v", err)
	}
	// Refuses trailing data and off-curve points.
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, malformed("dsig11:DEREncodedKeyValue: %v", err)
	}
	return pub, checkReceivedKey(pub, dsaAlg)
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
