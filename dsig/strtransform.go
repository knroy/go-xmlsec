package dsig

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"slices"
	"strings"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

// The STR Dereference Transform, SOAP Message Security 1.1.1 section 8.3.

// tokenDeref returns the token a wsse:SecurityTokenReference names, for the
// STR Dereference Transform.
type tokenDeref func(str *xdm.Node) (*xdm.Node, error)

// strDeref is the tokenDeref of doc: a token in the message, by
// wss.ReferencedToken with idAttrs; for an X509SubjectKeyIdentifier or
// ThumbprintSHA1 key identifier or an issuer-serial reference, the X509v3
// wsse:BinarySecurityToken that section 8.3 builds from the certificate
// resolve returns; for a SAML key identifier, the assertion in the message
// that carries its ID. Without resolve an X.509 reference cannot be
// dereferenced, and section 8.3 says the transform "MUST signal a failure".
// Any other key identifier, such as an EncryptedKeySHA1 or a Kerberos one,
// names a token this transform cannot reproduce and is refused with
// xmlsec.ErrUnsupportedKeyInfo: digesting a certificate in its place would
// sign something other than the token.
func strDeref(doc *xdm.Node, idAttrs []xdm.QName, resolve func(*xdm.Node) (*x509.Certificate, error)) tokenDeref {
	return func(str *xdm.Node) (*xdm.Node, error) {
		if !namesCertificate(str) {
			return wss.ReferencedToken(doc, str, idAttrs...)
		}
		if !x509Reference(str) {
			return samlToken(doc, str.ChildElements()[0], idAttrs)
		}
		if resolve == nil {
			return nil, fmt.Errorf("%w: a key identifier or issuer-serial reference under the STR Dereference Transform needs ResolveSecurityToken",
				xmlsec.ErrSecurityTokenUnavailable)
		}
		cert, err := resolveCertificate(str, resolve)
		if err != nil {
			return nil, err
		}
		return x509Token(str, cert), nil
	}
}

// The SAML Token Profile 1.1.1 key identifiers, and the assertion each
// names: its namespace and ID attribute.
var samlKeyIdentifiers = map[string]struct{ ns, id string }{
	"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID": {"urn:oasis:names:tc:SAML:1.0:assertion", "AssertionID"},
	"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID":          {"urn:oasis:names:tc:SAML:2.0:assertion", "ID"},
}

// samlToken returns the saml:Assertion in doc that the SAML key identifier
// ki names, by FindByID over its ID attribute and idAttrs, so an ID
// carried twice is refused with xmlsec.ErrAmbiguousID. An assertion not in
// the message, which only the SAML authority could supply, is
// xmlsec.ErrSecurityTokenUnavailable; a key identifier of any other
// ValueType is xmlsec.ErrUnsupportedKeyInfo.
func samlToken(doc, ki *xdm.Node, idAttrs []xdm.QName) (*xdm.Node, error) {
	vt := ki.AttrValue("ValueType")
	saml, ok := samlKeyIdentifiers[vt]
	if !ok {
		return nil, fmt.Errorf("%w: the STR Dereference Transform cannot dereference a %q key identifier", xmlsec.ErrUnsupportedKeyInfo, vt)
	}
	id := strings.TrimSpace(ki.StringValue())
	tok, err := wss.FindByID(doc, id, append(slices.Clone(idAttrs), xdm.QName{Local: saml.id})...)
	switch {
	case errors.Is(err, xmlsec.ErrIDNotFound):
		return nil, fmt.Errorf("%w: %w", xmlsec.ErrSecurityTokenUnavailable, err)
	case err != nil:
		return nil, err
	case !tok.IsElement(saml.ns, "Assertion") || tok.AttrValue(saml.id) != id:
		return nil, fmt.Errorf("%w: SAML key identifier %q names no assertion in the message", xmlsec.ErrSecurityTokenUnavailable, id)
	}
	return tok, nil
}

// namesCertificate reports whether a wsse:SecurityTokenReference names a
// token by a property rather than by where it is: a single
// wsse:KeyIdentifier or ds:X509Data.
func namesCertificate(str *xdm.Node) bool {
	kids := str.ChildElements()
	return len(kids) == 1 && (kids[0].IsElement(xmlsec.NSWSSE, "KeyIdentifier") || kids[0].IsElement(xmlsec.NSDSig, "X509Data"))
}

// resolveCertificate calls the caller's ResolveSecurityToken.
func resolveCertificate(str *xdm.Node, resolve func(*xdm.Node) (*x509.Certificate, error)) (*x509.Certificate, error) {
	cert, err := resolve(str)
	if err == nil && (cert == nil || len(cert.Raw) == 0) {
		err = errors.New("no certificate")
	}
	if err != nil {
		return nil, fmt.Errorf("%w: ResolveSecurityToken: %w", xmlsec.ErrSecurityTokenUnavailable, err)
	}
	return cert, nil
}

// x509Token is the token section 8.3 substitutes for a reference to a raw
// binary token: a wsse:BinarySecurityToken with the prefix of the reference,
// no EncodingType, the X509v3 ValueType, and the certificate in base64
// without white space. WSS4J builds the same element, with wsse for an
// unprefixed reference.
func x509Token(str *xdm.Node, cert *x509.Certificate) *xdm.Node {
	p := str.Name.Prefix
	if p == "" {
		p = "wsse"
	}
	bst := xmltree.Element(nil, p, xmlsec.NSWSSE, "BinarySecurityToken")
	bst.AddNamespace(p, xmlsec.NSWSSE)
	xmltree.SetAttr(bst, "", "", "ValueType", xmlsec.BSTValueTypeX509v3)
	xmltree.Text(bst, base64.StdEncoding.EncodeToString(cert.Raw))
	return bst
}

// strOctets is the output of the STR Dereference Transform for token,
// canonicalized by alg: under Exclusive C14N with prefixes and the default
// namespace inclusive, and with xmlns="" on the apex when no default
// namespace is in scope there, as section 8.3 requires. That is WSS4J's
// reading, which canonicalizes with "#default" inclusive and Santuario's
// propagateDefaultNamespace, whatever PrefixList the transform states; a
// default namespace in scope is therefore rendered. Sign states the
// "#default" it digests (see strTransformParams).
func strOctets(token *xdm.Node, alg string, prefixes []string) ([]byte, error) {
	if !slices.Contains(prefixes, "") {
		prefixes = append(slices.Clone(prefixes), "")
	}
	b, err := c14n.Bytes(token, c14n.Options{Algorithm: c14n.Algorithm(alg), InclusiveNamespacePrefixes: prefixes})
	if err != nil {
		return nil, err
	}
	// Canonical form escapes '>' and '"' in attribute values and has no
	// empty-element tags: the apex start tag ends at the first '>', and a
	// default namespace declaration in it is written ` xmlns="`. It sorts
	// first, straight after the element name.
	tag := b[:bytes.IndexByte(b, '>')]
	if !bytes.Contains(tag, []byte(` xmlns="`)) {
		name := len(tag)
		if i := bytes.IndexByte(tag, ' '); i >= 0 {
			name = i
		}
		b = slices.Insert(b, name, []byte(` xmlns=""`)...)
	}
	return b, nil
}

// strC14N is the canonicalization algorithm of an STR Dereference
// Transform: the ds:CanonicalizationMethod of its
// wsse:TransformationParameters, which parseSTRTransform has checked on a
// received transform and strTransformParams built on a signed one.
func strC14N(t TransformSpec) string {
	return t.el.ChildElements()[0].ChildElements()[0].AttrValue("Algorithm")
}

// digestSTR applies the STR Dereference Transform to d, which must be the
// node set of a wsse:SecurityTokenReference; only is whether it is the
// reference's only transform. It writes the output into w.
func (d *data) digestSTR(w hash.Hash, t TransformSpec, only bool) error {
	if !only || d.ns == nil || d.strDeref == nil || !d.ns.Root().IsElement(xmlsec.NSWSSE, "SecurityTokenReference") {
		return malformed("the STR Dereference Transform must be the only transform of a same-document reference to a wsse:SecurityTokenReference")
	}
	tok, err := d.strDeref(d.ns.Root())
	if err != nil {
		return err
	}
	b, err := strOctets(tok, strC14N(t), t.InclusiveNamespacePrefixes)
	if err != nil {
		return err
	}
	w.Write(b)
	d.token = tok
	return nil
}

// parseSTRTransform reads the parameters of a received STR Dereference
// Transform: one wsse:TransformationParameters without attributes, holding
// one ds:CanonicalizationMethod (Basic Security Profile R3065), which must
// name a canonicalization algorithm; its InclusiveNamespaces become the
// spec's. VerifyOptions.AllowedCanonicalizationAlgorithms decides which
// algorithm is admitted, and VerifyOptions.StrictBSP requires Exclusive C14N
// (R5404). Section 8.3 says unrecognized parameters and attributes SHOULD
// cause a fault; they do.
func parseSTRTransform(spec TransformSpec) (TransformSpec, error) {
	kids := spec.el.ChildElements()
	if len(kids) != 1 || !kids[0].IsElement(xmlsec.NSWSSE, "TransformationParameters") || len(kids[0].Attrs) > 0 {
		return spec, malformed("the STR Dereference Transform must hold one wsse:TransformationParameters, without attributes (BSP R3065)")
	}
	params := kids[0].ChildElements()
	if len(params) != 1 || !params[0].IsElement(xmlsec.NSDSig, "CanonicalizationMethod") {
		return spec, malformed("wsse:TransformationParameters must hold one ds:CanonicalizationMethod (BSP R3065)")
	}
	cm, err := parseTransform(params[0])
	if err != nil {
		return spec, err
	}
	if !isC14N(cm.Algorithm) {
		return spec, fmt.Errorf("%w: STR Dereference Transform canonicalization %q", xmlsec.ErrUnsupportedAlgorithm, cm.Algorithm)
	}
	spec.InclusiveNamespacePrefixes = cm.InclusiveNamespacePrefixes
	return spec, nil
}

// strTransformParams appends the wsse:TransformationParameters of an STR
// Dereference Transform that Sign emits: Exclusive C14N, with
// t.InclusiveNamespacePrefixes and the default namespace as its PrefixList.
// The transform renders the default namespace whatever the PrefixList says
// (see strOctets), so "#default" is always stated: the parameter then names
// the octets digested, and WSS4J, which ignores the PrefixList, verifies it
// all the same.
func strTransformParams(tr *xdm.Node, t TransformSpec) error {
	tp := xmltree.Element(tr, "wsse", xmlsec.NSWSSE, "TransformationParameters")
	if err := xmltree.Declare(tp, "wsse", xmlsec.NSWSSE); err != nil {
		return err
	}
	prefixes := t.InclusiveNamespacePrefixes
	if !slices.Contains(prefixes, "") {
		prefixes = append(slices.Clone(prefixes), "")
	}
	cm := algElement(tp, "CanonicalizationMethod", string(c14n.Exclusive10))
	return transformParams(cm, TransformSpec{Algorithm: string(c14n.Exclusive10), InclusiveNamespacePrefixes: prefixes})
}

// resolveSTR resolves the wsse:SecurityTokenReference of a ds:KeyInfo: a
// key identifier or issuer-serial reference through resolve when the
// caller supplied one, after CheckSecurityTokenReference when strict;
// anything else with wss.ResolveSecurityTokenReference, or its strict form.
func resolveSTR(doc, str *xdm.Node, strict bool, resolve func(*xdm.Node) (*x509.Certificate, error)) (*x509.Certificate, error) {
	if resolve != nil && namesCertificate(str) {
		if strict {
			if err := wss.CheckSecurityTokenReference(str); err != nil {
				return nil, err
			}
		}
		return resolveCertificate(str, resolve)
	}
	if strict {
		return wss.ResolveSecurityTokenReferenceStrict(doc, str)
	}
	return wss.ResolveSecurityTokenReference(doc, str)
}
