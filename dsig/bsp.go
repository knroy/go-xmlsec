package dsig

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

// The X.509 key identifiers of the X.509 Token Profile 1.1.1 and SOAP
// Message Security 1.1.1, which wss.MatchSecurityTokenReference compares
// with a certificate.
const (
	valueTypeSKI            = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier"
	valueTypeThumbprintSHA1 = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1"
)

// bspTransforms are the transforms the Basic Security Profile admits (R5423),
// and bspLastTransforms those a reference's transforms may end with (R5412).
var (
	bspTransforms = []string{
		string(c14n.Exclusive10), xmlsec.TransformXPathFilter2, xmlsec.TransformSTR, xmlsec.TransformEnvelopedSignature,
		xmlsec.TransformAttachmentContentSignature, xmlsec.TransformAttachmentCompleteSignature,
	}
	bspLastTransforms = []string{
		string(c14n.Exclusive10), xmlsec.TransformSTR,
		xmlsec.TransformAttachmentContentSignature, xmlsec.TransformAttachmentCompleteSignature,
	}
)

// checkBSP applies VerifyOptions.StrictBSP, before any cryptographic work:
// the WS-I Basic Security Profile 1.1 rules for a received signature.
//
//   - R5404: ds:SignedInfo is canonicalized with Exclusive C14N;
//   - R5401: ds:SignatureMethod has no ds:HMACOutputLength, or any child;
//   - R5402, R5417: a ds:KeyInfo holds exactly one
//     wsse:SecurityTokenReference, which wss.CheckSecurityTokenReference
//     accepts (R3061, R3027, R3054, R3063, R3070, R3071, R3069, R3072,
//     R3060, R3056, and the TokenType of SOAP Message Security section 7.1);
//   - R5403: the signature holds no ds:Manifest;
//   - R5440: the signature holds no xenc:EncryptedData;
//   - R5416, R5411: every ds:Reference has ds:Transforms, with a transform;
//   - R5423: every transform is Exclusive C14N, XPath Filter 2.0, the STR
//     Dereference Transform, enveloped-signature or an SwA signature
//     transform;
//   - R5404, R3065: an STR Dereference Transform canonicalizes with
//     Exclusive C14N;
//   - R5412: the last is Exclusive C14N, the STR Dereference Transform or
//     an SwA signature transform;
//   - R6101 and SwA profile 5.4.4: a cid: reference begins with an SwA
//     signature transform;
//   - R3102: no reference names content of the signature's own ds:Object,
//     which would make it enveloping.
//
// Every breach is xmlsec.ErrMalformed, as under
// xenc.DecryptOptions.StrictBSP.
func checkBSP(doc, sig *xdm.Node, p *parsedSignature, idAttrs []xdm.QName) error {
	if p.c14n.Algorithm != c14n.Exclusive10 {
		return malformed("ds:SignedInfo canonicalization %q (BSP R5404)", p.c14n.Algorithm)
	}
	if len(p.sigMethod.ChildElements()) > 0 {
		return malformed("ds:SignatureMethod has children (BSP R5401)")
	}
	if p.keyInfo != nil {
		kids := p.keyInfo.ChildElements()
		if len(kids) != 1 || !kids[0].IsElement(xmlsec.NSWSSE, "SecurityTokenReference") {
			return malformed("ds:KeyInfo must hold exactly one wsse:SecurityTokenReference (BSP R5402, R5417)")
		}
		if err := wss.CheckSecurityTokenReference(kids[0]); err != nil {
			return err
		}
	}
	var inside error
	xmltree.Walk(sig, func(e *xdm.Node) {
		switch {
		case e.IsElement(xmlsec.NSDSig, "Manifest"):
			inside = malformed("ds:Signature holds a ds:Manifest (BSP R5403)")
		case e.IsElement(xmlsec.NSXEnc, "EncryptedData"):
			inside = malformed("ds:Signature holds an xenc:EncryptedData (BSP R5440)")
		}
	})
	if inside != nil {
		return inside
	}
	for _, r := range p.refs {
		if err := checkBSPReference(doc, sig, r, idAttrs); err != nil {
			return err
		}
	}
	return nil
}

// checkBSPReference applies checkBSP's rules to one reference.
func checkBSPReference(doc, sig *xdm.Node, r parsedReference, idAttrs []xdm.QName) error {
	n := len(r.transforms)
	if n == 0 {
		return malformed("ds:Reference %q without transforms (BSP R5416, R5411)", r.uri)
	}
	for _, t := range r.transforms {
		if !slices.Contains(bspTransforms, t.Algorithm) {
			return malformed("transform %q (BSP R5423)", t.Algorithm)
		}
		if t.Algorithm == xmlsec.TransformSTR && strC14N(t) != string(c14n.Exclusive10) {
			return malformed("STR Dereference Transform canonicalization %q (BSP R5404, R3065)", strC14N(t))
		}
	}
	if !slices.Contains(bspLastTransforms, r.transforms[n-1].Algorithm) {
		return malformed("ds:Reference %q ends with transform %q (BSP R5412)", r.uri, r.transforms[n-1].Algorithm)
	}
	first := r.transforms[0].Algorithm
	if strings.HasPrefix(r.uri, "cid:") && first != xmlsec.TransformAttachmentContentSignature && first != xmlsec.TransformAttachmentCompleteSignature {
		return malformed("cid: reference %q must begin with an SwA signature transform (BSP R6101)", r.uri)
	}
	if r.omitted || !isSameDocument(r.uri) {
		return nil
	}
	id, whole, _, err := sameDocumentTarget(r.uri)
	if err != nil || whole {
		return err
	}
	target, err := wss.FindByID(doc, id, idAttrs...)
	if err != nil {
		return err
	}
	// Enveloping is signing a ds:Object of the signature itself. Its
	// ds:KeyInfo is not one: WSS4J signs the reference there through the STR
	// Dereference Transform.
	for e := target; e.Parent != nil; e = e.Parent {
		if e.Parent == sig && e.IsElement(xmlsec.NSDSig, "Object") {
			return malformed("ds:Reference %q names content of the signature's own ds:Object, an enveloping signature (BSP R3102)", r.uri)
		}
	}
	return nil
}

// x509Reference reports whether a wsse:SecurityTokenReference names an X.509
// certificate by a property of it: an X509SubjectKeyIdentifier or
// ThumbprintSHA1 key identifier, or ds:X509Data.
func x509Reference(str *xdm.Node) bool {
	kids := str.ChildElements()
	if len(kids) != 1 {
		return false
	}
	vt := kids[0].AttrValue("ValueType")
	return kids[0].IsElement(xmlsec.NSDSig, "X509Data") ||
		kids[0].IsElement(xmlsec.NSWSSE, "KeyIdentifier") && (vt == valueTypeSKI || vt == valueTypeThumbprintSHA1)
}

// checkPinnedSTR refuses, when strict and a certificate is pinned, a
// ds:KeyInfo whose wsse:SecurityTokenReference names another certificate
// by key identifier or issuer serial. The pinned certificate is what the
// signature is verified with either way; the refusal is for a message that
// says it was signed by someone else, which is what substituting the key
// would look like. Lenient verification ignores the reference, as it
// ignores any ds:KeyInfo under a pinned key: a peer computing the
// identifier differently, as WSS4J does for a certificate without a
// SubjectKeyIdentifier extension, would otherwise be refused.
func checkPinnedSTR(ki *xdm.Node, cert *x509.Certificate, strict bool) error {
	if !strict || cert == nil || ki == nil {
		return nil
	}
	kids := ki.ChildElements()
	if len(kids) == 1 && kids[0].IsElement(xmlsec.NSWSSE, "SecurityTokenReference") && x509Reference(kids[0]) &&
		!wss.MatchSecurityTokenReference(kids[0], cert) {
		return fmt.Errorf("%w: ds:KeyInfo names a certificate other than VerifyOptions.Certificate", xmlsec.ErrUnsupportedKeyInfo)
	}
	return nil
}

// checkKeyInfoElement refuses a SignOptions.KeyInfoElement that is not a
// detached wsse:SecurityTokenReference, or one naming an X.509 certificate
// other than cert.
func checkKeyInfoElement(cert *x509.Certificate, el *xdm.Node) error {
	if el.Parent != nil || !el.IsElement(xmlsec.NSWSSE, "SecurityTokenReference") {
		return fmt.Errorf("%w: SignOptions.KeyInfoElement must be a detached wsse:SecurityTokenReference", xmlsec.ErrMalformed)
	}
	if x509Reference(el) && !wss.MatchSecurityTokenReference(el, cert) {
		return errors.New("dsig: SignOptions.KeyInfoElement does not name the signing certificate")
	}
	return nil
}

// hasTransform reports whether r has a transform alg.
func hasTransform(r Reference, alg string) bool {
	return slices.ContainsFunc(r.Transforms, func(t TransformSpec) bool { return t.Algorithm == alg })
}
