package dsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/hashes"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

// SignOptions configures signature generation.
type SignOptions struct {
	// SignatureAlgorithm is a Sig* constant. Required. The legacy
	// verification-only algorithms (SigRSASHA1, SigDSASHA1, SigHMAC*) are
	// refused with xmlsec.ErrUnsupportedAlgorithm.
	SignatureAlgorithm string

	// CanonicalizationAlgorithm canonicalizes ds:SignedInfo itself,
	// independent of the algorithms used inside references. Required.
	CanonicalizationAlgorithm string

	// References are signed in the order given, which is preserved on the
	// wire.
	References []Reference

	// KeyInfo selects how key material is described. Required.
	KeyInfo KeyInfoForm

	// SecurityTokenID is the wsu:Id of the wsse:BinarySecurityToken, already
	// in doc, that a KeyInfoSecurityTokenReference points at. Required for
	// that form, ignored otherwise.
	SecurityTokenID string

	// SignatureID, if set, becomes the Id attribute of ds:Signature. It must
	// be an NCName.
	SignatureID string

	// Attachments resolves cid: references. Required if any reference uses
	// a cid: URI.
	Attachments xmlsec.AttachmentSet

	// Parent, if set, is the element inside doc that Sign appends the
	// signature to before digesting references and canonicalizing
	// ds:SignedInfo, so the signature is computed where it will stand. Any
	// canonicalization algorithm may then be used. Without it Sign returns a
	// detached signature, which only exclusive canonicalization keeps valid
	// wherever the caller places it.
	Parent *xdm.Node

	// IDAttributes names attributes that "#id" references resolve against
	// in addition to wsu:Id and xml:id, such as IDAttrSAML or IDAttrDSig.
	// Empty means only those two. An id value carried by more than one
	// attribute of the whole set is refused with xmlsec.ErrAmbiguousID. The
	// verifier must name the same attributes. SecurityTokenID is unaffected.
	IDAttributes []xdm.QName

	// ResolveURI supplies the octets of a reference to an absolute URI
	// other than cid:, such as "http://example.com/data.xml" (XML-DSig
	// 4.4.3.1). They go through the reference's transforms as an octet
	// stream: with none they are digested as they are, and a
	// canonicalization parses them with xmlsec.Parse first. This library
	// never fetches anything itself; see xmlsec.URIResolver. When nil, such
	// a reference is refused, and a relative URI is always refused.
	ResolveURI xmlsec.URIResolver
}

// Sign creates a ds:Signature over the references in opts.
//
// An RSA signing key must have at least 2048 bits (XML-DSig 6.4.2); a
// smaller one is refused with xmlsec.ErrUnsupportedKeyInfo.
//
// With opts.Parent set, the signature is appended to that element first and
// computed in place, and any canonicalization algorithm may be used; the
// signature is left there, and on failure the document is left unchanged.
//
// Without it, the signature is returned detached for the caller to place,
// for example inside wsse:Security, and the document is not modified. Then
// the CanonicalizationAlgorithm must be exclusive: ds:SignedInfo is
// canonicalized before it is placed, and only exclusive canonicalization is
// independent of where it ends up.
func Sign(doc *xdm.Node, key xmlsec.KeyProvider, opts SignOptions) (*xdm.Node, error) {
	if opts.Parent == nil {
		if !c14n.Algorithm(opts.CanonicalizationAlgorithm).Exclusive() {
			return nil, fmt.Errorf("%w: a detached signature needs an exclusive SignedInfo canonicalization, got %q; set SignOptions.Parent to compute it in place",
				xmlsec.ErrUnsupportedAlgorithm, opts.CanonicalizationAlgorithm)
		}
		return sign(doc, key, opts, nil)
	}
	p := opts.Parent
	if doc == nil || p.Kind != xdm.KindElement || p.Root() != doc.Root() {
		return nil, fmt.Errorf("%w: SignOptions.Parent must be an element inside doc", xmlsec.ErrMalformed)
	}
	n := len(p.Children)
	sig, err := sign(doc, key, opts, p)
	if err != nil {
		p.Children = p.Children[:n]
		return nil, err
	}
	return sig, nil
}

// SignEnveloped creates an enveloped signature, appended as the last child
// of the document element, and returns the signed document as octets. doc
// itself is left unmodified.
//
// Every reference with URI "" must carry an enveloped-signature transform
// followed by a canonicalization transform.
//
// The returned octets are the document as signed, in canonical form
// (Inclusive10WithComments, so comments survive). Callers transmit exactly
// these octets and never re-serialize the document.
func SignEnveloped(doc *xdm.Node, key xmlsec.KeyProvider, opts SignOptions) ([]byte, error) {
	el := xmltree.DocumentElement(doc)
	if el == nil {
		return nil, fmt.Errorf("%w: no document element", xmlsec.ErrMalformed)
	}
	n := len(el.Children)
	defer func() { el.Children = el.Children[:n] }()

	if _, err := sign(doc, key, opts, el); err != nil {
		return nil, err
	}
	return c14n.Bytes(doc.Root(), c14n.Options{Algorithm: c14n.Inclusive10WithComments})
}

// sign builds the signature, attaching it to parent first if non-nil so
// that references and ds:SignedInfo are processed in their final position.
func sign(doc *xdm.Node, key xmlsec.KeyProvider, opts SignOptions, parent *xdm.Node) (*xdm.Node, error) {
	if err := refuseLegacy(opts.SignatureAlgorithm); err != nil {
		return nil, err
	}
	sigHash, ok := hashes.Signature(opts.SignatureAlgorithm)
	if !ok {
		return nil, fmt.Errorf("%w: signature %q", xmlsec.ErrUnsupportedAlgorithm, opts.SignatureAlgorithm)
	}
	if !isC14N(opts.CanonicalizationAlgorithm) {
		return nil, fmt.Errorf("%w: canonicalization %q", xmlsec.ErrUnsupportedAlgorithm, opts.CanonicalizationAlgorithm)
	}
	if len(opts.References) == 0 {
		return nil, errors.New("dsig: no references")
	}
	if key.Signer == nil || key.Certificate == nil {
		return nil, errors.New("dsig: KeyProvider needs Signer and Certificate")
	}
	if pub, ok := key.Signer.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(key.Certificate.PublicKey) {
		return nil, errors.New("dsig: Signer does not match Certificate")
	}
	// XML-DSig 6.4.2: implementations "MUST use at least 2048-bit keys for
	// creating signatures".
	if k, ok := key.Signer.Public().(*rsa.PublicKey); ok {
		if err := checkRSASize(k); err != nil {
			return nil, err
		}
	}
	if opts.SignatureID != "" && !xdm.IsNCName(opts.SignatureID) {
		return nil, fmt.Errorf("%w: SignatureID %q is not an NCName", xmlsec.ErrMalformed, opts.SignatureID)
	}
	for _, r := range opts.References {
		if err := checkReference(r); err != nil {
			return nil, err
		}
	}

	sig := xmltree.Element(parent, "ds", xmlsec.NSDSig, "Signature")
	if err := xmltree.Declare(sig, "ds", xmlsec.NSDSig); err != nil {
		return nil, err
	}
	if opts.SignatureID != "" {
		xmltree.SetAttr(sig, "", "", "Id", opts.SignatureID)
	}
	si := xmltree.Element(sig, "ds", xmlsec.NSDSig, "SignedInfo")
	algElement(si, "CanonicalizationMethod", opts.CanonicalizationAlgorithm)
	algElement(si, "SignatureMethod", opts.SignatureAlgorithm)

	for _, r := range opts.References {
		dh, ok := hashes.Digest(r.DigestAlgorithm)
		if !ok {
			return nil, fmt.Errorf("%w: digest %q", xmlsec.ErrUnsupportedAlgorithm, r.DigestAlgorithm)
		}
		ref := xmltree.Element(si, "ds", xmlsec.NSDSig, "Reference")
		if r.ID != "" {
			xmltree.SetAttr(ref, "", "", "Id", r.ID)
		}
		if r.Type != "" {
			xmltree.SetAttr(ref, "", "", "Type", r.Type)
		}
		xmltree.SetAttr(ref, "", "", "URI", r.URI)
		// The transforms are built before digesting: here() and an XSLT
		// stylesheet are read from them where they stand.
		transforms := slices.Clone(r.Transforms)
		if len(transforms) > 0 {
			ts := xmltree.Element(ref, "ds", xmlsec.NSDSig, "Transforms")
			for i, t := range transforms {
				tr := algElement(ts, "Transform", t.Algorithm)
				if err := transformParams(tr, t); err != nil {
					return nil, err
				}
				transforms[i].el = tr
			}
		}
		h := dh.New()
		if _, err := digestReference(h, doc, sig, r.URI, transforms, opts.Attachments, false, opts.IDAttributes, opts.ResolveURI); err != nil {
			return nil, err
		}
		algElement(ref, "DigestMethod", r.DigestAlgorithm)
		xmltree.Text(xmltree.Element(ref, "ds", xmlsec.NSDSig, "DigestValue"), base64.StdEncoding.EncodeToString(h.Sum(nil)))
	}

	h := sigHash.New()
	if _, err := c14n.DigestNodeSet(h, c14n.Subtree(si), c14n.Options{Algorithm: c14n.Algorithm(opts.CanonicalizationAlgorithm)}); err != nil {
		return nil, err
	}
	value, err := signDigest(key.Signer, opts.SignatureAlgorithm, sigHash, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	xmltree.Text(xmltree.Element(sig, "ds", xmlsec.NSDSig, "SignatureValue"), base64.StdEncoding.EncodeToString(value))

	if err := addKeyInfo(sig, doc, key, opts); err != nil {
		return nil, err
	}
	return sig, nil
}

// checkReference refuses a Reference that would make the ds:Signature
// schema invalid (XML-DSig 4.2: implementations "MUST generate laxly schema
// valid Signature elements"), or that no peer would accept.
func checkReference(r Reference) error {
	if err := refuseLegacy(r.DigestAlgorithm); err != nil {
		return err
	}
	if r.ID != "" && !xdm.IsNCName(r.ID) {
		return fmt.Errorf("%w: Reference.ID %q is not an NCName", xmlsec.ErrMalformed, r.ID)
	}
	if r.Type != "" {
		if _, err := url.Parse(r.Type); err != nil || strings.ContainsFunc(r.Type, unicode.IsSpace) {
			return fmt.Errorf("%w: Reference.Type %q is not a URI", xmlsec.ErrMalformed, r.Type)
		}
	}
	for _, t := range r.Transforms {
		switch t.Algorithm {
		case xmlsec.TransformXPath, xmlsec.TransformXPathFilter2:
			if err := checkXPathSpec(t); err != nil {
				return err
			}
		case xmlsec.TransformXSLT:
			if !isStylesheet(t.Stylesheet) {
				return fmt.Errorf("%w: an XSLT transform needs TransformSpec.Stylesheet, an xsl:stylesheet element", xmlsec.ErrMalformed)
			}
		}
	}
	first := ""
	if len(r.Transforms) > 0 {
		first = r.Transforms[0].Algorithm
	}
	switch {
	case (r.URI == "" || r.URI == "#xpointer(/)") && first != xmlsec.TransformEnvelopedSignature:
		return fmt.Errorf("%w: a reference to the whole document must begin with enveloped-signature", xmlsec.ErrMalformed)
	case strings.HasPrefix(r.URI, "cid:") && first != xmlsec.TransformAttachmentContentSignature && first != xmlsec.TransformAttachmentCompleteSignature:
		// SwA profile 5.3 and WS-I BSP R6101: an attachment is signed
		// through one of the SwA signature transforms, never as raw octets.
		return fmt.Errorf("%w: a cid: reference must begin with %s or %s", xmlsec.ErrMalformed,
			xmlsec.TransformAttachmentContentSignature, xmlsec.TransformAttachmentCompleteSignature)
	}
	return nil
}

func algElement(parent *xdm.Node, local, alg string) *xdm.Node {
	e := xmltree.Element(parent, "ds", xmlsec.NSDSig, local)
	xmltree.SetAttr(e, "", "", "Algorithm", alg)
	return e
}

// transformParams appends a ds:Transform's parameter children: the
// ec:InclusiveNamespaces of an exclusive canonicalization, the XPath
// elements of the XPath transforms, or the XSLT stylesheet.
func transformParams(tr *xdm.Node, t TransformSpec) error {
	switch t.Algorithm {
	case xmlsec.TransformXPath, xmlsec.TransformXPathFilter2:
		return xpathElements(tr, t)
	case xmlsec.TransformXSLT:
		copyStylesheet(tr, t.Stylesheet)
		return nil
	}
	if !c14n.Algorithm(t.Algorithm).Exclusive() || len(t.InclusiveNamespacePrefixes) == 0 {
		return nil
	}
	in := xmltree.Element(tr, "ec", xmlsec.NSExcC14N, "InclusiveNamespaces")
	if err := xmltree.Declare(in, "ec", xmlsec.NSExcC14N); err != nil {
		return err
	}
	xmltree.SetAttr(in, "", "", "PrefixList", c14n.FormatPrefixList(t.InclusiveNamespacePrefixes))
	return nil
}

func addKeyInfo(sig, doc *xdm.Node, key xmlsec.KeyProvider, opts SignOptions) error {
	switch opts.KeyInfo {
	case KeyInfoNone:
		return nil
	case KeyInfoX509Data:
		ki := xmltree.Element(sig, "ds", xmlsec.NSDSig, "KeyInfo")
		xd := xmltree.Element(ki, "ds", xmlsec.NSDSig, "X509Data")
		xmltree.Text(xmltree.Element(xd, "ds", xmlsec.NSDSig, "X509Certificate"), base64.StdEncoding.EncodeToString(key.Certificate.Raw))
		return nil
	case KeyInfoSecurityTokenReference:
		tok, err := wss.FindByID(doc, opts.SecurityTokenID)
		if err != nil {
			return fmt.Errorf("dsig: SecurityTokenID: %w", err)
		}
		cert, err := wss.ParseBinarySecurityToken(tok)
		if err != nil {
			return err
		}
		if !cert.Equal(key.Certificate) {
			return errors.New("dsig: the referenced security token does not carry the signing certificate")
		}
		str, err := wss.NewSecurityTokenReference(doc, opts.SecurityTokenID, tok.AttrValue("ValueType"))
		if err != nil {
			return err
		}
		xmltree.Element(sig, "ds", xmlsec.NSDSig, "KeyInfo").AppendChild(str)
		return nil
	case KeyInfoKeyValue, KeyInfoDEREncodedKeyValue:
		return addRawKey(sig, key.Certificate, opts.KeyInfo)
	}
	return fmt.Errorf("dsig: unknown KeyInfoForm %d", opts.KeyInfo)
}

// addRawKey emits the certificate's key, which sign has checked is the
// signer's, as ds:KeyValue or dsig11:DEREncodedKeyValue. A key the verifier
// would refuse as a raw key is refused here.
func addRawKey(sig *xdm.Node, cert *x509.Certificate, form KeyInfoForm) error {
	if err := checkRawKey(cert.PublicKey); err != nil {
		return err
	}
	ki := xmltree.Element(sig, "ds", xmlsec.NSDSig, "KeyInfo")
	b64 := base64.StdEncoding.EncodeToString
	if form == KeyInfoDEREncodedKeyValue {
		e, err := dsig11Element(ki, "DEREncodedKeyValue")
		if err != nil {
			return err
		}
		xmltree.Text(e, b64(cert.RawSubjectPublicKeyInfo))
		return nil
	}
	kv := xmltree.Element(ki, "ds", xmlsec.NSDSig, "KeyValue")
	if k, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		r := xmltree.Element(kv, "ds", xmlsec.NSDSig, "RSAKeyValue")
		xmltree.Text(xmltree.Element(r, "ds", xmlsec.NSDSig, "Modulus"), b64(k.N.Bytes()))
		xmltree.Text(xmltree.Element(r, "ds", xmlsec.NSDSig, "Exponent"), b64(big.NewInt(int64(k.E)).Bytes()))
		return nil
	}
	k := cert.PublicKey.(*ecdsa.PublicKey) // checkRawKey admits only RSA and ECDSA
	ec, err := dsig11Element(kv, "ECKeyValue")
	if err != nil {
		return err
	}
	xmltree.SetAttr(xmltree.Element(ec, "dsig11", xmlsec.NSDSig11, "NamedCurve"), "", "", "URI", namedCurves[k.Curve])
	pt, _ := k.Bytes() // cannot fail on a curve in namedCurves
	xmltree.Text(xmltree.Element(ec, "dsig11", xmlsec.NSDSig11, "PublicKey"), b64(pt))
	return nil
}

// dsig11Element appends a dsig11 element to parent, declaring the prefix.
func dsig11Element(parent *xdm.Node, local string) (*xdm.Node, error) {
	e := xmltree.Element(parent, "dsig11", xmlsec.NSDSig11, local)
	return e, xmltree.Declare(e, "dsig11", xmlsec.NSDSig11)
}

// signDigest signs in the XML-DSig encoding: PKCS#1 v1.5 for RSA, and the
// fixed-width r||s concatenation, not ASN.1, for ECDSA.
func signDigest(s crypto.Signer, alg string, h crypto.Hash, digest []byte) ([]byte, error) {
	isEC := ecdsaAlgorithms[alg]
	switch pub := s.Public().(type) {
	case *rsa.PublicKey:
		if isEC {
			break
		}
		return s.Sign(rand.Reader, digest, h)
	case *ecdsa.PublicKey:
		if !isEC {
			break
		}
		der, err := s.Sign(rand.Reader, digest, h)
		if err != nil {
			return nil, err
		}
		var rs struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(der, &rs); err != nil || len(rest) > 0 {
			return nil, fmt.Errorf("dsig: signer returned malformed ECDSA signature")
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		rs.R.FillBytes(out[:size])
		rs.S.FillBytes(out[size:])
		return out, nil
	}
	return nil, fmt.Errorf("%w: %s with a %T key", xmlsec.ErrUnsupportedAlgorithm, alg, s.Public())
}
