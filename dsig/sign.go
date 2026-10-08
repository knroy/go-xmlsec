package dsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"slices"
	"strconv"
	"strings"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

// SignOptions configures signature generation.
type SignOptions struct {
	// SignatureAlgorithm is a Sig* constant. Required. The legacy
	// verification-only algorithms (SigRSASHA1, SigDSASHA1, SigDSASHA256,
	// SigECDSASHA1, SigHMACSHA1) are refused with
	// xmlsec.ErrUnsupportedAlgorithm. SigRSASHA224 and SigECDSASHA224 are
	// produced, though a verifier must name them in its allow-list.
	// SigHMACSHA224, 256, 384 and 512 need HMACKey, and are the only ones
	// accepted with it.
	SignatureAlgorithm string

	// CanonicalizationAlgorithm canonicalizes ds:SignedInfo itself,
	// independent of the algorithms used inside references. Required.
	CanonicalizationAlgorithm string

	// CanonicalizationPrefixes populates the ec:InclusiveNamespaces
	// PrefixList of ds:CanonicalizationMethod (XML-DSig 4.4.1, Exclusive
	// C14N 3), with "" for the default namespace, and ds:SignedInfo is
	// canonicalized with it. It needs an exclusive CanonicalizationAlgorithm
	// and Parent: which listed prefixes are rendered depends on where the
	// signature stands, so a detached signature would break when placed.
	CanonicalizationPrefixes []string

	// HMACKey, if set, makes the signature an HMAC keyed with this shared
	// secret (XML-DSig 6.3): SignatureAlgorithm must then be SigHMACSHA224,
	// SigHMACSHA256, SigHMACSHA384 or SigHMACSHA512 (SigHMACSHA1 is
	// verification-only), the key must be at least as long as the hash
	// output (RFC 2104 section 3), the KeyProvider is not used and KeyInfo must be KeyInfoNone: the
	// verifier already holds the secret, and nothing about it travels.
	HMACKey []byte

	// HMACOutputLength, with HMACKey, truncates the MAC to this many bits
	// and emits ds:HMACOutputLength. Zero means the full hash output, with
	// no ds:HMACOutputLength. Otherwise it must be a multiple of 8, no
	// larger than the hash output and no smaller than half of it or 80 bits
	// (XML-DSig 4.4.2 and 6.3.1, CVE-2009-0217).
	HMACOutputLength int

	// References are signed in the order given, which is preserved on the
	// wire.
	References []Reference

	// KeyInfo selects how key material is described. The zero value,
	// KeyInfoNone, emits no ds:KeyInfo: the verifier must already hold the
	// key, as it always does for an HMAC.
	KeyInfo KeyInfoForm

	// SecurityTokenID is the wsu:Id of the wsse:BinarySecurityToken, already
	// in doc, that a KeyInfoSecurityTokenReference points at. Required for
	// that form, ignored otherwise.
	SecurityTokenID string

	// KeyName, if set, is emitted as ds:KeyName first in ds:KeyInfo
	// (XML-DSig 4.5.1), beside the form KeyInfo selects; it is required for
	// KeyInfoKeyName, which emits it alone, and refused with KeyInfoNone.
	KeyName string

	// Chain are certificates emitted after the signing certificate in
	// ds:X509Data, for KeyInfoX509Data only: the path from it towards a
	// trust anchor (XML-DSig 4.5.4). The signing certificate must be the one
	// leaf of itself and Chain, which may include other certificates for
	// its key, and there may be at most 15 of them.
	Chain []*x509.Certificate

	// X509Descriptors are emitted in ds:X509Data, in the order given and
	// before the certificate: beside it for KeyInfoX509Data, instead of it
	// for KeyInfoX509Descriptors. Each may appear once.
	X509Descriptors []X509Descriptor

	// KeyInfoReferenceURI is the URI of the dsig11:KeyInfoReference that
	// KeyInfoReference emits: "#id" for a ds:KeyInfo the caller places in
	// the same document, or an absolute URI. Required for that form,
	// refused with any other.
	KeyInfoReferenceURI string

	// SignatureID, if set, becomes the Id attribute of ds:Signature. It must
	// be an NCName.
	SignatureID string

	// SignedInfoID, SignatureValueID and KeyInfoID, if set, become the Id
	// attributes of ds:SignedInfo, ds:SignatureValue and ds:KeyInfo
	// (XML-DSig 4.3 to 4.5). Each must be an NCName, and every Id Sign
	// emits must differ. KeyInfoID needs a ds:KeyInfo to put it on. A
	// reference to "#"+KeyInfoID signs the ds:KeyInfo, which XML-DSig 4.5
	// suggests when the key information must not be substituted.
	SignedInfoID     string
	SignatureValueID string
	KeyInfoID        string

	// Objects are emitted as ds:Object elements after ds:KeyInfo, in order
	// (XML-DSig 4.6). They are built before any reference is digested, so a
	// reference to "#"+Object.ID covers one: with the signature as the
	// document element, that is an enveloping signature.
	Objects []Object

	// Properties are emitted in one ds:SignatureProperties, in a ds:Object
	// after Objects (XML-DSig 5.2). A reference to "#"+SignatureProperty.ID
	// signs one.
	Properties []SignatureProperty

	// OmittedURIData is the data object of the one Reference with OmitURI
	// set, digested through its transforms as octets (XML-DSig 4.4.3.1).
	// The verifier supplies the same octets with
	// VerifyOptions.ResolveOmittedURI. Required with OmitURI.
	OmittedURIData []byte

	// BaseURI, if set, is the absolute URI a relative reference URI, such
	// as "data.xml", is resolved against (XML-DSig 4.4.3.1, RFC 3986) before
	// it is given to ResolveURI. It is never taken from xml:base or anything
	// else in the document. Without it, a relative URI is refused.
	BaseURI string

	// ManifestID, if set, becomes the Id attribute of the ds:Manifest that
	// BuildManifest returns, which a Reference of Type xmlsec.TypeManifest
	// names. It must be an NCName. Sign ignores it.
	ManifestID string

	// Attachments resolves cid: references. Required if any reference uses
	// a cid: URI.
	Attachments xmlsec.AttachmentSet

	// Parent, if set, is the element inside doc that Sign appends the
	// signature to before digesting references and canonicalizing
	// ds:SignedInfo, so the signature is computed where it will stand. Any
	// canonicalization algorithm may then be used. Without it Sign returns a
	// detached signature, which only exclusive canonicalization keeps valid
	// wherever the caller places it: CanonicalizationAlgorithm must be
	// exclusive, and so must every canonicalization of a reference to an
	// element of the signature itself, such as a ds:Object or ds:KeyInfo
	// (XML-DSig 4.4.3.3), without InclusiveNamespacePrefixes; such a
	// reference may also carry enveloped-signature and base64, and is
	// otherwise refused with xmlsec.ErrUnsupportedAlgorithm. An inclusive
	// canonicalization, here or on a reference, is not Basic Security
	// Profile output (R5404, R5423).
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
	// a reference is refused, and so is a relative URI without BaseURI.
	ResolveURI xmlsec.URIResolver

	// KeyInfoElement, with KeyInfo set to KeyInfoSecurityTokenReference, is
	// the wsse:SecurityTokenReference Sign places in ds:KeyInfo instead of a
	// direct reference to SecurityTokenID, which is then ignored: a key
	// identifier or issuer-serial reference from
	// wss.NewKeyIdentifierReference or wss.NewIssuerSerialReference, for a
	// certificate the message does not carry (X.509 Token Profile 1.1.1
	// section 3.2, Basic Security Profile R5417, R5209), or a reference to
	// an xenc:EncryptedKey (wss.NewEncryptedKeyReference). It must be
	// detached, and Sign takes it: build a new one for each signature. A
	// key identifier or issuer-serial reference must name the signing
	// certificate; any other reference is placed as given.
	KeyInfoElement *xdm.Node

	// ResolveSecurityToken supplies the certificate that a key identifier
	// or issuer-serial wsse:SecurityTokenReference names, for a reference
	// through the STR Dereference Transform (xmlsec.TransformSTR), which
	// digests the token rather than the reference to it; see
	// VerifyOptions.ResolveSecurityToken. A direct reference, a
	// wsse:Embedded or a SAML key identifier, whose assertion is found in
	// the document, needs no resolver.
	ResolveSecurityToken func(str *xdm.Node) (*x509.Certificate, error)
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
// independent of where it ends up. For the same reason a reference to an
// element of the signature itself, such as a ds:Object, ds:KeyInfo or a
// token embedded in it, is refused with xmlsec.ErrUnsupportedAlgorithm
// unless its transforms are exclusive canonicalization without
// InclusiveNamespacePrefixes, enveloped-signature or base64: an inclusive
// canonicalization, an XPath or XSLT transform, or the STR Dereference
// Transform of an embedded token would digest what the element renders
// before the caller places it. doc may then be nil, for an enveloping
// signature: references resolve only within the signature, such as to a
// ds:Object of opts.Objects, and the caller makes the returned element a
// document's element, so its references may use any transform.
//
// Sign refuses with xmlsec.ErrNotNFC to sign a same-document reference, or
// a ds:SignedInfo, whose canonical form is not in Unicode Normalization Form
// C (XML-DSig 8.1.3): a verifier may normalize what it receives.
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
	sigHash, err := signatureMethod(opts)
	if err != nil {
		return nil, err
	}
	mac := len(opts.HMACKey) > 0
	if !isC14N(opts.CanonicalizationAlgorithm) {
		return nil, fmt.Errorf("%w: canonicalization %q", xmlsec.ErrUnsupportedAlgorithm, opts.CanonicalizationAlgorithm)
	}
	if err := checkPrefixes(opts, parent != nil); err != nil {
		return nil, err
	}
	if len(opts.References) == 0 {
		return nil, errors.New("dsig: no references")
	}
	if !mac {
		if err := checkKey(key); err != nil {
			return nil, err
		}
	}
	if err := checkReferences(opts.References, opts, doc == nil); err != nil {
		return nil, err
	}
	if err := checkObjects(opts); err != nil {
		return nil, err
	}
	if err := checkIDs(map[string]string{
		"SignatureID": opts.SignatureID, "SignedInfoID": opts.SignedInfoID,
		"SignatureValueID": opts.SignatureValueID, "KeyInfoID": opts.KeyInfoID,
	}, signatureIDs(opts, opts.References)); err != nil {
		return nil, err
	}

	sig := xmltree.Element(parent, "ds", xmlsec.NSDSig, "Signature")
	if err := xmltree.Declare(sig, "ds", xmlsec.NSDSig); err != nil {
		return nil, err
	}
	if doc == nil {
		doc = sig // enveloping: the signature is all there is
	}
	setOptional(sig, "Id", opts.SignatureID)
	si := xmltree.Element(sig, "ds", xmlsec.NSDSig, "SignedInfo")
	setOptional(si, "Id", opts.SignedInfoID)
	cm := algElement(si, "CanonicalizationMethod", opts.CanonicalizationAlgorithm)
	if err := transformParams(cm, TransformSpec{Algorithm: opts.CanonicalizationAlgorithm, InclusiveNamespacePrefixes: opts.CanonicalizationPrefixes}); err != nil {
		return nil, err
	}
	sm := algElement(si, "SignatureMethod", opts.SignatureAlgorithm)
	if opts.HMACOutputLength > 0 {
		xmltree.Text(xmltree.Element(sm, "ds", xmlsec.NSDSig, "HMACOutputLength"), strconv.Itoa(opts.HMACOutputLength))
	}

	// Everything after ds:SignedInfo is built before any reference is
	// digested, so that a reference to ds:KeyInfo (XML-DSig 4.5) or to a
	// ds:Object covers it as it will stand; ds:SignatureValue is filled in
	// last.
	sv := xmltree.Element(sig, "ds", xmlsec.NSDSig, "SignatureValue")
	setOptional(sv, "Id", opts.SignatureValueID)
	if err := addKeyInfo(sig, doc, key, opts); err != nil {
		return nil, err
	}
	if opts.KeyInfoID != "" {
		kids := sig.ChildElements()
		ki := kids[len(kids)-1]
		if !ki.IsElement(xmlsec.NSDSig, "KeyInfo") {
			return nil, fmt.Errorf("%w: KeyInfoID is set, and no ds:KeyInfo is emitted", xmlsec.ErrMalformed)
		}
		xmltree.SetAttr(ki, "", "", "Id", opts.KeyInfoID)
	}
	addObjects(sig, opts)

	if err := addReferences(si, doc, sig, opts.References, opts); err != nil {
		return nil, err
	}

	var h hash.Hash
	if mac {
		h = hmac.New(sigHash.New, opts.HMACKey)
	} else {
		h = sigHash.New()
	}
	siOpts := c14n.Options{Algorithm: c14n.Algorithm(opts.CanonicalizationAlgorithm), InclusiveNamespacePrefixes: opts.CanonicalizationPrefixes}
	if err := checkNFC(true, h, "ds:SignedInfo", func(w hash.Hash) error {
		_, err := c14n.DigestNodeSet(w, c14n.Subtree(si), siOpts)
		return err
	}); err != nil {
		return nil, err
	}
	var value []byte
	if mac {
		value = macValue(h, opts.HMACOutputLength)
	} else if value, err = signDigest(key.Signer, opts.SignatureAlgorithm, sigHash, h.Sum(nil)); err != nil {
		return nil, err
	}
	xmltree.Text(sv, base64.StdEncoding.EncodeToString(value))
	return sig, nil
}

// checkKey admits a KeyProvider for a public-key signature.
func checkKey(key xmlsec.KeyProvider) error {
	if key.Signer == nil || key.Certificate == nil {
		return errors.New("dsig: KeyProvider needs Signer and Certificate")
	}
	if pub, ok := key.Signer.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(key.Certificate.PublicKey) {
		return errors.New("dsig: Signer does not match Certificate")
	}
	// XML-DSig 6.4.2: implementations "MUST use at least 2048-bit keys for
	// creating signatures".
	if k, ok := key.Signer.Public().(*rsa.PublicKey); ok {
		return checkRSASize(k)
	}
	return nil
}

// checkPrefixes admits SignOptions.CanonicalizationPrefixes: exclusive
// canonicalization, computed in place, and prefixes that are NCNames or ""
// for the default namespace.
func checkPrefixes(opts SignOptions, inPlace bool) error {
	if len(opts.CanonicalizationPrefixes) == 0 {
		return nil
	}
	if !c14n.Algorithm(opts.CanonicalizationAlgorithm).Exclusive() || !inPlace {
		return fmt.Errorf("%w: CanonicalizationPrefixes needs an exclusive CanonicalizationAlgorithm and SignOptions.Parent", xmlsec.ErrMalformed)
	}
	for _, p := range opts.CanonicalizationPrefixes {
		if p != "" && !xdm.IsNCName(p) {
			return fmt.Errorf("%w: CanonicalizationPrefixes entry %q is not a prefix", xmlsec.ErrMalformed, p)
		}
	}
	return nil
}

// checkIDs refuses an Id Sign or BuildManifest would emit that is not an
// NCName, or that another one of them repeats. named maps option names to
// the Ids they set; others are Ids already checked to be NCNames.
func checkIDs(named map[string]string, others []string) error {
	seen := map[string]bool{}
	for name, id := range named {
		if id != "" && !xdm.IsNCName(id) {
			return fmt.Errorf("%w: %s %q is not an NCName", xmlsec.ErrMalformed, name, id)
		}
		others = append(others, id)
	}
	for _, id := range others {
		if id != "" && seen[id] {
			return fmt.Errorf("%w: Id %q is emitted twice", xmlsec.ErrMalformed, id)
		}
		seen[id] = true
	}
	return nil
}

// signatureIDs are the Ids of opts.Objects and opts.Properties and of
// refs, for checkIDs.
func signatureIDs(opts SignOptions, refs []Reference) []string {
	var ids []string
	for _, r := range refs {
		ids = append(ids, r.ID)
	}
	for _, o := range opts.Objects {
		ids = append(ids, o.ID)
	}
	for _, p := range opts.Properties {
		ids = append(ids, p.ID)
	}
	return ids
}

// checkReferences checks each reference, and the rules across them: at
// most one omitted URI, which needs OmittedURIData, and without a document
// no reference to the whole of it.
func checkReferences(refs []Reference, opts SignOptions, noDoc bool) error {
	if err := checkBaseURI(opts.BaseURI); err != nil {
		return err
	}
	omitted := 0
	for _, r := range refs {
		if err := checkReference(r); err != nil {
			return err
		}
		switch {
		case r.OmitURI:
			omitted++
		case noDoc && (r.URI == "" || r.URI == "#xpointer(/)"):
			return fmt.Errorf("%w: a reference to the whole document, and no document", xmlsec.ErrMalformed)
		}
	}
	switch {
	case omitted > 1:
		return fmt.Errorf("%w: %d references with OmitURI; at most one is allowed", xmlsec.ErrMalformed, omitted)
	case omitted == 1 && opts.OmittedURIData == nil:
		return fmt.Errorf("%w: a reference with OmitURI needs SignOptions.OmittedURIData", xmlsec.ErrMalformed)
	}
	return nil
}

// addReferences appends a digested ds:Reference to parent, a ds:SignedInfo
// or ds:Manifest, for each of refs. sig is what the enveloped-signature
// transform removes, and whose own Ids "#id" resolves against.
func addReferences(parent, doc, sig *xdm.Node, refs []Reference, opts SignOptions) error {
	for _, r := range refs {
		dh, ok := signingDigest(r.DigestAlgorithm)
		if !ok {
			return fmt.Errorf("%w: digest %q", xmlsec.ErrUnsupportedAlgorithm, r.DigestAlgorithm)
		}
		ref := xmltree.Element(parent, "ds", xmlsec.NSDSig, "Reference")
		setOptional(ref, "Id", r.ID)
		setOptional(ref, "Type", r.Type)
		if !r.OmitURI {
			xmltree.SetAttr(ref, "", "", "URI", r.URI)
		}
		// The transforms are built before digesting: here() and an XSLT
		// stylesheet are read from them where they stand.
		transforms := slices.Clone(r.Transforms)
		if len(transforms) > 0 {
			ts := xmltree.Element(ref, "ds", xmlsec.NSDSig, "Transforms")
			for i, t := range transforms {
				tr := algElement(ts, "Transform", t.Algorithm)
				if err := transformParams(tr, t); err != nil {
					return err
				}
				transforms[i].el = tr
			}
		}
		// XML-DSig 4.4.3.3: digesting an element of a detached signature
		// fixes what it renders now, before the caller places it.
		detached := sig.Parent == nil && sig != doc
		if detached && !r.OmitURI && !placementIndependent(r.Transforms) && within(signatureTarget(doc, sig, r.URI, opts.IDAttributes), sig) {
			return fmt.Errorf("%w: reference %q names an element of the detached signature, and its transforms depend on where the signature is placed; "+
				"use only exclusive canonicalization without InclusiveNamespacePrefixes, or set SignOptions.Parent", xmlsec.ErrUnsupportedAlgorithm, r.URI)
		}
		h := dh.New()
		sameDocument := !r.OmitURI && isSameDocument(r.URI)
		if err := checkNFC(sameDocument, h, fmt.Sprintf("reference %q", r.URI), func(w hash.Hash) error {
			if r.OmitURI {
				d := data{octets: opts.OmittedURIData}
				return d.digest(w, nil, "(omitted)", transforms, false)
			}
			out, err := digestReference(w, doc, sig, absoluteURI(opts.BaseURI, r.URI), transforms, opts.Attachments, false, opts.IDAttributes, opts.ResolveURI,
				strDeref(doc, opts.IDAttributes, opts.ResolveSecurityToken))
			if err == nil && detached && within(out.token, sig) {
				// The STR Dereference Transform renders the token's default
				// namespace in scope, which its placement decides.
				return fmt.Errorf("%w: reference %q digests a token inside the detached signature; set SignOptions.Parent", xmlsec.ErrUnsupportedAlgorithm, r.URI)
			}
			return err
		}); err != nil {
			return err
		}
		algElement(ref, "DigestMethod", r.DigestAlgorithm)
		xmltree.Text(xmltree.Element(ref, "ds", xmlsec.NSDSig, "DigestValue"), base64.StdEncoding.EncodeToString(h.Sum(nil)))
	}
	return nil
}

// placementIndependent reports whether transforms digest an element of a
// signature the same wherever that signature is later placed: only the
// enveloped-signature transform, exclusive canonicalization without an
// InclusiveNamespaces PrefixList, base64, and the STR Dereference Transform,
// which digests a token rather than the element (addReferences checks
// where that token stands). Inclusive canonicalization renders the
// ancestors' namespaces and xml: attributes, a PrefixList the in-scope
// namespaces, and the XPath and XSLT transforms can read anything around
// the element.
func placementIndependent(transforms []TransformSpec) bool {
	for _, t := range transforms {
		switch a := t.Algorithm; {
		case a == xmlsec.TransformEnvelopedSignature, a == xmlsec.TransformBase64, a == xmlsec.TransformSTR:
		case c14n.Algorithm(a).Exclusive() && len(t.InclusiveNamespacePrefixes) == 0:
		default:
			return false
		}
	}
	return true
}

// signatureTarget is the element a "#id" or #xpointer(id('ID')) uri names,
// or nil for any other uri or one that does not resolve, which digesting
// it reports.
func signatureTarget(doc, sig *xdm.Node, uri string, idAttrs []xdm.QName) *xdm.Node {
	if !isSameDocument(uri) {
		return nil
	}
	id, whole, _, err := sameDocumentTarget(uri)
	if err != nil || whole {
		return nil
	}
	el, _ := findID(doc, sig, id, idAttrs)
	return el
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
	if r.Type != "" && !isURI(r.Type) {
		return fmt.Errorf("%w: Reference.Type %q is not a URI", xmlsec.ErrMalformed, r.Type)
	}
	if r.OmitURI && r.URI != "" {
		return fmt.Errorf("%w: Reference.OmitURI with URI %q", xmlsec.ErrMalformed, r.URI)
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
	case !r.OmitURI && (r.URI == "" || r.URI == "#xpointer(/)") && first != xmlsec.TransformEnvelopedSignature:
		return fmt.Errorf("%w: a reference to the whole document must begin with enveloped-signature", xmlsec.ErrMalformed)
	case strings.HasPrefix(r.URI, "cid:") && first != xmlsec.TransformAttachmentContentSignature && first != xmlsec.TransformAttachmentCompleteSignature:
		// SwA profile 5.3 and WS-I BSP R6101: an attachment is signed
		// through one of the SwA signature transforms, never as raw octets.
		return fmt.Errorf("%w: a cid: reference must begin with %s or %s", xmlsec.ErrMalformed,
			xmlsec.TransformAttachmentContentSignature, xmlsec.TransformAttachmentCompleteSignature)
	case strings.HasPrefix(r.URI, "cid:") && hasTransform(r, xmlsec.TransformBase64):
		// SwA profile 5.4.4: transfer encoding is the MIME layer's, and no
		// peer expects a base64 transform on an attachment.
		return fmt.Errorf("%w: a cid: reference must not carry the base64 transform (SwA profile 5.4.4)", xmlsec.ErrMalformed)
	case hasTransform(r, xmlsec.TransformSTR) && (len(r.Transforms) != 1 || !strings.HasPrefix(r.URI, "#") || r.URI == "#xpointer(/)"):
		return fmt.Errorf("%w: the STR Dereference Transform must be the only transform of a reference to a wsse:SecurityTokenReference by ID", xmlsec.ErrMalformed)
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
	case xmlsec.TransformSTR:
		return strTransformParams(tr, t)
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
	switch {
	case opts.KeyInfo == KeyInfoNone && opts.KeyName != "":
		return errors.New("dsig: SignOptions.KeyName needs a KeyInfo form")
	case opts.KeyInfo == KeyInfoKeyName && opts.KeyName == "":
		return errors.New("dsig: KeyInfoKeyName needs SignOptions.KeyName")
	case (opts.KeyInfo == KeyInfoReference) != (opts.KeyInfoReferenceURI != ""):
		return errors.New("dsig: SignOptions.KeyInfoReferenceURI goes with KeyInfoReference, and only with it")
	case len(opts.Chain) > 0 && opts.KeyInfo != KeyInfoX509Data:
		return errors.New("dsig: SignOptions.Chain needs KeyInfoX509Data")
	case len(opts.X509Descriptors) > 0 && opts.KeyInfo != KeyInfoX509Data && opts.KeyInfo != KeyInfoX509Descriptors:
		return errors.New("dsig: SignOptions.X509Descriptors needs KeyInfoX509Data or KeyInfoX509Descriptors")
	}
	var ki *xdm.Node
	keyInfo := func() *xdm.Node {
		if ki == nil {
			ki = xmltree.Element(sig, "ds", xmlsec.NSDSig, "KeyInfo")
			if opts.KeyName != "" {
				xmltree.Text(xmltree.Element(ki, "ds", xmlsec.NSDSig, "KeyName"), opts.KeyName)
			}
		}
		return ki
	}
	switch opts.KeyInfo {
	case KeyInfoNone:
		return nil
	case KeyInfoKeyName:
		keyInfo()
		return nil
	case KeyInfoX509Data, KeyInfoX509Descriptors:
		return addX509Data(keyInfo(), key.Certificate, opts, opts.KeyInfo == KeyInfoX509Descriptors)
	case KeyInfoReference:
		if !strings.HasPrefix(opts.KeyInfoReferenceURI, "#") && !isExternal(opts.KeyInfoReferenceURI) {
			return fmt.Errorf("%w: KeyInfoReferenceURI %q is neither \"#id\" nor absolute", xmlsec.ErrMalformed, opts.KeyInfoReferenceURI)
		}
		e, err := dsig11Element(keyInfo(), "KeyInfoReference")
		if err != nil {
			return err
		}
		xmltree.SetAttr(e, "", "", "URI", opts.KeyInfoReferenceURI)
		return nil
	case KeyInfoSecurityTokenReference:
		if opts.KeyInfoElement != nil {
			if err := checkKeyInfoElement(key.Certificate, opts.KeyInfoElement); err != nil {
				return err
			}
			keyInfo().AppendChild(opts.KeyInfoElement)
			return nil
		}
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
		keyInfo().AppendChild(str)
		return nil
	case KeyInfoKeyValue, KeyInfoDEREncodedKeyValue:
		if err := checkRawKey(key.Certificate.PublicKey); err != nil {
			return err
		}
		return addRawKey(keyInfo(), key.Certificate, opts.KeyInfo)
	}
	return fmt.Errorf("dsig: unknown KeyInfoForm %d", opts.KeyInfo)
}

// addRawKey emits the certificate's key, which sign has checked is the
// signer's, into ki as ds:KeyValue or dsig11:DEREncodedKeyValue. addKeyInfo
// has refused a key the verifier would refuse as a raw key.
func addRawKey(ki *xdm.Node, cert *x509.Certificate, form KeyInfoForm) error {
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
