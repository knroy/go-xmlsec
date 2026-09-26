package dsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
)

// VerifyOptions configures verification.
type VerifyOptions struct {
	// Certificate, if set, is the only key accepted. When nil, the
	// certificate is taken from the signature's KeyInfo, which means the
	// signature is self-describing and the CALLER MUST separately establish
	// that the certificate is trusted. This library does not make trust
	// decisions.
	//
	// When nil, an attacker can sign with their own key, and every reference
	// is digested before the caller can refuse their certificate. Set it
	// whenever the sender is known in advance: a signature from any other key
	// is then refused before any reference is processed.
	//
	// A pinned key replaces whatever ds:KeyInfo describes, which is then not
	// compared with it: a signature by another key fails as
	// ErrSignatureInvalid. ds:KeyInfo is still read, so a form this library
	// does not accept, or a malformed one, is refused even when a key is
	// pinned.
	Certificate *x509.Certificate

	// PublicKey, if set, is the only key accepted, as Certificate but for a
	// sender known by a raw key: an *rsa.PublicKey or *ecdsa.PublicKey.
	// Setting both is an error. The 2048-bit RSA minimum applied to a raw key
	// read from ds:KeyInfo does not apply to a pinned key, which crypto/rsa
	// bounds at 1024 bits.
	PublicKey crypto.PublicKey

	// AllowedSignatureAlgorithms restricts the accepted ds:SignatureMethod
	// values. Empty means every Sig* constant. A caller enforcing a profile
	// passes exactly the values it permits; accepting more is a downgrade
	// surface.
	AllowedSignatureAlgorithms []string

	// AllowedDigestAlgorithms restricts ds:DigestMethod values. Empty means
	// every Digest* constant.
	AllowedDigestAlgorithms []string

	// AllowedCanonicalizationAlgorithms restricts ds:CanonicalizationMethod
	// and canonicalization transform values. Empty means every c14n
	// Algorithm constant.
	AllowedCanonicalizationAlgorithms []string

	// Attachments resolves cid: references encountered during verification.
	Attachments xmlsec.AttachmentSet

	// IDAttributes names attributes that "#id" references resolve against
	// in addition to wsu:Id and xml:id: IDAttrSAML for a SAML assertion,
	// IDAttrDSig for XAdES. Empty means only those two. An id value carried
	// by more than one attribute of the whole set is refused with
	// xmlsec.ErrAmbiguousID. Name only what the profile defines as an ID:
	// each attribute added widens the signature wrapping surface, and the
	// application must locate what it reads by the same attributes, or by
	// Coverage.SignedElements.
	IDAttributes []xdm.QName

	// MaxReferences caps the number of ds:Reference elements processed.
	// Zero means DefaultMaxReferences. Set it to what the profile needs: it
	// bounds how much work one message can force.
	MaxReferences int

	// TrustKey, if set, is called with the key the signature is about to be
	// verified against, and its certificate when there is one (nil for a raw
	// key), after ds:KeyInfo is resolved and before any cryptographic or
	// digest work. Returning an error stops verification with ErrUntrusted,
	// wrapping it. It lets a caller that cannot pin one key still refuse a
	// sender before the message costs anything to process.
	TrustKey func(cert *x509.Certificate, key crypto.PublicKey) error

	// RequireExplicitCanonicalization refuses a same-document reference
	// whose transforms end in a node set, instead of completing it with the
	// Canonical XML 1.0 that XML-DSig 4.4.3.2 implies. Most signers rely on
	// the implied form, so this is off by default; a profile that names its
	// canonicalization on every reference can turn it on.
	RequireExplicitCanonicalization bool
}

// Coverage describes exactly what a verified signature covered.
type Coverage struct {
	// SignedElementIDs are the IDs of elements covered by a same-document
	// reference, in reference order: the id value, whichever attribute
	// carried it.
	SignedElementIDs []string

	// SignedElements are the covered elements themselves, in reference
	// order, for callers that need to check identity rather than ID.
	SignedElements []*xdm.Node

	// WholeDocumentSigned is true if a reference with an empty URI covered
	// the document, as in an enveloped signature.
	WholeDocumentSigned bool

	// SignedAttachmentIDs are the attachment IDs covered by cid:
	// references, in reference order.
	SignedAttachmentIDs []string

	// Certificate is the certificate the signature was verified against. It
	// is nil when the key was a raw one: VerifyOptions.PublicKey, or a
	// KeyInfoKeyValue or KeyInfoDEREncodedKeyValue form.
	Certificate *x509.Certificate

	// PublicKey is the key the signature was verified with, always set: the
	// certificate's key when there is a certificate.
	PublicKey crypto.PublicKey

	// KeyInfoForm records how the key was described in the signature. When a
	// key was pinned, that description was read but not used.
	KeyInfoForm KeyInfoSpec

	// References are the verified references in order, retained because
	// some receipts must echo them.
	References []VerifiedReference
}

// VerifiedReference is one verified ds:Reference, as it appeared.
type VerifiedReference struct {
	URI             string
	Type            string
	DigestAlgorithm string
	DigestValue     []byte
	Transforms      []TransformSpec

	// Raw is the ds:Reference element canonicalized with the SignedInfo's
	// own canonicalization algorithm. xdm keeps no source offsets, so the
	// original octets are not available; for exclusive canonicalization,
	// which receipts use, this is what a receipt reproduces.
	Raw []byte
}

// Covers reports whether every given element ID appears in SignedElementIDs.
func (c *Coverage) Covers(elementIDs ...string) bool {
	for _, id := range elementIDs {
		if !slices.Contains(c.SignedElementIDs, id) {
			return false
		}
	}
	return true
}

// CoversAttachments reports whether every given attachment ID appears in
// SignedAttachmentIDs.
func (c *Coverage) CoversAttachments(attachmentIDs ...string) bool {
	for _, id := range attachmentIDs {
		if !slices.Contains(c.SignedAttachmentIDs, id) {
			return false
		}
	}
	return true
}

// Verify checks a ds:Signature and reports what it covered.
//
// doc must have been parsed with xmlsec.Parse, and sig must be inside it.
//
// The returned Coverage is not optional detail: a valid signature over the
// wrong elements is the basis of XML Signature Wrapping attacks, so the
// caller MUST inspect Coverage and confirm it includes everything its
// profile requires.
//
// A non-nil error means the signature is invalid or malformed. A nil error
// means the signature is cryptographically valid over precisely the nodes
// described in Coverage, and nothing more. It says nothing about whether
// the certificate or key is trusted.
func Verify(doc *xdm.Node, sig *xdm.Node, opts VerifyOptions) (*Coverage, error) {
	cov, err := verify(doc, sig, opts)
	if errors.Is(err, c14n.ErrRelativeNamespaceURI) || errors.Is(err, c14n.ErrXML11) {
		err = fmt.Errorf("%w: %w", xmlsec.ErrUnverifiable, err)
	}
	return cov, err
}

func verify(doc, sig *xdm.Node, opts VerifyOptions) (*Coverage, error) {
	if doc == nil || sig == nil || !sig.IsElement(NSDSig, "Signature") {
		return nil, malformed("not a ds:Signature")
	}
	if sig.Root() != doc.Root() {
		return nil, errors.New("dsig: signature is not inside the document")
	}
	if opts.Certificate != nil && opts.PublicKey != nil {
		return nil, errors.New("dsig: VerifyOptions.Certificate and PublicKey are both set")
	}
	maxRefs := opts.MaxReferences
	if maxRefs <= 0 {
		maxRefs = DefaultMaxReferences
	}
	p, err := parseSignature(sig, maxRefs)
	if err != nil {
		return nil, err
	}

	// Every algorithm is checked before any cryptographic work.
	if err := allowed("signature", p.sigAlg, opts.AllowedSignatureAlgorithms, func(s string) bool { _, ok := xmlsec.SignatureHash(s); return ok }); err != nil {
		return nil, err
	}
	if p.sigMethodChildren > 0 {
		return nil, malformed("ds:SignatureMethod has children")
	}
	if err := allowed("canonicalization", string(p.c14n.Algorithm), opts.AllowedCanonicalizationAlgorithms, isC14N); err != nil {
		return nil, err
	}
	for _, r := range p.refs {
		if err := allowed("digest", r.digestAlg, opts.AllowedDigestAlgorithms, func(s string) bool { _, ok := xmlsec.DigestHash(s); return ok }); err != nil {
			return nil, err
		}
		for _, t := range r.transforms {
			if isC14N(t.Algorithm) {
				if err := allowed("canonicalization", t.Algorithm, opts.AllowedCanonicalizationAlgorithms, isC14N); err != nil {
					return nil, err
				}
			}
		}
		// The SwA signature transforms canonicalize an XML attachment with
		// Exclusive C14N (SwA profile 5.4.2), so they need it allowed.
		for _, t := range r.transforms {
			if t.Algorithm == xmlsec.TransformAttachmentContentSignature || t.Algorithm == xmlsec.TransformAttachmentCompleteSignature {
				if err := allowed("attachment canonicalization", string(c14n.Exclusive10), opts.AllowedCanonicalizationAlgorithms, isC14N); err != nil {
					return nil, err
				}
			}
		}
		// The implicit Canonical XML 1.0 is subject to the allow-list like
		// any named one.
		if impliesC14N(r.uri, r.transforms) {
			if opts.RequireExplicitCanonicalization {
				return nil, fmt.Errorf("%w: reference %q relies on implicit canonicalization", xmlsec.ErrAlgorithmNotAllowed, r.uri)
			}
			if err := allowed("implicit canonicalization", string(c14n.Inclusive10), opts.AllowedCanonicalizationAlgorithms, isC14N); err != nil {
				return nil, err
			}
		}
	}

	// Each Reference's canonical form, for Coverage.Raw. Taken before
	// SignedInfo is, so a document with no canonical form fails here first;
	// SignedInfo can still fail on its own, on a relative namespace only it
	// uses under exclusive canonicalization.
	raw := make([][]byte, len(p.refs))
	for i, r := range p.refs {
		if raw[i], err = c14n.Bytes(r.el, p.c14n); err != nil {
			return nil, err
		}
	}

	cert, pub, form, err := resolveKeyInfo(doc, p.keyInfo)
	if err != nil {
		return nil, err
	}
	switch {
	case opts.Certificate != nil:
		cert, pub = opts.Certificate, opts.Certificate.PublicKey
	case opts.PublicKey != nil:
		cert, pub = nil, opts.PublicKey
	}
	if pub == nil {
		return nil, fmt.Errorf("%w: no key supplied and none in ds:KeyInfo", xmlsec.ErrUnsupportedKeyInfo)
	}
	if opts.TrustKey != nil {
		if err := opts.TrustKey(cert, pub); err != nil {
			return nil, fmt.Errorf("%w: %w", xmlsec.ErrUntrusted, err)
		}
	}

	// SignedInfo is canonicalized where it stands in the received tree.
	// Extracting it first would change its in-scope namespaces.
	sigHash, _ := xmlsec.SignatureHash(p.sigAlg)
	h := sigHash.New()
	if _, err := c14n.DigestNodeSet(h, c14n.Subtree(p.signedInfo), p.c14n); err != nil {
		return nil, err
	}
	if err := verifyDigest(pub, p.sigAlg, sigHash, h.Sum(nil), p.value); err != nil {
		return nil, err
	}

	cov := &Coverage{Certificate: cert, PublicKey: pub, KeyInfoForm: form}
	for i, r := range p.refs {
		dh, _ := xmlsec.DigestHash(r.digestAlg)
		h := dh.New()
		got, err := digestReference(h, doc, sig, r.uri, r.transforms, opts.Attachments, true, opts.IDAttributes)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(h.Sum(nil), r.digest) != 1 {
			return nil, fmt.Errorf("%w: reference %q", xmlsec.ErrDigestMismatch, r.uri)
		}
		switch {
		case got.whole:
			cov.WholeDocumentSigned = true
		case got.element != nil:
			cov.SignedElementIDs = append(cov.SignedElementIDs, r.uri[1:])
			cov.SignedElements = append(cov.SignedElements, got.element)
		case got.attachment != nil:
			cov.SignedAttachmentIDs = append(cov.SignedAttachmentIDs, got.attachment.ID)
		}
		cov.References = append(cov.References, VerifiedReference{
			URI: r.uri, Type: r.typ, DigestAlgorithm: r.digestAlg,
			DigestValue: r.digest, Transforms: r.transforms, Raw: raw[i],
		})
	}
	return cov, nil
}

// allowed checks v against list, or against known when list is empty.
func allowed(kind, v string, list []string, known func(string) bool) error {
	if len(list) == 0 && known(v) || slices.Contains(list, v) {
		return nil
	}
	return fmt.Errorf("%w: %s algorithm %q", xmlsec.ErrAlgorithmNotAllowed, kind, v)
}

func verifyDigest(pub crypto.PublicKey, alg string, h crypto.Hash, digest, sig []byte) error {
	isEC := ecdsaAlgorithms[alg]
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if isEC {
			break
		}
		if rsa.VerifyPKCS1v15(k, h, digest, sig) != nil {
			return xmlsec.ErrSignatureInvalid
		}
		return nil
	case *ecdsa.PublicKey:
		if !isEC {
			break
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return xmlsec.ErrSignatureInvalid
		}
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, digest, r, s) {
			return xmlsec.ErrSignatureInvalid
		}
		return nil
	}
	return fmt.Errorf("%w: %s with a %T key", xmlsec.ErrUnsupportedAlgorithm, alg, pub)
}
