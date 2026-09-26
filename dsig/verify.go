package dsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"slices"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/hashes"
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
	// ErrSignatureInvalid. ds:KeyInfo is only a hint (XML-DSig 3.2.2: "from
	// KeyInfo or from an external source"), so a form this library does not
	// accept is then ignored, and Coverage.KeyInfoForm is KeyInfoNone. It is
	// still read: a malformed one, or one whose reference is ambiguous, is
	// refused even when a key is pinned.
	Certificate *x509.Certificate

	// PublicKey, if set, is the only key accepted, as Certificate but for a
	// sender known by a raw key: an *rsa.PublicKey or *ecdsa.PublicKey, or a
	// (1024, 160) *dsa.PublicKey for an explicitly allowed xmlsec.SigDSASHA1.
	// Setting both is an error. The 2048-bit RSA minimum applied to a raw key
	// read from ds:KeyInfo does not apply to a pinned key, which crypto/rsa
	// bounds at 1024 bits.
	PublicKey crypto.PublicKey

	// AllowedSignatureAlgorithms restricts the accepted ds:SignatureMethod
	// values. Empty means the default set, today every Sig* constant. A
	// caller enforcing a profile passes exactly the values it permits;
	// accepting more is a downgrade surface.
	//
	// For every allow-list, an algorithm implemented only for legacy
	// interoperability is outside the default set, and accepted only when
	// named in the list: xmlsec.SigRSASHA1, SigDSASHA1 and the SigHMAC*
	// constants here, xmlsec.DigestSHA1 for digests. They are verified, and
	// never produced by Sign.
	AllowedSignatureAlgorithms []string

	// AllowedDigestAlgorithms restricts ds:DigestMethod values. Empty means
	// the default set, today every Digest* constant; xmlsec.DigestSHA1 is
	// accepted only when named.
	AllowedDigestAlgorithms []string

	// HMACKey is the shared secret of an HMAC ds:SignatureMethod
	// (xmlsec.SigHMAC*, each accepted only when named in
	// AllowedSignatureAlgorithms). An HMAC key is only ever this: never
	// anything in ds:KeyInfo, never a certificate or public key. An HMAC
	// signature without it is refused with xmlsec.ErrUnsupportedKeyInfo; with
	// it, any other SignatureMethod is refused with
	// xmlsec.ErrAlgorithmNotAllowed, since a caller holding a shared secret
	// expects a MAC, not a signature by whatever key ds:KeyInfo names. It
	// cannot be combined with Certificate or PublicKey. ds:KeyInfo is read as
	// for a pinned key, and not used. ds:HMACOutputLength, when present, must
	// be a multiple of 8 no smaller than half the hash output and 80 bits
	// (XML-DSig 4.4.2, CVE-2009-0217); the MAC is compared in constant time.
	// TrustKey is not called, and Coverage.PublicKey is nil.
	HMACKey []byte

	// AllowedCanonicalizationAlgorithms restricts ds:CanonicalizationMethod
	// and canonicalization transform values. Empty means the default set,
	// today every c14n Algorithm constant.
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

	// StrictSecurityTokenReference resolves a wsse:SecurityTokenReference in
	// ds:KeyInfo with wss.ResolveSecurityTokenReferenceStrict: the reference
	// must carry the token's ValueType (and TokenType where the profile
	// requires one), and the token must be in the same wsse:Security header,
	// before the reference. For profiles that demand WS-I Basic Security
	// Profile conformance of what they receive.
	StrictSecurityTokenReference bool

	// ResolveOmittedURI supplies the data object of a ds:Reference without
	// a URI attribute, which XML-DSig 4.4.3.1 allows on at most one
	// Reference: "the receiving application is expected to know the
	// identity of the object". The returned octets go through that
	// Reference's transforms, which must accept octets, and are digested.
	// It is called only after the signature value has verified. When nil, a
	// Reference without a URI is refused; more than one is always refused.
	ResolveOmittedURI func() ([]byte, error)

	// ResolveURI supplies the octets of a ds:Reference to an absolute URI
	// other than cid:, such as "http://example.com/data.xml", which XML-DSig
	// 4.4.3.1 recommends dereferencing. The octets go through that
	// Reference's transforms as an octet stream, and Coverage.ExternalURIs
	// reports the URI. Like ResolveOmittedURI, it is called only after
	// every algorithm has passed the allow-lists, TrustKey has accepted the
	// key and the signature value has verified, so a message from an
	// untrusted or wrong key never makes it fetch. It is still called with
	// URIs the signer chose: see xmlsec.URIResolver for what a safe one
	// does. An error it returns is wrapped with xmlsec.ErrDereference. When
	// nil, such a reference is refused, and a relative URI is always
	// refused.
	ResolveURI xmlsec.URIResolver
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

	// WholeDocumentSigned is true if a reference with an empty URI, or
	// "#xpointer(/)", covered the document, as in an enveloped signature.
	WholeDocumentSigned bool

	// SignedAttachmentIDs are the attachment IDs covered by cid:
	// references, in reference order.
	SignedAttachmentIDs []string

	// OmittedURISigned is true if a reference without a URI covered the
	// octets VerifyOptions.ResolveOmittedURI returned.
	OmittedURISigned bool

	// ExternalURIs are the absolute URIs of references whose octets
	// VerifyOptions.ResolveURI supplied, in reference order. What the
	// resolver returned for each is what was signed.
	ExternalURIs []string

	// Certificate is the certificate the signature was verified against. It
	// is nil when the key was a raw one: VerifyOptions.PublicKey, or a
	// KeyInfoKeyValue or KeyInfoDEREncodedKeyValue form.
	Certificate *x509.Certificate

	// PublicKey is the key the signature was verified with: the
	// certificate's key when there is a certificate. It is set except for an
	// HMAC, whose key is VerifyOptions.HMACKey.
	PublicKey crypto.PublicKey

	// KeyInfoForm records how the key was described in the signature; for a
	// dsig11:KeyInfoReference, how the ds:KeyInfo it references describes
	// it. When a key was pinned, that description was read but not used, and
	// a form this library does not accept is reported as KeyInfoNone.
	KeyInfoForm KeyInfoForm

	// References are the verified references in order, retained because
	// some receipts must echo them.
	References []VerifiedReference
}

// VerifiedReference is one verified ds:Reference, as it appeared.
type VerifiedReference struct {
	// URI is "" both for an empty URI and for an omitted one; Raw shows
	// which.
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
	if doc == nil || sig == nil || !sig.IsElement(xmlsec.NSDSig, "Signature") {
		return nil, malformed("not a ds:Signature")
	}
	if sig.Root() != doc.Root() {
		return nil, errors.New("dsig: signature is not inside the document")
	}
	if opts.Certificate != nil && opts.PublicKey != nil {
		return nil, errors.New("dsig: VerifyOptions.Certificate and PublicKey are both set")
	}
	if len(opts.HMACKey) > 0 && (opts.Certificate != nil || opts.PublicKey != nil) {
		return nil, errors.New("dsig: VerifyOptions.HMACKey is set with Certificate or PublicKey")
	}
	maxRefs := opts.MaxReferences
	if maxRefs <= 0 {
		maxRefs = DefaultMaxReferences
	}
	p, err := parseSignature(sig, maxRefs)
	if err != nil {
		return nil, err
	}
	omitted := 0
	for _, r := range p.refs {
		if r.omitted {
			omitted++
		}
	}
	switch {
	case omitted > 1:
		return nil, malformed("%d ds:Reference elements without URI; at most one is allowed", omitted)
	case omitted == 1 && opts.ResolveOmittedURI == nil:
		return nil, malformed("ds:Reference without URI, and no VerifyOptions.ResolveOmittedURI")
	}

	// Every algorithm is checked before any cryptographic work.
	if err := allowed("signature", p.sigAlg, opts.AllowedSignatureAlgorithms, defaultSignature); err != nil {
		return nil, err
	}
	sigHash, ok := signatureHash(p.sigAlg)
	if !ok {
		return nil, fmt.Errorf("%w: signature %q", xmlsec.ErrUnsupportedAlgorithm, p.sigAlg)
	}
	mac := hmacAlgorithms[p.sigAlg]
	macLen := 0
	switch {
	case mac:
		if macLen, err = hmacOutputLength(p.sigMethod, sigHash); err != nil {
			return nil, err
		}
		if len(opts.HMACKey) == 0 {
			return nil, fmt.Errorf("%w: %s needs VerifyOptions.HMACKey; an HMAC key is never taken from ds:KeyInfo, a certificate or a public key",
				xmlsec.ErrUnsupportedKeyInfo, p.sigAlg)
		}
	case len(p.sigMethod.ChildElements()) > 0:
		return nil, malformed("ds:SignatureMethod has children")
	case len(opts.HMACKey) > 0:
		return nil, fmt.Errorf("%w: VerifyOptions.HMACKey is set, and signature algorithm %q is not HMAC", xmlsec.ErrAlgorithmNotAllowed, p.sigAlg)
	}
	if err := allowed("canonicalization", string(p.c14n.Algorithm), opts.AllowedCanonicalizationAlgorithms, defaultC14N); err != nil {
		return nil, err
	}
	for _, r := range p.refs {
		if err := allowed("digest", r.digestAlg, opts.AllowedDigestAlgorithms, defaultDigest); err != nil {
			return nil, err
		}
		if _, ok := digestHash(r.digestAlg); !ok {
			return nil, fmt.Errorf("%w: digest %q", xmlsec.ErrUnsupportedAlgorithm, r.digestAlg)
		}
		for _, t := range r.transforms {
			if isC14N(t.Algorithm) {
				if err := allowed("canonicalization", t.Algorithm, opts.AllowedCanonicalizationAlgorithms, defaultC14N); err != nil {
					return nil, err
				}
			}
		}
		// The SwA signature transforms canonicalize an XML attachment with
		// Exclusive C14N (SwA profile 5.4.2), so they need it allowed.
		for _, t := range r.transforms {
			if t.Algorithm == xmlsec.TransformAttachmentContentSignature || t.Algorithm == xmlsec.TransformAttachmentCompleteSignature {
				if err := allowed("attachment canonicalization", string(c14n.Exclusive10), opts.AllowedCanonicalizationAlgorithms, defaultC14N); err != nil {
					return nil, err
				}
			}
		}
		// The implicit Canonical XML 1.0 is subject to the allow-list like
		// any named one.
		if impliesC14N(!r.omitted && isSameDocument(r.uri), r.transforms) {
			if opts.RequireExplicitCanonicalization {
				return nil, fmt.Errorf("%w: reference %q relies on implicit canonicalization", xmlsec.ErrAlgorithmNotAllowed, r.uri)
			}
			if err := allowed("implicit canonicalization", string(c14n.Inclusive10), opts.AllowedCanonicalizationAlgorithms, defaultC14N); err != nil {
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

	cert, pub, form, err := resolveKeyInfo(doc, p.keyInfo, opts.IDAttributes, opts.StrictSecurityTokenReference, p.sigAlg == xmlsec.SigDSASHA1)
	// An HMAC key is pinned by definition: VerifyOptions.HMACKey.
	pinned := opts.Certificate != nil || opts.PublicKey != nil || mac
	switch {
	case pinned && errors.Is(err, xmlsec.ErrUnsupportedKeyInfo):
		// XML-DSig 3.2.2: the key comes "from KeyInfo or from an external
		// source". With the key pinned, a form this library does not
		// implement is a hint it cannot use, not an error.
		form = KeyInfoNone
	case err != nil:
		return nil, err
	}
	switch {
	case mac:
		// Whatever ds:KeyInfo described never keys an HMAC.
		cert, pub = nil, nil
	case opts.Certificate != nil:
		cert, pub = opts.Certificate, opts.Certificate.PublicKey
	case opts.PublicKey != nil:
		cert, pub = nil, opts.PublicKey
	}
	if pub == nil && !mac {
		return nil, fmt.Errorf("%w: no key supplied and none in ds:KeyInfo", xmlsec.ErrUnsupportedKeyInfo)
	}
	if opts.TrustKey != nil && !mac {
		if err := opts.TrustKey(cert, pub); err != nil {
			return nil, fmt.Errorf("%w: %w", xmlsec.ErrUntrusted, err)
		}
	}

	// SignedInfo is canonicalized where it stands in the received tree.
	// Extracting it first would change its in-scope namespaces.
	var h hash.Hash
	if mac {
		h = hmac.New(sigHash.New, opts.HMACKey)
	} else {
		h = sigHash.New()
	}
	if _, err := c14n.DigestNodeSet(h, c14n.Subtree(p.signedInfo), p.c14n); err != nil {
		return nil, err
	}
	if mac {
		// Constant time; the truncation length is public, from SignedInfo.
		if !hmac.Equal(h.Sum(nil)[:macLen], p.value) {
			return nil, xmlsec.ErrSignatureInvalid
		}
	} else if err := verifyDigest(pub, p.sigAlg, sigHash, h.Sum(nil), p.value); err != nil {
		return nil, err
	}

	cov := &Coverage{Certificate: cert, PublicKey: pub, KeyInfoForm: form}
	for i, r := range p.refs {
		dh, _ := digestHash(r.digestAlg)
		h := dh.New()
		var got dereferenced
		if r.omitted {
			err = digestOmitted(h, r.transforms, opts.ResolveOmittedURI)
		} else {
			got, err = digestReference(h, doc, sig, r.uri, r.transforms, opts.Attachments, true, opts.IDAttributes, opts.ResolveURI)
		}
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(h.Sum(nil), r.digest) != 1 {
			return nil, fmt.Errorf("%w: reference %q", xmlsec.ErrDigestMismatch, r.uri)
		}
		switch {
		case r.omitted:
			cov.OmittedURISigned = true
		case got.whole:
			cov.WholeDocumentSigned = true
		case got.element != nil:
			cov.SignedElementIDs = append(cov.SignedElementIDs, got.id)
			cov.SignedElements = append(cov.SignedElements, got.element)
		case got.attachment != nil:
			cov.SignedAttachmentIDs = append(cov.SignedAttachmentIDs, got.attachment.ID)
		case got.external != "":
			cov.ExternalURIs = append(cov.ExternalURIs, got.external)
		}
		cov.References = append(cov.References, VerifiedReference{
			URI: r.uri, Type: r.typ, DigestAlgorithm: r.digestAlg,
			DigestValue: r.digest, Transforms: r.transforms, Raw: raw[i],
		})
	}
	return cov, nil
}

// digestOmitted digests the data object of a Reference without a URI, as
// VerifyOptions.ResolveOmittedURI supplies it.
func digestOmitted(h hash.Hash, transforms []TransformSpec, resolve func() ([]byte, error)) error {
	b, err := resolve()
	if err != nil {
		return fmt.Errorf("dsig: ResolveOmittedURI: %w", err)
	}
	return data{octets: b}.digest(h, nil, "(omitted)", transforms, true)
}

// The default sets: what an empty allow-list accepts. An algorithm
// implemented only for legacy interoperability (legacy.go) is left out of
// them, so it is accepted only when an allow-list names it:
// hashes.Signature and hashes.Digest never return one.
func defaultSignature(alg string) bool { _, ok := hashes.Signature(alg); return ok }
func defaultDigest(alg string) bool    { _, ok := hashes.Digest(alg); return ok }
func defaultC14N(alg string) bool      { return isC14N(alg) }

// allowed checks v against list, or against the default set when list is
// empty. A non-empty list is the whole policy: it may name an algorithm
// outside the default set.
func allowed(kind, v string, list []string, isDefault func(string) bool) error {
	if len(list) == 0 && isDefault(v) || slices.Contains(list, v) {
		return nil
	}
	return fmt.Errorf("%w: %s algorithm %q", xmlsec.ErrAlgorithmNotAllowed, kind, v)
}

// verifyDigest checks a public-key SignatureValue. An HMAC never reaches it.
func verifyDigest(pub crypto.PublicKey, alg string, h crypto.Hash, digest, sig []byte) error {
	if alg == xmlsec.SigDSASHA1 {
		return verifyDSA(pub, digest, sig)
	}
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
