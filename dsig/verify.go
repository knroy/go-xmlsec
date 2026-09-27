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
	// *dsa.PublicKey for an explicitly allowed xmlsec.SigDSASHA1 (1024, 160)
	// or xmlsec.SigDSASHA256 ((2048, 256) or (3072, 256)).
	// Setting both is an error. The 2048-bit RSA minimum applied to a raw key
	// read from ds:KeyInfo does not apply to a pinned key, which crypto/rsa
	// bounds at 1024 bits.
	PublicKey crypto.PublicKey

	// AllowedSignatureAlgorithms restricts the accepted ds:SignatureMethod
	// values. Empty means the default set, today RSA and ECDSA with SHA-256,
	// SHA-384 and SHA-512. A
	// caller enforcing a profile passes exactly the values it permits;
	// accepting more is a downgrade surface.
	//
	// For every allow-list, an algorithm implemented only for legacy
	// interoperability is outside the default set, and accepted only when
	// named in the list: xmlsec.SigRSASHA1, SigDSASHA1, SigDSASHA256,
	// SigECDSASHA1 and the SigHMAC* constants here, xmlsec.DigestSHA1 for
	// digests. They are verified, and never produced by Sign, except
	// HMAC-SHA224, 256, 384 and 512, which Sign produces with
	// SignOptions.HMACKey and which are not weak: they are outside the
	// default set because their key is a shared secret only the caller can
	// supply. The SHA-224 algorithms (xmlsec.SigRSASHA224, SigECDSASHA224,
	// DigestSHA224) are outside the default sets too, though Sign produces
	// them on request.
	AllowedSignatureAlgorithms []string

	// AllowedDigestAlgorithms restricts ds:DigestMethod values. Empty means
	// the default set, today xmlsec.DigestSHA256, DigestSHA384 and
	// DigestSHA512; DigestSHA1 and DigestSHA224 are accepted only when named. It also bounds the
	// algorithm of a dsig11:X509Digest in ds:KeyInfo.
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

	// AllowedXPathExpressions opts in to the XPath (xmlsec.TransformXPath)
	// and XPath Filter 2.0 (xmlsec.TransformXPathFilter2) transforms, for
	// exactly the expressions listed. Empty, the default, refuses both with
	// xmlsec.ErrTransformRefused. A received expression is accepted when,
	// with surrounding whitespace trimmed, it equals an entry's Expr and each
	// prefix in the entry's Namespaces is bound to the same URI where it
	// stands; it is then compiled from the entry, with the entry's bindings.
	// Anything else is refused with xmlsec.ErrTransformRefused, before any
	// cryptographic work and before anything is compiled or evaluated. An
	// XPath Filter 2.0 Filter attribute is taken as received.
	//
	// A transform that drops part of what a reference names takes it out of
	// Coverage: an element is reported only when all of its subtree was
	// digested, the whole document only when nothing but the signature was
	// dropped. Evaluation costs one expression per node of the input.
	AllowedXPathExpressions []XPathExpression

	// AllowedXSLTStylesheets opts in to the XSLT transform
	// (xmlsec.TransformXSLT), for exactly the stylesheets listed. Empty, the
	// default, refuses it with xmlsec.ErrTransformRefused. A received
	// stylesheet is accepted when it equals an entry under Exclusive C14N
	// with every prefix the entry binds rendered, so no prefix the entry's
	// expressions use can be rebound; anything else is refused before any
	// cryptographic work. The stylesheet runs with no resolver of any kind,
	// and its output is bounded like a parsed document. Its output is new
	// content, so a reference through XSLT appears in Coverage.References
	// only, never as a covered element, document or attachment.
	AllowedXSLTStylesheets []*xdm.Node

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
	// before the reference. A key identifier or issuer-serial reference
	// resolved by ResolveSecurityToken must pass
	// wss.CheckSecurityTokenReference. With Certificate set, such a
	// reference must name that certificate, or verification fails with
	// xmlsec.ErrUnsupportedKeyInfo: a message that says it was signed by
	// someone else is what a substituted key looks like. (Lenient
	// verification ignores the reference under a pinned key, as it does
	// any ds:KeyInfo: WSS4J, for one, computes a SubjectKeyIdentifier for a
	// certificate without the extension that a comparison would reject.)
	// For profiles that demand WS-I Basic Security Profile conformance of
	// what they receive.
	StrictSecurityTokenReference bool

	// StrictBSP enforces the WS-I Basic Security Profile 1.1 rules on the
	// shape of the signature, before any cryptographic work, as
	// xenc.DecryptOptions.StrictBSP does on what is decrypted, refusing
	// with xmlsec.ErrMalformed:
	//
	//   - a ds:SignedInfo not canonicalized with Exclusive C14N (R5404), or
	//     a ds:SignatureMethod with children, such as HMACOutputLength
	//     (R5401);
	//   - a ds:KeyInfo holding anything but one wsse:SecurityTokenReference
	//     (R5402, R5417), or one wss.CheckSecurityTokenReference refuses;
	//   - a ds:Manifest or xenc:EncryptedData in the signature (R5403,
	//     R5440);
	//   - a reference without transforms (R5416, R5411), with a transform
	//     other than Exclusive C14N, XPath Filter 2.0, the STR Dereference
	//     Transform, enveloped-signature or an SwA signature transform
	//     (R5423), or ending in another than Exclusive C14N, the STR
	//     Dereference Transform or an SwA signature transform (R5412);
	//   - a cid: reference not beginning with an SwA signature transform
	//     (R6101), or a reference into the signature's own ds:Object, an
	//     enveloping signature (R3102).
	//
	// It implies StrictSecurityTokenReference. The profile's signature and
	// digest algorithm lists (R5420, R5421), which name SHA-1, RSA-SHA1 and
	// HMAC-SHA1, are not enforced: the allow-lists decide algorithms. For
	// receivers that require BSP conformance.
	StrictBSP bool

	// ResolveSecurityToken supplies the certificate a key identifier or
	// issuer-serial wsse:SecurityTokenReference names (X.509 Token Profile
	// 1.1.1 section 3.2): one the caller already holds and trusts, looked up
	// by wss.MatchSecurityTokenReference or its own index, never fetched. It
	// is called for such a reference in ds:KeyInfo, when no key is pinned,
	// before any cryptographic work and before TrustKey sees the
	// certificate; and for such a reference through the STR Dereference
	// Transform (xmlsec.TransformSTR), after the signature value has
	// verified, to build the X509v3 wsse:BinarySecurityToken that section
	// 8.3 digests. When nil, the first is refused with
	// xmlsec.ErrUnsupportedKeyInfo and the second with
	// xmlsec.ErrSecurityTokenUnavailable; an error it returns, or a nil
	// certificate, is xmlsec.ErrSecurityTokenUnavailable.
	ResolveSecurityToken func(str *xdm.Node) (*x509.Certificate, error)

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
	// nil, such a reference is refused, and so is a relative URI without
	// BaseURI.
	ResolveURI xmlsec.URIResolver

	// BaseURI, if set, is the absolute URI a relative reference URI is
	// resolved against (XML-DSig 4.4.3.1, RFC 3986) before it is given to
	// ResolveURI; Coverage.ExternalURIs reports the resolved form. It is the
	// caller's, and never taken from xml:base or anything else in the
	// document, which the signer controls. Without it, a relative URI is
	// refused.
	BaseURI string

	// RequireNFC refuses with xmlsec.ErrNotNFC a signature whose canonical
	// ds:SignedInfo, or the canonical octets of a same-document reference,
	// are not in Unicode Normalization Form C (XML-DSig 8.1.3), as Sign
	// never produces. Off by default: other signers need not normalize.
	RequireNFC bool

	// ResolveKeyName maps a ds:KeyName that ds:KeyInfo holds alone
	// (XML-DSig 4.5.1) to the signer's key: a certificate, or a raw key with
	// a nil certificate, never both. Beside any other key form a ds:KeyName
	// is only reported, in Coverage.KeyName. It runs before any
	// cryptographic work, on a name the unauthenticated message chose, so
	// it must look the name up among keys the caller already holds, and
	// never fetch. TrustKey still judges what it returns. An error it
	// returns is wrapped with xmlsec.ErrUnsupportedKeyInfo. When nil, a lone
	// ds:KeyName is refused. It is not called when a key is pinned.
	ResolveKeyName func(name string) (*x509.Certificate, crypto.PublicKey, error)

	// ResolveX509 supplies the certificate that ds:X509Data identifies
	// without carrying it (XML-DSig 4.5.4): by issuer and serial number,
	// SKI, subject name or dsig11:X509Digest, whose algorithm the digest
	// allow-list has already accepted. The certificate returned must match
	// every identifier given, or verification fails with
	// xmlsec.ErrUnsupportedKeyInfo, as does an error it returns. It runs
	// before any cryptographic work, like ResolveKeyName, with the same
	// cautions; TrustKey still applies. When nil, ds:X509Data without a
	// certificate is refused. It is not called when a key is pinned.
	ResolveX509 func(id X509Identifier) (*x509.Certificate, error)

	// StrictX509Data refuses, with xmlsec.ErrUnsupportedKeyInfo, a
	// ds:X509IssuerSerial, X509SKI, X509SubjectName or dsig11:X509Digest
	// beside carried certificates that describes none of them. XML-DSig
	// 4.5.4 requires the signer to keep them consistent, but real signers
	// renew a certificate and leave a stale descriptor, and a descriptor
	// selects nothing when the certificate is carried: by default they are
	// ignored, as Santuario ignores them, and TrustKey judges the
	// certificate.
	StrictX509Data bool

	// ResolveKeyInfoURI supplies the octets of an absolute URI that
	// ds:KeyInfo points at: a dsig11:KeyInfoReference to a ds:KeyInfo in
	// another document (XML-DSig 4.5.10), parsed with xmlsec.Parse, or a
	// ds:RetrievalMethod of Type rawX509Certificate (4.5.3), a DER
	// certificate. Unlike ResolveURI it runs BEFORE the signature is
	// verified, on a URI the unauthenticated message chose: every algorithm
	// has passed the allow-lists, but anyone can make it fetch. A safe one
	// serves only a fixed set of URIs (see xmlsec.URIResolver). What it
	// returns is only ever a key description, which TrustKey then judges,
	// and a reference found there is not followed. An error it returns is
	// wrapped with xmlsec.ErrDereference. When nil, such a reference is
	// refused. It is not called when a key is pinned.
	ResolveKeyInfoURI xmlsec.URIResolver
}

// Coverage describes exactly what a verified signature covered. A
// reference whose XPath or XPath Filter 2.0 transform dropped part of its
// target (other than the signature itself), or that went through XSLT,
// covers less than its URI names: it is listed in References only.
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

	// SignedTokens are the security tokens covered through the STR
	// Dereference Transform (xmlsec.TransformSTR), in reference order: the
	// token element in the message, or for a key identifier or
	// issuer-serial reference the X509v3 wsse:BinarySecurityToken built
	// from the certificate VerifyOptions.ResolveSecurityToken returned,
	// which is not in the document. The wsse:SecurityTokenReference itself
	// is not covered by such a reference, and is not reported.
	SignedTokens []*xdm.Node

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

	// KeyName is the ds:KeyName in ds:KeyInfo or, failing that, in the
	// ds:KeyInfo a dsig11:KeyInfoReference names, as received; "" when
	// there is none. KeyName, Intermediates and CRLs are reported only when
	// the key came from ds:KeyInfo, not when one was pinned.
	// It is not authenticated: the signature covers what KeyInfo describes
	// only when a Reference signs ds:KeyInfo.
	KeyName string

	// Intermediates are the ds:X509Certificate elements beside the signing
	// certificate in ds:X509Data, in document order: the path a caller may
	// build to its trust anchors. They are not verified in any way.
	Intermediates []*x509.Certificate

	// CRLs are the DER octets of each ds:X509CRL in ds:X509Data, not parsed
	// and not checked: revocation is the caller's decision.
	CRLs [][]byte

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
	return cov, unverifiable(err)
}

// unverifiable wraps with xmlsec.ErrUnverifiable an error that means the
// document has no canonical form.
func unverifiable(err error) error {
	if errors.Is(err, c14n.ErrRelativeNamespaceURI) || errors.Is(err, c14n.ErrXML11) {
		return fmt.Errorf("%w: %w", xmlsec.ErrUnverifiable, err)
	}
	return err
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
	if err := checkBaseURI(opts.BaseURI); err != nil {
		return nil, err
	}
	p, err := parseSignature(sig, maxReferences(opts))
	if err != nil {
		return nil, err
	}
	if err := checkOmitted(p.refs, opts); err != nil {
		return nil, err
	}
	if opts.StrictBSP {
		if err := checkBSP(doc, sig, p, opts.IDAttributes); err != nil {
			return nil, err
		}
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
	if err := admitReferences(p.refs, opts); err != nil {
		return nil, err
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

	// An HMAC key is pinned by definition: VerifyOptions.HMACKey.
	pinned := opts.Certificate != nil || opts.PublicKey != nil || mac
	strict := opts.StrictSecurityTokenReference || opts.StrictBSP
	if err := checkPinnedSTR(p.keyInfo, opts.Certificate, strict); err != nil {
		return nil, err
	}
	kc := keyContext{doc: doc, opts: opts}
	if _, ok := dsaKeySizes[p.sigAlg]; ok {
		kc.dsaAlg = p.sigAlg
	}
	if pinned {
		// Nothing is looked up or fetched for a key that will not be used.
		kc.opts.ResolveKeyName, kc.opts.ResolveX509, kc.opts.ResolveKeyInfoURI, kc.opts.ResolveSecurityToken = nil, nil, nil, nil
	}
	key, err := kc.resolve(p.keyInfo, false)
	cert, pub, form := key.cert, key.pub, key.form
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
	if err := checkNFC(opts.RequireNFC, h, "ds:SignedInfo", func(w hash.Hash) error {
		_, err := c14n.DigestNodeSet(w, c14n.Subtree(p.signedInfo), p.c14n)
		return err
	}); err != nil {
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
	if !pinned {
		cov.KeyName, cov.Intermediates, cov.CRLs = key.keyName, key.intermediates, key.crls
	}
	if err := digestReferences(cov, doc, sig, p.refs, raw, opts); err != nil {
		return nil, err
	}
	return cov, nil
}

// checkOmitted applies XML-DSig 4.4.3.1 to received references: at most
// one without a URI, and only with VerifyOptions.ResolveOmittedURI.
func checkOmitted(refs []parsedReference, opts VerifyOptions) error {
	omitted := 0
	for _, r := range refs {
		if r.omitted {
			omitted++
		}
	}
	switch {
	case omitted > 1:
		return malformed("%d ds:Reference elements without URI; at most one is allowed", omitted)
	case omitted == 1 && opts.ResolveOmittedURI == nil:
		return malformed("ds:Reference without URI, and no VerifyOptions.ResolveOmittedURI")
	}
	return nil
}

// admitReferences checks the algorithms and transforms of received
// references against the allow-lists, before any cryptographic work.
func admitReferences(refs []parsedReference, opts VerifyOptions) error {
	for _, r := range refs {
		if err := allowed("digest", r.digestAlg, opts.AllowedDigestAlgorithms, defaultDigest); err != nil {
			return err
		}
		if _, ok := digestHash(r.digestAlg); !ok {
			return fmt.Errorf("%w: digest %q", xmlsec.ErrUnsupportedAlgorithm, r.digestAlg)
		}
		for _, t := range r.transforms {
			if isC14N(t.Algorithm) {
				if err := allowed("canonicalization", t.Algorithm, opts.AllowedCanonicalizationAlgorithms, defaultC14N); err != nil {
					return err
				}
			}
			if t.Algorithm == xmlsec.TransformSTR {
				if err := allowed("STR Dereference Transform canonicalization", string(c14n.Exclusive10), opts.AllowedCanonicalizationAlgorithms, defaultC14N); err != nil {
					return err
				}
			}
		}
		// The SwA signature transforms canonicalize an XML attachment with
		// Exclusive C14N (SwA profile 5.4.2), so they need it allowed.
		for _, t := range r.transforms {
			if t.Algorithm == xmlsec.TransformAttachmentContentSignature || t.Algorithm == xmlsec.TransformAttachmentCompleteSignature {
				if err := allowed("attachment canonicalization", string(c14n.Exclusive10), opts.AllowedCanonicalizationAlgorithms, defaultC14N); err != nil {
					return err
				}
			}
		}
		for j := range r.transforms {
			if isProgramTransform(r.transforms[j].Algorithm) {
				if err := admitTransform(&r.transforms[j], opts); err != nil {
					return err
				}
			}
		}
		// The implicit Canonical XML 1.0 is subject to the allow-list like
		// any named one.
		if impliesC14N(!r.omitted && isSameDocument(r.uri), r.transforms) {
			if opts.RequireExplicitCanonicalization {
				return fmt.Errorf("%w: reference %q relies on implicit canonicalization", xmlsec.ErrAlgorithmNotAllowed, r.uri)
			}
			if err := allowed("implicit canonicalization", string(c14n.Inclusive10), opts.AllowedCanonicalizationAlgorithms, defaultC14N); err != nil {
				return err
			}
		}
	}
	return nil
}

// digestReferences digests each of refs, which admitReferences has
// admitted, compares it with its DigestValue and records what it covered
// in cov. sig is what the enveloped-signature transform removes, and whose
// own Ids "#id" resolves against; raw holds each reference's canonical form.
func digestReferences(cov *Coverage, doc, sig *xdm.Node, refs []parsedReference, raw [][]byte, opts VerifyOptions) error {
	deref := strDeref(doc, opts.IDAttributes, opts.ResolveSecurityToken)
	for i, r := range refs {
		dh, _ := digestHash(r.digestAlg)
		h := dh.New()
		var got dereferenced
		covered := true
		err := checkNFC(opts.RequireNFC && !r.omitted && isSameDocument(r.uri), h, fmt.Sprintf("reference %q", r.uri), func(w hash.Hash) error {
			var err error
			if r.omitted {
				covered, err = digestOmitted(w, r.transforms, opts.ResolveOmittedURI)
			} else {
				got, err = digestReference(w, doc, sig, absoluteURI(opts.BaseURI, r.uri), r.transforms, opts.Attachments, true, opts.IDAttributes, opts.ResolveURI, deref)
			}
			return err
		})
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(h.Sum(nil), r.digest) != 1 {
			return fmt.Errorf("%w: reference %q", xmlsec.ErrDigestMismatch, r.uri)
		}
		switch {
		case r.omitted:
			cov.OmittedURISigned = covered
		case got.token != nil:
			cov.SignedTokens = append(cov.SignedTokens, got.token)
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
	return nil
}

// maxReferences is VerifyOptions.MaxReferences, or its default.
func maxReferences(opts VerifyOptions) int {
	if opts.MaxReferences <= 0 {
		return DefaultMaxReferences
	}
	return opts.MaxReferences
}

// digestOmitted digests the data object of a Reference without a URI, as
// VerifyOptions.ResolveOmittedURI supplies it, and reports whether the
// transforms kept all of it.
func digestOmitted(h hash.Hash, transforms []TransformSpec, resolve func() ([]byte, error)) (bool, error) {
	b, err := resolve()
	if err != nil {
		return false, fmt.Errorf("dsig: ResolveOmittedURI: %w", err)
	}
	d := data{octets: b}
	err = d.digest(h, nil, "(omitted)", transforms, true)
	return d.covers(nil), err
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
	if _, ok := dsaKeySizes[alg]; ok {
		return verifyDSA(pub, alg, digest, sig)
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
