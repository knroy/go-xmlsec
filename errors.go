package xmlsec

import "errors"

var (
	// ErrUnsupportedAlgorithm is returned for an algorithm URI this library
	// does not implement.
	ErrUnsupportedAlgorithm = errors.New("xmlsec: unsupported algorithm")

	// ErrAlgorithmNotAllowed is returned when a received document names an
	// algorithm outside the caller's allow-list. It is checked before any
	// cryptographic work.
	ErrAlgorithmNotAllowed = errors.New("xmlsec: algorithm not allowed")

	// ErrTransformRefused is returned for the XSLT and XPath transforms,
	// which this library refuses by design.
	ErrTransformRefused = errors.New("xmlsec: transform refused")

	// ErrUnverifiable is returned when a document can never be verified
	// because it has no canonical form: it declares a relative namespace
	// URI, or it is XML 1.1. The underlying c14n error is wrapped. This is
	// a permanent failure, not a transient one.
	ErrUnverifiable = errors.New("xmlsec: document has no canonical form")

	// ErrMalformed is returned for a security element whose structure does
	// not match its schema.
	ErrMalformed = errors.New("xmlsec: malformed element")

	// ErrDigestMismatch is returned when a reference's digest does not
	// match the referenced content.
	ErrDigestMismatch = errors.New("xmlsec: digest mismatch")

	// ErrSignatureInvalid is returned when ds:SignatureValue does not verify.
	ErrSignatureInvalid = errors.New("xmlsec: signature value invalid")

	// ErrLimitExceeded is returned when input exceeds a resource limit.
	ErrLimitExceeded = errors.New("xmlsec: resource limit exceeded")

	// ErrUntrusted is returned when VerifyOptions.TrustKey refuses the
	// signer's key. The caller's reason is wrapped.
	ErrUntrusted = errors.New("xmlsec: certificate not trusted")

	// ErrAmbiguousID is returned when more than one element carries an ID
	// being resolved. Duplicate IDs are an XML Signature Wrapping technique.
	ErrAmbiguousID = errors.New("xmlsec: ambiguous ID")

	// ErrIDNotFound is returned when no element carries an ID being resolved.
	ErrIDNotFound = errors.New("xmlsec: ID not found")

	// ErrUnsupportedKeyInfo is returned for a ds:KeyInfo or
	// wsse:SecurityTokenReference form this library does not accept.
	ErrUnsupportedKeyInfo = errors.New("xmlsec: unsupported key info")

	// ErrAttachmentNotFound is returned when a cid: URI matches no attachment.
	ErrAttachmentNotFound = errors.New("xmlsec: attachment not found")

	// ErrDuplicateAttachmentID is returned when two attachments share an ID.
	ErrDuplicateAttachmentID = errors.New("xmlsec: duplicate attachment ID")
)
