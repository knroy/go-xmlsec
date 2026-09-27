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

	// ErrTransformRefused is returned for an XSLT, XPath or XPath Filter 2.0
	// transform whose stylesheet or expression the caller has not allowed,
	// before any cryptographic work.
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

	// ErrMessageExpired is returned when a wsu:Timestamp is not fresh: it
	// has expired, was created in the future, or is older than the caller
	// allows. It is the WS-Security wsse:MessageExpired fault.
	ErrMessageExpired = errors.New("xmlsec: message expired")

	// ErrAttachmentNotFound is returned when a cid: URI matches no attachment.
	ErrAttachmentNotFound = errors.New("xmlsec: attachment not found")

	// ErrDereference is returned when a URIResolver fails to supply an
	// external reference. The resolver's error is wrapped.
	ErrDereference = errors.New("xmlsec: URI dereference failed")

	// ErrDuplicateAttachmentID is returned when two attachments share an ID.
	ErrDuplicateAttachmentID = errors.New("xmlsec: duplicate attachment ID")

	// ErrNotNFC is returned when an element or element content to be
	// encrypted is not in Unicode Normalization Form C, which XML Encryption
	// 1.1 section 4.3 requires of the plaintext; when dsig.Sign is asked to
	// sign content, or a ds:SignedInfo, that is not (XML Signature 1.1
	// section 8.1.3); and by dsig.Verify with VerifyOptions.RequireNFC. It
	// is refused rather than normalized: normalizing would change content
	// that may already be signed.
	ErrNotNFC = errors.New("xmlsec: not in Unicode Normalization Form C")

	// ErrDecryptionFailed is wrapped by every failure of the decryption
	// itself: a key unwrap whose integrity check fails, an RSA-OAEP key
	// transport that does not decrypt, AES-GCM data whose tag does not
	// verify, CBC data with bad padding, a session key of the wrong length
	// for the data, and a decrypted EncryptedHeader that does not parse to
	// one element. Each cause gives the same error, without detail, so that
	// a receiver cannot be used as an oracle; report it as the WS-Security
	// wsse:FailedCheck fault (SOAP Message Security 1.1.1 section 12) and
	// never say which step failed.
	ErrDecryptionFailed = errors.New("xmlsec: decryption failed")
)
