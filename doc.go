// Package xmlsec implements XML Signature, XML Encryption and the
// WS-Security profile of the two, over the go-xml node model.
//
// It has no knowledge of AS4, ebMS3 or any other messaging profile. Callers
// supply documents, node selections, keys and attachments; this package
// supplies octets and verdicts.
//
// Every algorithm is named explicitly at every call site. There are no
// defaults, because document families differ in the canonicalization they
// require and a default would silently produce a valid-looking signature
// that no peer accepts.
//
// # Canonicalization
//
// Canonicalization is not implemented here. It belongs to
// github.com/knroy/go-xml/c14n, whose Algorithm constants are used directly:
//
//	c14n.Exclusive10    // WS-Security, AS4
//	c14n.Inclusive10    // enveloped document signatures such as SMP
//
// # Threat model
//
// dsig.Verify establishes that a signature was made by the key in a given
// certificate over exactly the nodes it reports in its Coverage. It makes
// NO trust decision about that certificate: whether the certificate is
// trusted is the caller's question. A caller that treats a nil error from
// Verify as "this message is authentic" has a vulnerability.
//
// A valid signature over the wrong elements is the basis of XML Signature
// Wrapping. The caller must check Coverage against what its profile
// requires. Same-document ID resolution refuses duplicate IDs for the same
// reason.
//
// Documents to be verified must be parsed with Parse, whose options are
// fixed: the parse is part of the signature, so two different parse
// configurations can make one set of octets verify one way and not another.
//
// Parsing can cost about 40 times the input in memory, and a signature that
// is not checked against a pinned certificate can be the attacker's own. A
// server caps input size and pins certificates where it can; docs/security.md
// has the measurements.
//
// # Deliberate refusals
//
//   - Producing any weak algorithm: SHA-1, DSA, HMAC-SHA1, rsa-oaep-mgf1p,
//     rsa-1_5, AES-CBC, 3DES. The specifications require them, so they are
//     verified or decrypted, but only when a caller names each one; they are
//     never in a default allow-list.
//   - The XSLT, XPath and XPath Filter 2.0 transforms, unless the caller
//     allows the exact stylesheet or expression: they would run
//     attacker-supplied code during verification of an unauthenticated
//     message. See dsig.VerifyOptions.AllowedXPathExpressions and
//     AllowedXSLTStylesheets.
//   - Trust decisions about certificates.
//   - Network or filesystem dereferencing of any URI. An external reference
//     is dereferenced only through a URIResolver the caller supplies, which
//     is then the caller's request forgery boundary.
package xmlsec
