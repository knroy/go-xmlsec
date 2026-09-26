// Package dsig implements XML Signature generation and verification.
package dsig

import "github.com/knroy/go-xml/c14n"

// Namespace URIs.
const (
	NSDSig    = "http://www.w3.org/2000/09/xmldsig#"
	NSExcC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
)

// Resource limits.
const (
	DefaultMaxReferences      = 64
	MaxTransformsPerReference = 8
)

// Reference describes one ds:Reference to be signed.
type Reference struct {
	// URI is the reference target. Supported forms:
	//   ""            the whole document (only valid with an enveloped transform)
	//   "#id"         a same-document element by wsu:Id or xml:id
	//   "cid:..."     a MIME attachment, requiring an AttachmentSet
	URI string

	// ID, if set, becomes the Id attribute of the ds:Reference element.
	ID string

	// Type, if set, becomes the Type attribute.
	Type string

	// Transforms are applied in order. The final transform's output must be
	// an octet stream: for same-document references the last transform is
	// a canonicalization; for cid: references it is an SwA transform.
	Transforms []TransformSpec

	// DigestAlgorithm is a Digest* constant. Required.
	DigestAlgorithm string
}

// TransformSpec names a transform and carries its parameters.
type TransformSpec struct {
	Algorithm string

	// InclusiveNamespacePrefixes populates the InclusiveNamespaces
	// PrefixList child of an exclusive canonicalization transform, with ""
	// for the default namespace. Ignored for other algorithms.
	InclusiveNamespacePrefixes []string
}

// KeyInfoSpec selects the ds:KeyInfo form.
type KeyInfoSpec int

const (
	// KeyInfoNone emits no ds:KeyInfo. The verifier must already know the key.
	KeyInfoNone KeyInfoSpec = iota

	// KeyInfoX509Data emits ds:X509Data/ds:X509Certificate with the
	// base64 DER of the signing certificate.
	KeyInfoX509Data

	// KeyInfoSecurityTokenReference emits a wsse:SecurityTokenReference
	// pointing at a wsse:BinarySecurityToken that the caller has placed in
	// the wsse:Security header.
	KeyInfoSecurityTokenReference
)

func isC14N(alg string) bool { return c14n.Algorithm(alg).Valid() }
