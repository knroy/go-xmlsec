// Package dsig implements XML Signature generation and verification.
package dsig

import (
	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
)

// Namespace URIs.
const (
	NSDSig    = "http://www.w3.org/2000/09/xmldsig#"
	NSExcC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
)

// Common ID attributes for SignOptions.IDAttributes and
// VerifyOptions.IDAttributes. Neither counts unless named there: each one
// added widens what an attacker can use to duplicate an ID.
var (
	// IDAttrSAML is the unqualified ID attribute of SAML 2.0, as on
	// saml:Assertion and samlp:Response.
	IDAttrSAML = xdm.QName{Local: "ID"}

	// IDAttrDSig is the unqualified Id attribute that the XML Signature
	// schema gives its own elements, and that XAdES and many other XML
	// Signature profiles use on theirs.
	IDAttrDSig = xdm.QName{Local: "Id"}
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
	//   "#id"         a same-document element by wsu:Id or xml:id, or an
	//                 attribute named in SignOptions.IDAttributes
	//   "#xpointer(/)", "#xpointer(id('id'))"
	//                 as "" and "#id", but comments are kept, so a
	//                 #WithComments canonicalization covers them (XML-DSig
	//                 4.4.3.3); any other XPointer is refused
	//   "cid:..."     a MIME attachment, requiring an AttachmentSet; the
	//                 first transform must be an SwA signature transform
	URI string

	// ID, if set, becomes the Id attribute of the ds:Reference element. It
	// must be an NCName.
	ID string

	// Type, if set, becomes the Type attribute. It must be a URI.
	Type string

	// Transforms are applied in order. The final transform's output must be
	// an octet stream: for same-document references the last transform is
	// a canonicalization or base64; for cid: references the first is an SwA
	// signature transform. Octets followed by a canonicalization are parsed
	// with xmlsec.Parse (XML-DSig 4.4.3.2); base64 of a node set decodes its
	// text (XML-DSig 6.6.2).
	// (Verify also accepts a received reference that ends in a node set,
	// completing it with Canonical XML 1.0 as XML-DSig 4.4.3.2 requires;
	// Sign never produces one.)
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

	// KeyInfoKeyValue emits the raw public key as ds:KeyValue: a
	// ds:RSAKeyValue, or a dsig11:ECKeyValue naming P-256, P-384 or P-521.
	// No certificate travels, so the verifier must already trust the key.
	// Sign takes the key from KeyProvider.Certificate, which it still
	// requires, and refuses a key Verify would refuse: RSA under 2048 bits,
	// or another curve.
	KeyInfoKeyValue

	// KeyInfoDEREncodedKeyValue emits the raw public key as
	// dsig11:DEREncodedKeyValue, the base64 of its DER SubjectPublicKeyInfo.
	// As with KeyInfoKeyValue, the key is RSA or ECDSA on P-256, P-384 or
	// P-521.
	KeyInfoDEREncodedKeyValue
)

func isC14N(alg string) bool { return c14n.Algorithm(alg).Valid() }

// withoutComments maps each #WithComments canonicalization to its plain form.
var withoutComments = map[c14n.Algorithm]c14n.Algorithm{
	c14n.Inclusive10WithComments: c14n.Inclusive10,
	c14n.Exclusive10WithComments: c14n.Exclusive10,
	c14n.Inclusive11WithComments: c14n.Inclusive11,
}

// ecdsaAlgorithms are the Sig* constants that take an ECDSA key. The others
// take RSA.
var ecdsaAlgorithms = map[string]bool{
	xmlsec.SigECDSASHA256: true,
	xmlsec.SigECDSASHA384: true,
	xmlsec.SigECDSASHA512: true,
}
