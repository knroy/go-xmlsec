// Package xenc implements XML Encryption 1.1: RSA-OAEP key transport with
// an explicit MGF, AES key wrap, ECDH-ES key agreement with ConcatKDF, and
// AES-GCM data encryption of elements, element content and attachments,
// inline or by CipherReference.
//
// # Allow-lists
//
// Every Decrypt and Unwrap function takes allow-lists, checked before any
// cryptographic work. An empty list means the default set: every secure
// algorithm this package implements. A list can never enable an algorithm
// this package does not implement.
//
// # Legacy algorithms, decryption only
//
// The legacy algorithms XML Encryption 1.1 still requires are implemented
// for decryption only, for peers that cannot send anything better:
// xmlsec.EncAES128CBC, EncAES192CBC, EncAES256CBC and EncTripleDESCBC data,
// xmlsec.KeyTransportRSAOAEPMGF1P and RSA-OAEP with a SHA-1 digest or MGF,
// xmlsec.KeyTransportRSA15 through DecryptEncryptedKeyPKCS1v15, and
// xmlsec.KeyWrapTripleDES. None is in a default set, so an empty list
// refuses them all; each is accepted only when a caller names it. SHA-1 is
// named as xmlsec.DigestSHA1 and xmlsec.MGF1SHA1 whether the document names
// it or implies it by leaving out ds:DigestMethod or xenc11:MGF, since the
// algorithm used is the same. No Encrypt function and GenerateEncryptedKey
// ever produce one: they return xmlsec.ErrUnsupportedAlgorithm.
//
// CBC has no integrity: see DecryptData. Name CBC and GCM in one list only
// when one peer really sends both, since a key accepted under both lets an
// attacker take GCM ciphertext to the CBC padding oracle (section 6.1.3).
package xenc

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// Namespaces this package needs but does not export.
const (
	nsDSig11 = "http://www.w3.org/2009/xmldsig11#"
	nsWSSE   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	nsSOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"
	nsSOAP12 = "http://www.w3.org/2003/05/soap-envelope"
)

// Namespace and type URIs.
const (
	NSXEnc   = "http://www.w3.org/2001/04/xmlenc#"
	NSXEnc11 = "http://www.w3.org/2009/xmlenc11#"
	NSDSig   = "http://www.w3.org/2000/09/xmldsig#"

	// NSWSSE11 is the WS-Security 1.1 namespace of wsse11:EncryptedHeader.
	NSWSSE11 = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"

	TypeElement = "http://www.w3.org/2001/04/xmlenc#Element"
	TypeContent = "http://www.w3.org/2001/04/xmlenc#Content"

	// TypeEncryptedKey is the ds:RetrievalMethod Type of a reference to an
	// xenc:EncryptedKey (section 3.5.1).
	TypeEncryptedKey = "http://www.w3.org/2001/04/xmlenc#EncryptedKey"

	// TransformAttachmentCiphertext is the CipherReference transform the
	// SwA profile requires on every encrypted attachment.
	TransformAttachmentCiphertext = "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform"

	// DigestSHA384XMLEnc is XML Encryption's own SHA-384 identifier
	// (section 5.8.3). It is accepted on decryption as the OAEP and
	// ConcatKDF digest, alongside xmlsec.DigestSHA384, which is what this
	// package emits because xmlsec1 and Santuario recognise only that one.
	DigestSHA384XMLEnc = "http://www.w3.org/2001/04/xmlenc#sha384"
)

// EncryptOptions configures encryption.
type EncryptOptions struct {
	// DataAlgorithm is an Enc*GCM constant. Required. The CBC ones are
	// decryption-only and refused.
	DataAlgorithm string

	// KeyTransportAlgorithm selects how GenerateEncryptedKey protects the
	// session key: xmlsec.KeyTransportRSAOAEP for an RSA Recipient, or a
	// KeyWrap* constant, which wraps it under KeyEncryptionKey or, with an
	// EC Recipient, under a key agreed by KeyAgreementAlgorithm.
	KeyTransportAlgorithm string

	// MGFAlgorithm is MGF1SHA256, 384 or 512, required for RSA-OAEP. It is
	// emitted as an explicit xenc11:MGF element: omitting it means SHA-1
	// MGF by specification default.
	MGFAlgorithm string

	// DigestAlgorithm is a SHA-2 Digest* constant: the OAEP digest for
	// RSA-OAEP, the ConcatKDF digest for key agreement. Required for both.
	DigestAlgorithm string

	// OAEPParams is the optional OAEP label. Normally empty.
	OAEPParams []byte

	// Recipient is the certificate whose public key protects the session
	// key: RSA for RSA-OAEP, EC on P-256, P-384 or P-521 for ECDH-ES.
	Recipient *x509.Certificate

	// KeyAgreementAlgorithm is xmlsec.KeyAgreementECDHES, required when
	// Recipient holds an EC key. The KEK is derived with ConcatKDF.
	KeyAgreementAlgorithm string

	// KeyEncryptionKey is a shared AES key wrapping the session key under
	// a KeyWrap* algorithm of its size, when there is no Recipient. The
	// EncryptedKey then names no key; identify it with SetKeyInfo, such as
	// a ds:KeyName.
	KeyEncryptionKey []byte

	// CarriedKeyName, if set, is emitted as the EncryptedKey's
	// xenc:CarriedKeyName, which a ds:KeyName elsewhere can refer to
	// (sections 3.5 and 3.5.1). Whitespace is significant.
	CarriedKeyName string

	// RecipientHint, if set, becomes the EncryptedKey's Recipient
	// attribute: an application-defined hint naming whom the key is for.
	RecipientHint string

	// SessionKey, if non-nil, is used instead of a freshly generated key.
	// For tests only. Never set in production.
	SessionKey []byte

	// DataID, if set, becomes the Id of the xenc:EncryptedData produced,
	// for an EncryptedKey.AddDataReference to point at. It must be an
	// NCName.
	DataID string
}

// keySizes maps each data algorithm to its AES key length.
var keySizes = map[string]int{
	xmlsec.EncAES128GCM: 16,
	xmlsec.EncAES192GCM: 24,
	xmlsec.EncAES256GCM: 32,
}

// wrapSizes maps each key wrap algorithm to its KEK length.
var wrapSizes = map[string]int{
	xmlsec.KeyWrapAES128: 16,
	xmlsec.KeyWrapAES192: 24,
	xmlsec.KeyWrapAES256: 32,
}

// The default allow-lists, used when a caller passes an empty one.
var (
	defaultData         = []string{xmlsec.EncAES128GCM, xmlsec.EncAES192GCM, xmlsec.EncAES256GCM}
	defaultKeyTransport = []string{xmlsec.KeyTransportRSAOAEP}
	defaultKeyWrap      = []string{xmlsec.KeyWrapAES128, xmlsec.KeyWrapAES192, xmlsec.KeyWrapAES256}
	defaultAgreement    = []string{xmlsec.KeyAgreementECDHES}
	defaultMGF          = []string{xmlsec.MGF1SHA256, xmlsec.MGF1SHA384, xmlsec.MGF1SHA512}
	defaultDigest       = []string{xmlsec.DigestSHA256, xmlsec.DigestSHA384, DigestSHA384XMLEnc, xmlsec.DigestSHA512}
)

// ErrNotNFC is returned when an element or element content to be encrypted
// is not in Unicode Normalization Form C, which XML Encryption 1.1 section
// 4.3 requires of the plaintext. It is refused rather than normalized:
// normalizing would change content that may already be signed.
var ErrNotNFC = errors.New("xenc: plaintext is not in Unicode Normalization Form C")

var errDecrypt = errors.New("xenc: decryption failed")

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{xmlsec.ErrMalformed}, args...)...)
}

func unsupported(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{xmlsec.ErrUnsupportedAlgorithm}, args...)...)
}

// allowed checks v against list, or against defaults when list is empty.
func allowed(kind, v string, list, defaults []string) error {
	if len(list) == 0 {
		list = defaults
	}
	if slices.Contains(list, v) {
		return nil
	}
	return fmt.Errorf("%w: %s algorithm %q", xmlsec.ErrAlgorithmNotAllowed, kind, v)
}

// digest returns the hash of an allowed digest algorithm URI.
func digest(kind, v string, list []string) (crypto.Hash, error) {
	if err := allowed(kind, v, list, defaultDigest); err != nil {
		return 0, err
	}
	switch v {
	case DigestSHA384XMLEnc:
		return crypto.SHA384, nil
	case xmlsec.DigestSHA1:
		// Allowed only by name: never in defaultDigest.
		return crypto.SHA1, nil
	}
	h, ok := xmlsec.DigestHash(v)
	if !ok {
		return 0, unsupported("%s %q", kind, v)
	}
	return h, nil
}

func element(parent *xdm.Node, local string) *xdm.Node {
	return xmltree.Element(parent, "xenc", NSXEnc, local)
}

// nsElement creates an element in another namespace, declaring its prefix
// on it.
func nsElement(parent *xdm.Node, prefix, uri, local string) *xdm.Node {
	e := xmltree.Element(parent, prefix, uri, local)
	e.AddNamespace(prefix, uri)
	return e
}

// newRoot creates a detached xenc root element with its namespace declared.
func newRoot(local string) *xdm.Node {
	return nsElement(nil, "xenc", NSXEnc, local)
}

func encryptionMethod(parent *xdm.Node, alg string) *xdm.Node {
	m := element(parent, "EncryptionMethod")
	xmltree.SetAttr(m, "", "", "Algorithm", alg)
	return m
}

// newEncryptedData starts an xenc:EncryptedData of the given Type, with
// opts.DataID and an EncryptionMethod naming opts.DataAlgorithm.
func newEncryptedData(typ string, opts EncryptOptions) (*xdm.Node, error) {
	ed := newRoot("EncryptedData")
	if opts.DataID != "" {
		if !xdm.IsNCName(opts.DataID) {
			return nil, fmt.Errorf("xenc: DataID %q is not an NCName", opts.DataID)
		}
		xmltree.SetAttr(ed, "", "", "Id", opts.DataID)
	}
	xmltree.SetAttr(ed, "", "", "Type", typ)
	encryptionMethod(ed, opts.DataAlgorithm)
	return ed, nil
}

// parseEncryptionMethod returns the Algorithm of el's xenc:EncryptionMethod,
// which must be its first element child, and the method element itself.
func parseEncryptionMethod(el *xdm.Node) (string, *xdm.Node, error) {
	kids := el.ChildElements()
	if len(kids) == 0 || !kids[0].IsElement(NSXEnc, "EncryptionMethod") {
		return "", nil, malformed("%s without xenc:EncryptionMethod", el.Name.Local)
	}
	return kids[0].AttrValue("Algorithm"), kids[0], nil
}

// methodParams returns the children of an xenc:EncryptionMethod by local
// name. Section 3.2: a child the algorithm does not permit, or a KeySize
// (always permitted) inconsistent with the algorithm's bits, is an error.
// Each child may appear once.
func methodParams(m *xdm.Node, bits int, permitted ...xdm.QName) (map[string]*xdm.Node, error) {
	seen := map[string]*xdm.Node{}
	for _, k := range m.ChildElements() {
		switch {
		case k.IsElement(NSXEnc, "KeySize"):
			// xs:integer collapses whitespace.
			if n, err := strconv.Atoi(strings.TrimSpace(k.StringValue())); err != nil || n != bits {
				return nil, malformed("xenc:KeySize %q inconsistent with %s, which needs %d", k.StringValue(), m.AttrValue("Algorithm"), bits)
			}
		case !slices.ContainsFunc(permitted, func(q xdm.QName) bool { return k.IsElement(q.URI, q.Local) }):
			return nil, malformed("%s not permitted in xenc:EncryptionMethod of %s", k.Name.Local, m.AttrValue("Algorithm"))
		}
		if seen[k.Name.Local] != nil {
			return nil, malformed("%s twice in xenc:EncryptionMethod", k.Name.Local)
		}
		seen[k.Name.Local] = k
	}
	return seen, nil
}

// cipherData returns el's xenc:CipherData child.
func cipherData(el *xdm.Node) (*xdm.Node, error) {
	for _, k := range el.ChildElements() {
		if k.IsElement(NSXEnc, "CipherData") {
			return k, nil
		}
	}
	return nil, malformed("%s without xenc:CipherData", el.Name.Local)
}

// cipherValue decodes the xenc:CipherData/xenc:CipherValue of el.
func cipherValue(el *xdm.Node) ([]byte, error) {
	cd, err := cipherData(el)
	if err != nil {
		return nil, err
	}
	kids := cd.ChildElements()
	if len(kids) != 1 || !kids[0].IsElement(NSXEnc, "CipherValue") {
		return nil, malformed("xenc:CipherData must hold one xenc:CipherValue")
	}
	b, err := xmltree.Base64(kids[0])
	if err != nil {
		return nil, malformed("xenc:CipherValue: %v", err)
	}
	return b, nil
}
