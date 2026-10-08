// Package xenc implements XML Encryption 1.1: RSA-OAEP key transport with
// an explicit MGF, AES key wrap, ECDH-ES key agreement with ConcatKDF, and
// AES-GCM data encryption of elements, element content, attachments and
// arbitrary octets, inline or by CipherReference, and decryption in place.
//
// # Optional key agreement and derivation
//
// Three OPTIONAL algorithms of section 5 are implemented, and none is in a
// default allow-list: finite-field Diffie-Hellman, xmlsec.KeyAgreementDHES
// with an explicit KDF and xmlsec.KeyAgreementDH with the Legacy KDF
// (DecryptAgreedKeyDH, EncryptOptions.RecipientDH, DHPublicKey), in groups
// of MinDHBits to MaxDHBits with a checked subgroup; and
// xmlsec.KeyDerivationPBKDF2, from a password (UnwrapEncryptedKeyPassword,
// EncryptOptions.Password) or as the KDF of a key agreement, with an
// iteration count from MinPBKDF2Iterations to MaxPBKDF2Iterations. Each is
// accepted only when a caller names it, and PBKDF2's legacy HMAC-SHA1 PRF
// only when named in DecryptOptions.AllowedPRFAlgorithms.
//
// # Key information
//
// FindEncryptedKey and FindDerivedKey find the key of an EncryptedData or
// an EncryptedKey the ways section 3.5 provides: a child of its
// ds:KeyInfo, a same-document ds:RetrievalMethod, a ds:KeyName, or the
// xenc:ReferenceList naming it. Each takes one hop. An EncryptedKey's
// KEK may itself be an EncryptedKey (EncryptedKey.AddKeyReference names
// it); an xenc11:DerivedKey is derived from a shared master key by
// DeriveKey (EncryptOptions.MasterKey on encryption); an
// xenc:AgreementMethod directly under an EncryptedData is read by
// DecryptAgreedDataKey and DecryptAgreedDataKeyDH
// (EncryptOptions.DirectKeyAgreement). An EncryptedKey may carry its
// ciphertext by xenc:CipherReference, resolved as an EncryptedData's. An
// element without xenc:EncryptionMethod is decrypted only under an
// algorithm the DecryptOptions Implied fields name.
//
// # Allow-lists
//
// Every Decrypt and Unwrap function takes a DecryptOptions whose allow-lists
// are checked before any cryptographic work. An empty list means the
// default set of its role, which DecryptOptions lists: the recommended
// algorithms. The OPTIONAL ones (finite-field Diffie-Hellman, PBKDF2,
// MGF1 with SHA-224, HMAC-SHA1 as the PBKDF2 PRF) and the legacy ones
// below are in no default set, and are accepted only when named. A list
// can never enable an algorithm this package does not implement.
//
// Every failure of the decryption itself, whatever its cause, wraps
// xmlsec.ErrDecryptionFailed with a fixed message, so that a receiver is
// no oracle; DecryptOptions.StrictBSP adds the WS-I Basic Security
// Profile's structural checks, also before any cryptographic work.
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
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/hashes"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// Type URIs.
const (
	TypeElement = "http://www.w3.org/2001/04/xmlenc#Element"
	TypeContent = "http://www.w3.org/2001/04/xmlenc#Content"

	// TypeEncryptedKey is the ds:RetrievalMethod Type of a reference to an
	// xenc:EncryptedKey (section 3.5.1).
	TypeEncryptedKey = "http://www.w3.org/2001/04/xmlenc#EncryptedKey"

	// TypeDerivedKey is the ds:RetrievalMethod Type of a reference to an
	// xenc11:DerivedKey (section 3.5.2). Section 3.5.3 names
	// "http://www.w3.org/2009/xmlenc11#DerivedKey" instead, which
	// FindDerivedKey accepts as well.
	TypeDerivedKey = "http://www.w3.org/2001/04/xmlenc#DerivedKey"
)

// typeDerivedKey11 is the RetrievalMethod Type of a DerivedKey that section
// 3.5.3 gives, contradicting section 3.5.2.
const typeDerivedKey11 = "http://www.w3.org/2009/xmlenc11#DerivedKey"

// EncryptOptions configures encryption.
//
// One EncryptOptions may serve GenerateEncryptedKey and the Encrypt
// functions alike, but an option that has no effect on what is produced,
// or contradicts another, is refused rather than silently ignored: each
// field says when. GenerateEncryptedKey refuses, before any cryptographic
// work, more than one of Recipient, RecipientDH, KeyEncryptionKey and
// Password; MGFAlgorithm and OAEPParams except for RSA-OAEP;
// KeyEncryptionKey, Password and RecipientDH with RSA-OAEP;
// DigestAlgorithm and KeyAgreementAlgorithm under a KeyEncryptionKey or
// Password, which use no digest and agree no key; RecipientKeyName
// without RecipientDH; and MasterKey and DirectKeyAgreement, which make no
// EncryptedKey. GenerateEncryptedKey and every Encrypt function refuse
// PBKDF2Iterations set without Password, or outside MinPBKDF2Iterations to
// MaxPBKDF2Iterations. The fields of the EncryptedData alone, such as
// DataID, MimeType or EncryptionProperties, are ignored by
// GenerateEncryptedKey, so that the same options can make both.
type EncryptOptions struct {
	// DataAlgorithm is an Enc*GCM constant. Required. The CBC ones are
	// decryption-only and refused.
	DataAlgorithm string

	// KeyTransportAlgorithm selects how GenerateEncryptedKey protects the
	// session key: xmlsec.KeyTransportRSAOAEP for an RSA Recipient, or a
	// KeyWrap* constant, which wraps it under KeyEncryptionKey or, with an
	// EC Recipient, under a key agreed by KeyAgreementAlgorithm.
	KeyTransportAlgorithm string

	// MGFAlgorithm is MGF1SHA256, 384 or 512, required for RSA-OAEP and
	// refused with any other KeyTransportAlgorithm. It is emitted as an
	// explicit xenc11:MGF element: omitting it means SHA-1 MGF by
	// specification default.
	MGFAlgorithm string

	// DigestAlgorithm is a SHA-2 Digest* constant, or
	// xmlsec.DigestSHA384XMLEnc (section 5.8.3): the OAEP digest for
	// RSA-OAEP, the ConcatKDF digest for key agreement and MasterKey, the
	// Legacy KDF digest for xmlsec.KeyAgreementDH. Required for each, and
	// emitted as given. GenerateEncryptedKey refuses it under a
	// KeyEncryptionKey or Password, which use no digest.
	DigestAlgorithm string

	// OAEPParams is the optional OAEP label. Normally empty; refused with
	// any KeyTransportAlgorithm but RSA-OAEP.
	OAEPParams []byte

	// Recipient is the certificate whose public key protects the session
	// key: RSA for RSA-OAEP, EC on P-256, P-384 or P-521 for ECDH-ES.
	Recipient *x509.Certificate

	// KeyAgreementAlgorithm is xmlsec.KeyAgreementECDHES, required when
	// Recipient holds an EC key. The KEK is derived with ConcatKDF. With
	// RecipientDH it is xmlsec.KeyAgreementDHES or KeyAgreementDH.
	// GenerateEncryptedKey refuses it without either, or with RSA-OAEP.
	KeyAgreementAlgorithm string

	// KeyEncryptionKey is a shared AES key wrapping the session key under
	// a KeyWrap* algorithm of its size, when there is no Recipient. The
	// EncryptedKey then names no key; identify it with SetKeyInfo, such as
	// a ds:KeyName. Refused with RSA-OAEP, and beside Recipient,
	// RecipientDH or Password.
	KeyEncryptionKey []byte

	// CarriedKeyName, if set, is emitted as the EncryptedKey's
	// xenc:CarriedKeyName, which a ds:KeyName elsewhere can refer to
	// (sections 3.5 and 3.5.1). Whitespace is significant.
	CarriedKeyName string

	// RecipientHint, if set, becomes the EncryptedKey's Recipient
	// attribute: an application-defined hint naming whom the key is for.
	// The WS-I Basic Security Profile forbids it in WS-Security (R5602): a
	// SOAP header's actor or role names the recipient there.
	RecipientHint string

	// SessionKey, if non-nil, is the key GenerateEncryptedKey wraps instead
	// of a fresh random one; it must be DataAlgorithm's size. Set it to an
	// earlier EncryptedKey's SessionKey to wrap one key for several
	// recipients (XML Encryption 1.1 section 3.5.1). Never set it to
	// anything but a key from crypto/rand.
	SessionKey []byte

	// DataID, if set, becomes the Id of the xenc:EncryptedData produced,
	// for an EncryptedKey.AddDataReference to point at. It must be an
	// NCName.
	DataID string

	// RecipientDH is the recipient's finite-field Diffie-Hellman key, for
	// a KeyWrap* algorithm under a key agreed by KeyAgreementAlgorithm
	// xmlsec.KeyAgreementDHES (ConcatKDF) or xmlsec.KeyAgreementDH (the
	// Legacy KDF), with DigestAlgorithm, when there is no Recipient.
	// Refused with RSA-OAEP.
	RecipientDH *DHPublicKey

	// RecipientKeyName, if set, names the RecipientDH key in the
	// RecipientKeyInfo as a ds:KeyName, instead of its public value in an
	// xenc:DHKeyValue. xmlsec1 finds a recipient's DH key only by name.
	// GenerateEncryptedKey refuses it without RecipientDH.
	RecipientKeyName string

	// Password, when set and there is no other key, derives the KEK of a
	// KeyWrap* algorithm by PBKDF2 with HMAC-SHA256, a fresh 16-octet salt
	// and PBKDF2Iterations. Given to an Encrypt function with no session
	// key, it derives the data key the same way, named by an
	// xenc11:DerivedKey in the EncryptedData's ds:KeyInfo. Refused with
	// RSA-OAEP.
	Password []byte

	// PBKDF2Iterations is the PBKDF2 iteration count for Password, from
	// MinPBKDF2Iterations to MaxPBKDF2Iterations. Zero means
	// DefaultPBKDF2Iterations. Any other value without Password, or
	// outside that range, is refused by GenerateEncryptedKey and every
	// Encrypt function.
	PBKDF2Iterations int

	// Type, if set, is the Type attribute of the xenc:EncryptedData that
	// EncryptOctets produces: a URI telling the recipient what the octets
	// are (section 3.1). The other Encrypt functions set Type themselves
	// and refuse any other value.
	Type string

	// MimeType, if set, is the EncryptedData MimeType attribute, such as
	// "image/png" or, for an element, "text/xml" (section 3.1). It is
	// advisory: nothing checks it. EncryptAttachment refuses it, since it
	// takes MimeType from the attachment's Content-Type.
	MimeType string

	// Encoding, if set, is the EncryptedData Encoding attribute, a URI such
	// as xmlsec.TransformBase64 naming the transfer encoding of the
	// plaintext (section 3.1). It is advisory: nothing is encoded.
	Encoding string

	// EncryptionProperties, if any, are copied into an
	// xenc:EncryptionProperties after the EncryptedData's CipherData
	// (section 3.7): additional information about its generation, such as
	// a date. Each must be an xenc:EncryptionProperty element. It is copied
	// in inclusive canonical form, so it keeps the namespaces in scope
	// where it stands; the node itself is never modified. Only
	// EncryptedData carries them: GenerateEncryptedKey ignores this field.
	EncryptionProperties []*xdm.Node

	// CipherReferenceURI, if set, makes EncryptOctets emit an
	// xenc:CipherReference to this URI in place of an inline CipherValue,
	// and return the ciphertext for the caller to store there, as raw
	// octets (section 3.3.1). It must not be a same-document reference.
	// The other Encrypt functions refuse it.
	CipherReferenceURI string

	// MasterKey, when set and the Encrypt function is given no session
	// key, derives the data key from it by ConcatKDF with DigestAlgorithm
	// (section 5.4.1), and puts the xenc11:DerivedKey naming the derivation
	// in the EncryptedData's ds:KeyInfo (section 3.5.2). A fresh 16-octet
	// PartyUInfo makes each derived key new. It must be at least as long as
	// the data key. A receiver sharing it calls FindDerivedKey and
	// DeriveKey. GenerateEncryptedKey refuses it: it makes no
	// EncryptedKey.
	MasterKey []byte

	// DerivedKeyName and MasterKeyName, if set, are emitted as the
	// xenc11:DerivedKeyName and xenc11:MasterKeyName of the DerivedKey
	// MasterKey produces.
	DerivedKeyName, MasterKeyName string

	// DirectKeyAgreement, when the Encrypt function is given no session
	// key, agrees the data key itself with Recipient (ECDH-ES) or
	// RecipientDH, by KeyAgreementAlgorithm and DigestAlgorithm, and puts
	// the xenc:AgreementMethod in the EncryptedData's ds:KeyInfo, with no
	// EncryptedKey (section 5.6). A receiver calls DecryptAgreedDataKey or
	// DecryptAgreedDataKeyDH. GenerateEncryptedKey refuses it: it makes no
	// EncryptedKey.
	DirectKeyAgreement bool

	// DataKeyInfo, if set, is placed in a ds:KeyInfo of each
	// xenc:EncryptedData produced, after its EncryptionMethod, to name the
	// key that decrypts it. It is the ds:KeyInfo's one child, not the
	// ds:KeyInfo itself: a detached element such as a
	// wsse:SecurityTokenReference with a wsse:Reference to the
	// xenc:EncryptedKey's Id, as WS-Security's symmetric binding writes it
	// (SOAP Message Security 1.1.1 sections 7.7 and 9.4.1). The Basic
	// Security Profile requires one on every EncryptedData that no
	// EncryptedKey's ReferenceList names (R5629), holding exactly one
	// SecurityTokenReference (R5424, R5426). It is copied, so the same
	// options can encrypt several parts. It cannot be combined with a key
	// the EncryptedData's own ds:KeyInfo conveys (MasterKey,
	// DirectKeyAgreement, or Password with no session key): that is
	// refused, since one ds:KeyInfo naming the key two ways is ambiguous
	// and BSP allows only the reference.
	DataKeyInfo *xdm.Node
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

// DecryptOptions restricts the algorithms the Decrypt and Unwrap functions
// accept. Every list is checked before any cryptographic work. An empty list
// means the default set each field documents: the recommended algorithms
// of that role, which leave out the OPTIONAL finite-field Diffie-Hellman,
// PBKDF2, MGF1 with SHA-224 and HMAC-SHA1 PRF. A list can never enable an
// algorithm this package does not implement, and an OPTIONAL or legacy
// algorithm (see the package documentation) is accepted only when named. Each function reads only the lists that apply
// to it.
type DecryptOptions struct {
	// AllowedDataAlgorithms restricts the EncryptedData EncryptionMethod.
	// Default: the xmlsec.Enc*GCM constants.
	AllowedDataAlgorithms []string

	// AllowedKeyTransportAlgorithms restricts the EncryptionMethod of an
	// RSA EncryptedKey. Default: xmlsec.KeyTransportRSAOAEP.
	AllowedKeyTransportAlgorithms []string

	// AllowedMGFAlgorithms restricts the RSA-OAEP mask generation function.
	// Default: the xmlsec.MGF1SHA256, 384 and 512 constants.
	// xmlsec.MGF1SHA224 is accepted only when named.
	AllowedMGFAlgorithms []string

	// AllowedDigestAlgorithms restricts the RSA-OAEP and ConcatKDF digest.
	// Default: xmlsec.DigestSHA256, DigestSHA384, DigestSHA384XMLEnc and
	// DigestSHA512.
	AllowedDigestAlgorithms []string

	// AllowedKeyWrapAlgorithms restricts the EncryptionMethod of a wrapped
	// or agreed EncryptedKey. Default: the xmlsec.KeyWrapAES* constants.
	AllowedKeyWrapAlgorithms []string

	// AllowedKeyAgreementAlgorithms restricts the xenc:AgreementMethod.
	// Default: xmlsec.KeyAgreementECDHES. The finite-field
	// xmlsec.KeyAgreementDHES and KeyAgreementDH are accepted only when
	// named.
	AllowedKeyAgreementAlgorithms []string

	// ResolveURI supplies the octets of an xenc:CipherReference to an
	// absolute URI other than cid:, such as "http://example.com/ct.bin",
	// for DecryptData, and of an EncryptedKey's CipherReference for the
	// functions unwrapping it. It is called only after the algorithms and
	// the CipherReference transforms are accepted, before any decryption.
	// This library never fetches anything itself; see xmlsec.URIResolver. An error it returns is
	// wrapped with xmlsec.ErrDereference. When nil, such a CipherReference
	// is refused, and so is a relative one; with ResolveURI set, a relative
	// URI is resolved against BaseURI, and refused without one.
	ResolveURI xmlsec.URIResolver

	// AllowedKeyDerivationAlgorithms restricts the
	// xenc11:KeyDerivationMethod. Default: xmlsec.KeyDerivationConcatKDF.
	// xmlsec.KeyDerivationPBKDF2 is accepted only when named.
	AllowedKeyDerivationAlgorithms []string

	// AllowedPRFAlgorithms restricts the PBKDF2 PRF. Default:
	// xmlsec.SigHMACSHA256, 384 and 512. The legacy xmlsec.SigHMACSHA1,
	// the PKCS #5 default, is accepted only when named.
	AllowedPRFAlgorithms []string

	// BaseURI is the absolute URI a relative xenc:CipherReference URI,
	// such as "ct/1.bin", is resolved against (RFC 3986 section 5) before
	// ResolveURI is called with the result, as XML Signature resolves a
	// relative ds:Reference URI (section 3.3.1). It is never taken from
	// the document: xml:base is ignored. Empty, a relative URI is refused.
	// A same-document reference, "" or "#id", is never resolved against it.
	BaseURI string

	// AllowedXPathExpressions opts in to an XPath transform
	// (xmlsec.TransformXPath) on an xenc:CipherReference, followed by the
	// base64 transform (section 3.3.1, Example 13), for exactly the
	// expressions listed. The matching is dsig.VerifyOptions'
	// AllowedXPathExpressions': a received expression is accepted when,
	// with surrounding whitespace trimmed, it equals an entry's Expr and
	// each prefix in the entry's Namespaces is bound to the same URI where
	// it stands, and it is then compiled from the entry, with the entry's
	// bindings. Empty, the default, refuses the XPath transform with
	// xmlsec.ErrTransformRefused, as it does any expression not listed,
	// before ResolveURI is called and before any cryptographic work. XSLT
	// and XPath Filter 2.0 on a CipherReference stay refused.
	AllowedXPathExpressions []dsig.XPathExpression

	// ImpliedDataAlgorithm, ImpliedKeyWrapAlgorithm and
	// ImpliedKeyTransportAlgorithm name the algorithm of an EncryptedData,
	// a wrapped or agreed EncryptedKey and an RSA EncryptedKey that has no
	// xenc:EncryptionMethod, which sections 3.1 and 3.2 leave to be known
	// by the recipient. Each is used only when the element has none, and
	// passes the same allow-list an explicit one would. Empty, a missing
	// EncryptionMethod is xmlsec.ErrMalformed.
	ImpliedDataAlgorithm, ImpliedKeyWrapAlgorithm, ImpliedKeyTransportAlgorithm string

	// ImpliedKeyDerivationMethod is the xenc11:KeyDerivationMethod, with
	// its parameters, of an xenc11:DerivedKey that has none, which section
	// 3.5.2 leaves to be known by the recipient, for DeriveKey and
	// UnwrapEncryptedKeyPassword. It is an element rather than an
	// algorithm URI because every key derivation algorithm takes
	// parameters: ConcatKDF its ds:DigestMethod, PBKDF2 its salt and
	// iteration count. It is used only when the DerivedKey has none, and
	// passes the same allow-lists and checks an explicit one would. Nil, a
	// missing KeyDerivationMethod is xmlsec.ErrMalformed.
	ImpliedKeyDerivationMethod *xdm.Node

	// StrictBSP enforces the WS-I Basic Security Profile 1.1 rules on the
	// shape of what is decrypted, before any cryptographic work, refusing
	// with xmlsec.ErrMalformed:
	//
	//   - an xenc:EncryptedKey with a Type, MimeType, Encoding or Recipient
	//     attribute (R3209, R5622, R5623, R5602);
	//   - a ds:KeyInfo of an EncryptedKey or EncryptedData that does not
	//     hold exactly one wsse:SecurityTokenReference (R5424, R5426), which
	//     refuses key agreement and PBKDF2, whose ds:KeyInfo holds an
	//     xenc:AgreementMethod or xenc11:DerivedKey;
	//   - an xenc:EncryptedData that is a child of a SOAP Header (R3228), or
	//     that has no ds:KeyInfo and is not named by the ReferenceList of
	//     exactly one EncryptedKey in its document (R5629).
	//
	// Every Decrypt, Unwrap and Derive function applies them to the element
	// it is given: the EncryptedKey rules to an EncryptedKey (DeriveKey's
	// target included), the EncryptedData rules to an EncryptedData
	// (DecryptData, DecryptAttachment, DecryptAgreedDataKey,
	// DecryptAgreedDataKeyDH, DeriveKey's target, and through DecryptData,
	// DecryptAndReplace and DecryptHeader). So under StrictBSP a key agreed
	// or derived directly for an EncryptedData is refused as well.
	//
	// An EncryptionMethod on both (R5601, R5603) is required always, unless
	// an Implied*Algorithm supplies it. The
	// profile's algorithm lists (R5620, R5621, R5625, R5626), which name
	// only CBC, 3DES, RSA v1.5 and rsa-oaep-mgf1p, are not enforced: the
	// allow-lists decide algorithms, and those are decryption-only opt-ins.
	StrictBSP bool
}

// The default allow-lists, used when a caller passes an empty one.
var (
	defaultData         = []string{xmlsec.EncAES128GCM, xmlsec.EncAES192GCM, xmlsec.EncAES256GCM}
	defaultKeyTransport = []string{xmlsec.KeyTransportRSAOAEP}
	defaultKeyWrap      = []string{xmlsec.KeyWrapAES128, xmlsec.KeyWrapAES192, xmlsec.KeyWrapAES256}
	defaultAgreement    = []string{xmlsec.KeyAgreementECDHES}
	defaultDerivation   = []string{xmlsec.KeyDerivationConcatKDF}
	defaultPRF          = []string{xmlsec.SigHMACSHA256, xmlsec.SigHMACSHA384, xmlsec.SigHMACSHA512}
	defaultMGF          = []string{xmlsec.MGF1SHA256, xmlsec.MGF1SHA384, xmlsec.MGF1SHA512}
	defaultDigest       = []string{xmlsec.DigestSHA256, xmlsec.DigestSHA384, xmlsec.DigestSHA384XMLEnc, xmlsec.DigestSHA512}
)

// failure is a decryption failure: its message carries no detail, and it
// wraps xmlsec.ErrDecryptionFailed.
type failure string

func (f failure) Error() string { return string(f) }

func (failure) Unwrap() error { return xmlsec.ErrDecryptionFailed }

// errDecrypt is every data decryption failure, errUnwrap every key unwrap
// failure.
var (
	errDecrypt error = failure("xenc: decryption failed")
	errUnwrap  error = failure("xenc: key unwrap failed")
)

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
	if v == xmlsec.DigestSHA1 {
		// Allowed only by name: never in defaultDigest.
		return crypto.SHA1, nil
	}
	h, ok := encDigest(v)
	if !ok {
		return 0, unsupported("%s %q", kind, v)
	}
	return h, nil
}

// encDigest returns the hash of a secure RSA-OAEP or key derivation digest
// URI: a SHA-2 Digest* constant, or xmlsec.DigestSHA384XMLEnc, the SHA-384
// identifier section 5.8.3 gives.
func encDigest(uri string) (crypto.Hash, bool) {
	if uri == xmlsec.DigestSHA384XMLEnc {
		return crypto.SHA384, true
	}
	return hashes.Digest(uri)
}

func element(parent *xdm.Node, local string) *xdm.Node {
	return xmltree.Element(parent, "xenc", xmlsec.NSXEnc, local)
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
	return nsElement(nil, "xenc", xmlsec.NSXEnc, local)
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
	encryptionMethod(ed, opts.DataAlgorithm)
	if err := dataAttrs(ed, typ, opts); err != nil {
		return nil, err
	}
	if k := opts.DataKeyInfo; k != nil {
		if k.Kind != xdm.KindElement || k.Parent != nil || k.IsElement(xmlsec.NSDSig, "KeyInfo") {
			return nil, errors.New("xenc: DataKeyInfo must be a detached element to go inside ds:KeyInfo")
		}
		newKeyInfo(ed).AppendChild(xmltree.Clone(k))
	}
	return ed, nil
}

// parseEncryptionMethod returns the Algorithm of el's xenc:EncryptionMethod,
// which must be its first element child, and the method element itself.
// Without one, it returns implied and a nil method, or, when implied is
// empty, an error.
func parseEncryptionMethod(el *xdm.Node, implied string) (string, *xdm.Node, error) {
	kids := el.ChildElements()
	isMethod := func(k *xdm.Node) bool { return k.IsElement(xmlsec.NSXEnc, "EncryptionMethod") }
	switch {
	case len(kids) > 0 && isMethod(kids[0]):
		return kids[0].AttrValue("Algorithm"), kids[0], nil
	case implied == "" || slices.ContainsFunc(kids, isMethod):
		return "", nil, malformed("%s without xenc:EncryptionMethod first", el.Name.Local)
	}
	return implied, nil, nil
}

// keyInfo returns el's ds:KeyInfo, which follows its optional
// xenc:EncryptionMethod, or nil.
func keyInfo(el *xdm.Node) *xdm.Node {
	for i, k := range el.ChildElements() {
		if i < 2 && k.IsElement(xmlsec.NSDSig, "KeyInfo") {
			return k
		}
	}
	return nil
}

// methodParams returns the children of an xenc:EncryptionMethod by local
// name. Section 3.2: a child the algorithm does not permit, or a KeySize
// (always permitted) inconsistent with the algorithm's bits, is an error.
// Each child may appear once.
func methodParams(m *xdm.Node, bits int, permitted ...xdm.QName) (map[string]*xdm.Node, error) {
	seen := map[string]*xdm.Node{}
	if m == nil {
		// An implied algorithm, without parameters.
		return seen, nil
	}
	for _, k := range m.ChildElements() {
		switch {
		case k.IsElement(xmlsec.NSXEnc, "KeySize"):
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
		if k.IsElement(xmlsec.NSXEnc, "CipherData") {
			return k, nil
		}
	}
	return nil, malformed("%s without xenc:CipherData", el.Name.Local)
}

// cipherValue decodes the xenc:CipherValue of cd, an xenc:CipherData.
func cipherValue(cd *xdm.Node) ([]byte, error) {
	kids := cd.ChildElements()
	if len(kids) != 1 || !kids[0].IsElement(xmlsec.NSXEnc, "CipherValue") {
		return nil, malformed("xenc:CipherData must hold one xenc:CipherValue")
	}
	b, err := xmltree.Base64(kids[0])
	if err != nil {
		return nil, malformed("xenc:CipherValue: %v", err)
	}
	return b, nil
}
