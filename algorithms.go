package xmlsec

import "crypto"

// Signature algorithm URIs, for signing and verification.
const (
	SigRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	SigRSASHA384   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	SigRSASHA512   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	SigECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	SigECDSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	SigECDSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
)

// Digest algorithm URIs.
const (
	DigestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	DigestSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	DigestSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
)

// Legacy XML Signature 1.1 algorithms (section 6.1), implemented for
// VERIFICATION ONLY. Sign never produces them, SignatureHash and DigestHash
// do not return them, and no default set includes them: dsig.Verify accepts
// one only when the caller names it in the matching VerifyOptions allow-list.
const (
	// DigestSHA1 is SHA-1 (section 6.2.1), REQUIRED; "use is DISCOURAGED".
	DigestSHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"

	// SigRSASHA1 is RSA PKCS#1 v1.5 with SHA-1 (section 6.4.2), RECOMMENDED
	// for signature verification only.
	SigRSASHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"

	// SigDSASHA1 is DSA with SHA-1 (section 6.4.1), REQUIRED for signature
	// verification only, with (L, N) = (1024, 160) keys.
	SigDSASHA1 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1"

	// The HMAC MACs (section 6.3.1): SHA-1 and SHA-256 REQUIRED, SHA-384 and
	// SHA-512 RECOMMENDED. The key is only ever dsig.VerifyOptions.HMACKey,
	// never ds:KeyInfo.
	SigHMACSHA1   = "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
	SigHMACSHA256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
	SigHMACSHA384 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384"
	SigHMACSHA512 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"
)

// Transform URIs.
const (
	TransformEnvelopedSignature = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	TransformBase64             = "http://www.w3.org/2000/09/xmldsig#base64"

	// SwA signature transforms, OASIS wss-SwAProfile-v1.1.1 section 5.3:
	// the first transform of a cid: ds:Reference. Content-Signature
	// digests the attachment content canonicalized per section 5.4.2;
	// Complete-Signature prefixes it with the canonical MIME headers of
	// section 5.4.1.
	TransformAttachmentContentSignature  = "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform"
	TransformAttachmentCompleteSignature = "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Complete-Signature-Transform"

	// SwA xenc:EncryptedData Type URIs, section 5.5.2: the attachment
	// content alone, or the content with its MIME headers. They are not
	// signature transforms, and a ds:Transform naming either is refused:
	// sign attachments with TransformAttachmentContentSignature or
	// TransformAttachmentCompleteSignature.
	TransformAttachmentContentOnly = "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Only"
	TransformAttachmentComplete    = "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Complete"
)

// Transform URIs that are recognised only in order to be refused with
// ErrTransformRefused. See the package documentation.
const (
	TransformXSLT         = "http://www.w3.org/TR/1999/REC-xslt-19991116"
	TransformXPath        = "http://www.w3.org/TR/1999/REC-xpath-19991116"
	TransformXPathFilter2 = "http://www.w3.org/2002/06/xmldsig-filter2"
)

// Data encryption algorithm URIs.
const (
	EncAES128GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	EncAES192GCM = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
	EncAES256GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
)

// Key transport algorithm URIs. The legacy rsa-oaep-mgf1p and rsa-1_5 are
// with the decryption-only algorithms below.
const (
	KeyTransportRSAOAEP = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
)

// Symmetric key wrap algorithm URIs, RFC 3394 AES key wrap (XML Encryption
// 1.1 section 5.7.2). The legacy kw-tripledes is with the decryption-only
// algorithms below.
const (
	KeyWrapAES128 = "http://www.w3.org/2001/04/xmlenc#kw-aes128"
	KeyWrapAES192 = "http://www.w3.org/2001/04/xmlenc#kw-aes192"
	KeyWrapAES256 = "http://www.w3.org/2001/04/xmlenc#kw-aes256"
)

// Key agreement and key derivation algorithm URIs (XML Encryption 1.1
// sections 5.6.4 and 5.4.1).
const (
	KeyAgreementECDHES     = "http://www.w3.org/2009/xmlenc11#ECDH-ES"
	KeyDerivationConcatKDF = "http://www.w3.org/2009/xmlenc11#ConcatKDF"
)

// Mask generation function URIs, for RSA-OAEP.
const (
	MGF1SHA256 = "http://www.w3.org/2009/xmlenc11#mgf1sha256"
	MGF1SHA384 = "http://www.w3.org/2009/xmlenc11#mgf1sha384"
	MGF1SHA512 = "http://www.w3.org/2009/xmlenc11#mgf1sha512"
)

// BinarySecurityToken ValueType URIs.
const (
	BSTValueTypeX509v3      = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
	BSTValueTypeX509PKIPath = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509PKIPathv1"
)

// BSTEncodingBase64 is the only EncodingType this library emits or accepts.
const BSTEncodingBase64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"

var signatureHashes = map[string]crypto.Hash{
	SigRSASHA256:   crypto.SHA256,
	SigRSASHA384:   crypto.SHA384,
	SigRSASHA512:   crypto.SHA512,
	SigECDSASHA256: crypto.SHA256,
	SigECDSASHA384: crypto.SHA384,
	SigECDSASHA512: crypto.SHA512,
}

var digestHashes = map[string]crypto.Hash{
	DigestSHA256: crypto.SHA256,
	DigestSHA384: crypto.SHA384,
	DigestSHA512: crypto.SHA512,
}

var mgfHashes = map[string]crypto.Hash{
	MGF1SHA256: crypto.SHA256,
	MGF1SHA384: crypto.SHA384,
	MGF1SHA512: crypto.SHA512,
}

// SignatureHash returns the hash a Sig* algorithm signs over, and false for
// any URI that is not a Sig* constant.
func SignatureHash(uri string) (crypto.Hash, bool) {
	h, ok := signatureHashes[uri]
	return h, ok
}

// DigestHash returns the hash for a Digest* URI, and false for any other.
func DigestHash(uri string) (crypto.Hash, bool) {
	h, ok := digestHashes[uri]
	return h, ok
}

// MGFHash returns the hash for an MGF1* URI, and false for any other.
func MGFHash(uri string) (crypto.Hash, bool) {
	h, ok := mgfHashes[uri]
	return h, ok
}

// ---- BEGIN legacy XML Encryption algorithms (decryption only) ----
//
// XML Encryption 1.1 section 5.1.1 marks these REQUIRED (rsa-1_5 is
// OPTIONAL there, but section 5.5.1 requires it for TRIPLEDES keys), and
// section 6.1 describes the chosen-ciphertext attacks against each. The xenc
// package implements them for decryption only: no Encrypt function and
// GenerateEncryptedKey ever produces them, and none is in any default
// allow-list, so a receiver accepts one only when it names it explicitly.
// Name them only for a peer that cannot send AES-GCM and XML Encryption 1.1
// RSA-OAEP with SHA-2.
//
// The SHA-1 digest and MGF are not added to DigestHash or MGFHash: xenc
// resolves them itself, so neither becomes usable for signing, verifying or
// encrypting through those tables.
const (
	// Block encryption, sections 5.2.2 and 5.2.3: CBC with the IV prefixed
	// and the section 5.2.1 padding. Unauthenticated: see section 6.1.1.
	EncTripleDESCBC = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	EncAES128CBC    = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	EncAES192CBC    = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
	EncAES256CBC    = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"

	// KeyTransportRSAOAEPMGF1P is RSA-OAEP with MGF1-SHA1 fixed, section
	// 5.5.2; its digest defaults to SHA-1 too.
	KeyTransportRSAOAEPMGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"

	// KeyTransportRSA15 is RSAES-PKCS1-v1_5, section 5.5.1, open to
	// Bleichenbacher's attack (section 6.1.2).
	KeyTransportRSA15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"

	// KeyWrapTripleDES is the CMS Triple DES key wrap of RFC 3217, section
	// 5.7.1.
	KeyWrapTripleDES = "http://www.w3.org/2001/04/xmlenc#kw-tripledes"

	// MGF1SHA1 is MGF1 with SHA-1, section 5.5.2: what rsa-oaep-mgf1p fixes
	// and what an rsa-oaep EncryptionMethod without xenc11:MGF means.
	MGF1SHA1 = "http://www.w3.org/2009/xmlenc11#mgf1sha1"

	// DigestSHA1, declared with the legacy XML Signature algorithms above, is
	// also XML Encryption's SHA-1 (section 5.8.1): the RSA-OAEP digest an
	// EncryptionMethod without ds:DigestMethod means, or a ConcatKDF digest.
)

// ---- END legacy XML Encryption algorithms ----
