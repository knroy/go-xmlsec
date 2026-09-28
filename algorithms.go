package xmlsec

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

	// DigestSHA384XMLEnc is XML Encryption's own SHA-384 identifier
	// (section 5.8.3). The xenc package accepts it on decryption as the
	// OAEP and ConcatKDF digest, alongside DigestSHA384, which is what it
	// emits because xmlsec1 and Santuario recognise only that one. XML
	// Signature does not define it.
	DigestSHA384XMLEnc = "http://www.w3.org/2001/04/xmlenc#sha384"
)

// SHA-224 algorithms (XML Signature 1.1 section 6.1 and RFC 6931). They are
// in no default set: dsig.Verify accepts one only when the matching
// VerifyOptions allow-list names it. dsig.Sign produces DigestSHA224,
// SigRSASHA224 and SigECDSASHA224 when explicitly asked to, and
// SigHMACSHA224 with dsig.SignOptions.HMACKey; its verification key is only
// ever dsig.VerifyOptions.HMACKey.
const (
	DigestSHA224   = "http://www.w3.org/2001/04/xmldsig-more#sha224"
	SigRSASHA224   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224"
	SigECDSASHA224 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224"
	SigHMACSHA224  = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224"
)

// Legacy XML Signature 1.1 algorithms (section 6.1), implemented for
// VERIFICATION ONLY. Sign never produces them, the dsig package's hash tables
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

	// SigDSASHA256 is DSA with SHA-256 (section 6.4.1), OPTIONAL, verified
	// with (L, N) = (2048, 256) or (3072, 256) keys.
	SigDSASHA256 = "http://www.w3.org/2009/xmldsig11#dsa-sha256"

	// SigECDSASHA1 is ECDSA with SHA-1 (section 6.4.3, RFC 6931).
	SigECDSASHA1 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"

	// The HMAC MACs (section 6.3.1): SHA-1 and SHA-256 REQUIRED, SHA-384 and
	// SHA-512 RECOMMENDED. Only SigHMACSHA1 is legacy: dsig.Sign produces
	// the SHA-2 ones with dsig.SignOptions.HMACKey. None is in a default
	// set, since the key is a shared secret only the caller holds: it is
	// only ever dsig.SignOptions.HMACKey or dsig.VerifyOptions.HMACKey,
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

	// TransformAttachmentCiphertext is the xenc:CipherReference transform
	// the SwA profile requires on every encrypted attachment, section 5.5.2.
	TransformAttachmentCiphertext = "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform"

	// TransformSTR is the STR Dereference Transform of SOAP Message Security
	// 1.1.1 section 8.3: applied to a wsse:SecurityTokenReference, it digests
	// the token the reference names instead of the reference, serialized
	// with the Exclusive C14N its wsse:TransformationParameters carry. The
	// URI is the one WSS4J, the Basic Security Profile (R5423) and the
	// specification's own examples use; the specification's URI table
	// spells it #STRTransform.
	TransformSTR = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform"
)

// Transform URIs that carry a program: an XPath expression (XML Signature
// 6.6.3, XPath Filter 2.0) or an XSLT stylesheet (6.6.5). Verification
// refuses them with ErrTransformRefused unless the caller allows the exact
// program; see dsig.VerifyOptions.AllowedXPathExpressions and
// AllowedXSLTStylesheets. On a CipherReference, XSLT and XPath Filter 2.0
// are refused, and XPath is accepted only as
// xenc.DecryptOptions.AllowedXPathExpressions allows.
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
	// KeyTransportRSAOAEP is XML Encryption 1.1 RSA-OAEP (section 5.5.2),
	// with an explicit digest and MGF: the one to use for new work, and the
	// one WS-Security profiles such as Peppol AS4 require. Not to be confused
	// with KeyTransportRSAOAEPMGF1P, the XML Encryption 1.0 algorithm with
	// SHA-1 fixed, which is decryption-only.
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

	// OPTIONAL finite-field Diffie-Hellman (section 5.6.2): dh-es with an
	// explicit xenc11:KeyDerivationMethod, and dh with the Legacy KDF of
	// section 5.6.2.2. Neither is in a default allow-list.
	KeyAgreementDHES = "http://www.w3.org/2009/xmlenc11#dh-es"
	KeyAgreementDH   = "http://www.w3.org/2001/04/xmlenc#dh"

	// KeyDerivationPBKDF2 is PBKDF2 (section 5.4.2), OPTIONAL. Its PRF is
	// named by an HMAC URI: SigHMACSHA256, 384 or 512, or the legacy
	// SigHMACSHA1. It is not in a default allow-list.
	KeyDerivationPBKDF2 = "http://www.w3.org/2009/xmlenc11#pbkdf2"
)

// Mask generation function URIs, for RSA-OAEP.
const (
	MGF1SHA256 = "http://www.w3.org/2009/xmlenc11#mgf1sha256"
	MGF1SHA384 = "http://www.w3.org/2009/xmlenc11#mgf1sha384"
	MGF1SHA512 = "http://www.w3.org/2009/xmlenc11#mgf1sha512"

	// MGF1SHA224 is MGF1 with SHA-224 (section 5.5.2). It is produced when
	// named but is in no default allow-list: a receiver accepts it only
	// when it names it.
	MGF1SHA224 = "http://www.w3.org/2009/xmlenc11#mgf1sha224"
)

// BinarySecurityToken ValueType URIs.
const (
	BSTValueTypeX509v3      = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
	BSTValueTypeX509PKIPath = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509PKIPathv1"

	// BSTValueTypePKCS7 is a PKCS#7 SignedData carrying a certificate path
	// as an unordered set (X.509 Token Profile 1.1.1 section 3.1). The Basic
	// Security Profile prefers BSTValueTypeX509PKIPath (R5202).
	BSTValueTypePKCS7 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#PKCS7"
)

// BSTEncodingBase64 is the only EncodingType this library emits or accepts.
const BSTEncodingBase64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"

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
// The SHA-1 digest and MGF are not in the tables the dsig and xenc packages
// resolve secure algorithms through: xenc resolves them itself, so neither
// becomes usable for signing, verifying or encrypting.
const (
	// Block encryption, sections 5.2.2 and 5.2.3: CBC with the IV prefixed
	// and the section 5.2.1 padding. Unauthenticated: see section 6.1.1.
	EncTripleDESCBC = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	EncAES128CBC    = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	EncAES192CBC    = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
	EncAES256CBC    = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"

	// KeyTransportRSAOAEPMGF1P is RSA-OAEP with MGF1-SHA1 fixed, section
	// 5.5.2; its digest defaults to SHA-1 too. It is the XML Encryption 1.0
	// algorithm, decryption-only here: for new work use KeyTransportRSAOAEP,
	// despite the shorter name.
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
