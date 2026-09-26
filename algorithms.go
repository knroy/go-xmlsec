package xmlsec

import "crypto"

// Signature algorithm URIs. SHA-1 variants are deliberately absent.
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

// Key transport algorithm URIs. The legacy rsa-oaep-mgf1p form, which
// implies SHA-1 MGF, is deliberately absent.
const (
	KeyTransportRSAOAEP = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
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
