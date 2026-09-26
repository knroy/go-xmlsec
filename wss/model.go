// Package wss implements the WS-Security header model: the wsse:Security
// element, binary security tokens, security token references, wsu:Id
// assignment and timestamps.
//
// It does not implement any particular WS-Security policy or profile. It
// provides the elements; the caller composes them.
package wss

// Namespace URIs.
const (
	NSWSSE   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	NSWSU    = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	NSXML    = "http://www.w3.org/XML/1998/namespace"
	NSSOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"
	NSSOAP12 = "http://www.w3.org/2003/05/soap-envelope"

	// NSWSSE11 is the WS-Security 1.1 extension namespace, of
	// wsse11:TokenType.
	NSWSSE11 = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"
)

// The XML Signature and XML Encryption namespaces, whose elements carry an
// unqualified Id rather than wsu:Id. Not imported from dsig and xenc, which
// import this package.
const (
	nsDSig   = "http://www.w3.org/2000/09/xmldsig#"
	nsDSig11 = "http://www.w3.org/2009/xmldsig11#"
	nsXEnc   = "http://www.w3.org/2001/04/xmlenc#"
	nsXEnc11 = "http://www.w3.org/2009/xmlenc11#"
)

// roleUltimateReceiver is the SOAP 1.2 role of a header without one.
const roleUltimateReceiver = "http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver"

// Token and key identifier URIs of the X.509 Token Profile and SOAP Message
// Security 1.1.
const (
	valueTypePKCS7          = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#PKCS7"
	valueTypeSKI            = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier"
	valueTypeThumbprintSHA1 = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1"
)
