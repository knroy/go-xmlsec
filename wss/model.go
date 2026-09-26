// Package wss implements the WS-Security header model: the wsse:Security
// element, binary security tokens, security token references, wsu:Id
// assignment and timestamps.
//
// It does not implement any particular WS-Security policy or profile. It
// provides the elements; the caller composes them.
package wss

// roleUltimateReceiver is the SOAP 1.2 role of a header without one.
const roleUltimateReceiver = "http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver"

// Token and key identifier URIs of the X.509 Token Profile and SOAP Message
// Security 1.1.
const (
	valueTypeSKI            = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier"
	valueTypeThumbprintSHA1 = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1"
)
