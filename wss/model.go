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
)
