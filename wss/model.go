// Package wss implements the WS-Security header model: the wsse:Security
// element, binary security tokens, security token references, wsu:Id
// assignment, timestamps, signature confirmation and reference lists, the
// Basic Security Profile checks on a received header, and the SOAP Message
// Security fault codes.
//
// It does not implement any particular WS-Security policy or profile. It
// provides the elements; the caller composes them.
package wss

import (
	"fmt"

	"github.com/knroy/go-xml/v2/xdm"
)

// roleUltimateReceiver is the SOAP 1.2 role of a header without one.
const roleUltimateReceiver = "http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver"

// Token and key identifier URIs of the X.509 Token Profile and SOAP Message
// Security 1.1.
const (
	valueTypeSKI            = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier"
	valueTypeThumbprintSHA1 = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1"
	// valueTypeEncryptedKey is the wsse11:TokenType of the EncryptedKey
	// token of SOAP Message Security 1.1.1 section 7.7, and the ValueType of
	// a direct reference to one; valueTypeEncryptedKeySHA1 is its key
	// identifier, the SHA-1 of the xenc:CipherValue octets.
	valueTypeEncryptedKey     = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey"
	valueTypeEncryptedKeySHA1 = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1"

	// The SAML Token Profile key identifiers, which a strict check accepts
	// only without an EncodingType (BSP R3070, R6604).
	valueTypeSAMLAssertionID  = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID"
	valueTypeSAML2AssertionID = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID"
)

// firstElements returns the first k element children of n, or all of them
// if it has fewer: enough to tell "exactly one" from "more" without
// collecting every child of a wide element.
func firstElements(n *xdm.Node, k int) []*xdm.Node {
	var out []*xdm.Node
	for c := range n.Children() {
		if c.Kind() == xdm.KindElement {
			if out = append(out, c); len(out) == k {
				break
			}
		}
	}
	return out
}

// maxQuoted bounds the octets of a received value an error message quotes.
const maxQuoted = 64

// quote is %q of s, cut to maxQuoted octets plus "..." when longer, so that
// an error about an attacker's value is not three times its size.
func quote(s string) string {
	if len(s) > maxQuoted {
		return fmt.Sprintf("%q...", s[:maxQuoted])
	}
	return fmt.Sprintf("%q", s)
}
