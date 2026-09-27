package wss

import (
	"errors"
	"slices"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
)

// FaultCode maps an error from this module to the SOAP fault code of SOAP
// Message Security 1.1.1 section 12, a wsse-prefixed QName: the SOAP 1.1
// faultcode, or the SOAP 1.2 Subcode/Value under env:Sender. A nil error has
// the zero QName.
//
//	wsse:MessageExpired            xmlsec.ErrMessageExpired
//	wsse:SecurityTokenUnavailable  xmlsec.ErrSecurityTokenUnavailable
//	wsse:InvalidSecurityToken      xmlsec.ErrInvalidSecurityToken
//	wsse:UnsupportedAlgorithm      xmlsec.ErrUnsupportedAlgorithm, ErrAlgorithmNotAllowed, ErrTransformRefused
//	wsse:UnsupportedSecurityToken  xmlsec.ErrUnsupportedKeyInfo
//	wsse:FailedAuthentication      xmlsec.ErrUntrusted
//	wsse:FailedCheck               xmlsec.ErrSignatureInvalid, ErrDigestMismatch, ErrDecryptionFailed
//	wsse:InvalidSecurity           anything else
//
// The first row that matches wins, so an error wrapping two sentinels, such
// as a token that is both malformed and invalid, maps to the more specific.
//
// The mapping is coarse on purpose: it says which class of check failed,
// never which step of it, so a fault built from it is no oracle. Section 12
// still lets a receiver return no fault, or one generic fault, and that is
// the safer choice facing an unauthenticated sender; never put err's text in
// the faultstring.
func FaultCode(err error) xdm.QName {
	if err == nil {
		return xdm.QName{}
	}
	local := "InvalidSecurity"
	for _, m := range faultCodes {
		if slices.ContainsFunc(m.errs, func(t error) bool { return errors.Is(err, t) }) {
			local = m.local
			break
		}
	}
	return xdm.QName{Prefix: "wsse", URI: xmlsec.NSWSSE, Local: local}
}

var faultCodes = []struct {
	local string
	errs  []error
}{
	{"MessageExpired", []error{xmlsec.ErrMessageExpired}},
	{"SecurityTokenUnavailable", []error{xmlsec.ErrSecurityTokenUnavailable}},
	{"InvalidSecurityToken", []error{xmlsec.ErrInvalidSecurityToken}},
	{"UnsupportedAlgorithm", []error{xmlsec.ErrUnsupportedAlgorithm, xmlsec.ErrAlgorithmNotAllowed, xmlsec.ErrTransformRefused}},
	{"UnsupportedSecurityToken", []error{xmlsec.ErrUnsupportedKeyInfo}},
	{"FailedAuthentication", []error{xmlsec.ErrUntrusted}},
	{"FailedCheck", []error{xmlsec.ErrSignatureInvalid, xmlsec.ErrDigestMismatch, xmlsec.ErrDecryptionFailed}},
}
