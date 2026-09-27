package wss

import (
	"errors"
	"fmt"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
)

// FaultCode maps each class of error to its SOAP Message Security 1.1.1
// section 12 fault code, the more specific first.
func TestFaultCode(t *testing.T) {
	if FaultCode(nil) != (xdm.QName{}) {
		t.Fatal("nil error has a fault code")
	}
	for err, want := range map[error]string{
		xmlsec.ErrMessageExpired: "MessageExpired",
		fmt.Errorf("%w: %w", xmlsec.ErrSecurityTokenUnavailable, xmlsec.ErrIDNotFound): "SecurityTokenUnavailable",
		fmt.Errorf("%w: %w", xmlsec.ErrInvalidSecurityToken, xmlsec.ErrMalformed):      "InvalidSecurityToken",
		xmlsec.ErrUnsupportedAlgorithm: "UnsupportedAlgorithm",
		xmlsec.ErrAlgorithmNotAllowed:  "UnsupportedAlgorithm",
		xmlsec.ErrTransformRefused:     "UnsupportedAlgorithm",
		xmlsec.ErrUnsupportedKeyInfo:   "UnsupportedSecurityToken",
		xmlsec.ErrUntrusted:            "FailedAuthentication",
		xmlsec.ErrSignatureInvalid:     "FailedCheck",
		xmlsec.ErrDigestMismatch:       "FailedCheck",
		xmlsec.ErrDecryptionFailed:     "FailedCheck",
		xmlsec.ErrMalformed:            "InvalidSecurity",
		xmlsec.ErrAmbiguousID:          "InvalidSecurity",
		errors.New("other"):            "InvalidSecurity",
	} {
		if got := FaultCode(err); got.Local != want || got.URI != xmlsec.NSWSSE || got.Prefix != "wsse" {
			t.Errorf("%v: %v, want wsse:%s", err, got, want)
		}
	}

	// What this package returns maps as documented.
	if _, err := ParseBinarySecurityToken(parseDoc(t, bst(`EncodingType="`+xmlsec.BSTEncodingBase64+`" ValueType="`+
		xmlsec.BSTValueTypeX509v3+`"`, "AAAA")).Children[0]); FaultCode(err).Local != "InvalidSecurityToken" || !errors.Is(err, xmlsec.ErrInvalidSecurityToken) {
		t.Errorf("unreadable certificate: %v", err)
	}
}
