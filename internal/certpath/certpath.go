// Package certpath finds the end-entity certificate among an unordered set
// of certificates, as a PKCS7 token or a ds:X509Data element carries them.
package certpath

import (
	"bytes"
	"crypto/x509"
	"slices"
)

// Leaf returns the one certificate of certs that issued none of the others,
// by issuer and subject name and, where both are present, authority and
// subject key identifier. It returns nil when there is no such certificate
// or more than one. Nothing is verified: which certificate is the leaf is a
// question of structure, and trusting the path is the caller's decision.
func Leaf(certs []*x509.Certificate) *x509.Certificate {
	var leaf *x509.Certificate
	for _, c := range certs {
		if slices.ContainsFunc(certs, func(d *x509.Certificate) bool { return d != c && issued(c, d) }) {
			continue
		}
		if leaf != nil {
			return nil
		}
		leaf = c
	}
	return leaf
}

// issued reports whether the certificate issuer names issued subject.
func issued(issuer, subject *x509.Certificate) bool {
	return bytes.Equal(subject.RawIssuer, issuer.RawSubject) &&
		(len(subject.AuthorityKeyId) == 0 || len(issuer.SubjectKeyId) == 0 || bytes.Equal(subject.AuthorityKeyId, issuer.SubjectKeyId))
}
