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
func Leaf(certs []*x509.Certificate) *x509.Certificate { return leaf(certs, false) }

// LeafOfKey is Leaf where certificates for one public key count as one,
// such as a certificate and its re-issue (XML-DSig 4.5.4): issuance among
// them is ignored, and when every leaf carries the same key the first of
// them in certs is returned. Leaves with different keys still return nil.
func LeafOfKey(certs []*x509.Certificate) *x509.Certificate { return leaf(certs, true) }

func leaf(certs []*x509.Certificate, byKey bool) *x509.Certificate {
	same := func(a, b *x509.Certificate) bool {
		return byKey && len(a.RawSubjectPublicKeyInfo) > 0 && bytes.Equal(a.RawSubjectPublicKeyInfo, b.RawSubjectPublicKeyInfo)
	}
	var found *x509.Certificate
	for _, c := range certs {
		if slices.ContainsFunc(certs, func(d *x509.Certificate) bool { return d != c && !same(c, d) && issued(c, d) }) {
			continue
		}
		switch {
		case found == nil:
			found = c
		case !same(found, c):
			return nil
		}
	}
	return found
}

// issued reports whether the certificate issuer names issued subject.
func issued(issuer, subject *x509.Certificate) bool {
	return bytes.Equal(subject.RawIssuer, issuer.RawSubject) &&
		(len(subject.AuthorityKeyId) == 0 || len(issuer.SubjectKeyId) == 0 || bytes.Equal(subject.AuthorityKeyId, issuer.SubjectKeyId))
}
