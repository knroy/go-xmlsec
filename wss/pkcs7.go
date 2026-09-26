package wss

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"

	"github.com/knroy/go-xmlsec"
)

// PKCS#7 content types (RFC 2315 section 14).
var (
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

// maxPKCS7Certificates bounds the certificates a PKCS7 token may carry.
// Every one is parsed, and finding the leaf compares every pair; a real
// certificate path is a handful.
const maxPKCS7Certificates = 16

// marshalPKCS7 encodes certs as a degenerate, certificates-only PKCS#7
// SignedData in DER (RFC 2315 section 9.1): version 1, no digest algorithms,
// data content with no content, the certificates, no signer infos. Marshal
// sorts the SET OF certificates as DER requires, and cannot fail: each
// certificate is emitted verbatim from its Raw octets.
func marshalPKCS7(certs []*x509.Certificate) []byte {
	raw := make([]asn1.RawValue, len(certs))
	for i, c := range certs {
		raw[i] = asn1.RawValue{FullBytes: c.Raw}
	}
	sd, _ := asn1.Marshal(struct {
		Version          int
		DigestAlgorithms []asn1.RawValue `asn1:"set"`
		ContentInfo      struct{ ContentType asn1.ObjectIdentifier }
		Certificates     []asn1.RawValue `asn1:"set,tag:0"`
		SignerInfos      []asn1.RawValue `asn1:"set"`
	}{Version: 1, ContentInfo: struct{ ContentType asn1.ObjectIdentifier }{oidData}, Certificates: raw})
	der, _ := asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd}})
	return der
}

// parsePKCS7 returns the leaf certificate of a PKCS7 token: a DER
// ContentInfo of type signedData whose SignedData, version 1, has data
// content and carries X.509 certificates. CRLs and signer infos, which the
// X.509 Token Profile permits, are ignored: the XML signature, not the
// PKCS#7 one, is what authenticates the key, and trusting the certificates
// is the caller's decision. The SET OF certificates is unordered, so the
// leaf is the one certificate that issued none of the others, by issuer and
// subject name and, where both are present, authority and subject key
// identifier. None, or more than one, is ErrUnsupportedKeyInfo.
func parsePKCS7(der []byte) (*x509.Certificate, error) {
	malformed := fmt.Errorf("%w: BST PKCS7", xmlsec.ErrMalformed)
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}
	if rest, err := asn1.Unmarshal(der, &ci); err != nil || len(rest) > 0 ||
		!ci.ContentType.Equal(oidSignedData) || !isTag(ci.Content, asn1.ClassContextSpecific, 0) {
		return nil, malformed
	}
	var sd asn1.RawValue
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil || len(rest) > 0 || !isTag(sd, asn1.ClassUniversal, asn1.TagSequence) {
		return nil, malformed
	}
	// The fields of SignedData: version, digestAlgorithms, contentInfo,
	// [0] certificates, [1] crls, signerInfos.
	var f []asn1.RawValue
	for b := sd.Bytes; len(b) > 0; {
		var v asn1.RawValue
		var err error
		if b, err = asn1.Unmarshal(b, &v); err != nil {
			return nil, malformed
		}
		f = append(f, v)
	}
	if len(f) < 4 {
		return nil, malformed
	}
	var version int
	if _, err := asn1.Unmarshal(f[0].FullBytes, &version); err != nil {
		return nil, malformed
	}
	if version != 1 {
		return nil, fmt.Errorf("%w: BST PKCS7 SignedData version %d", xmlsec.ErrUnsupportedKeyInfo, version)
	}
	var content struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"optional"`
	}
	if !isTag(f[1], asn1.ClassUniversal, asn1.TagSet) || !isTag(f[2], asn1.ClassUniversal, asn1.TagSequence) {
		return nil, malformed
	}
	if _, err := asn1.Unmarshal(f[2].FullBytes, &content); err != nil || !content.ContentType.Equal(oidData) {
		return nil, malformed
	}
	var certsField []byte
	i := 3
	if isTag(f[i], asn1.ClassContextSpecific, 0) {
		certsField = f[i].Bytes
		i++
	}
	if i < len(f) && isTag(f[i], asn1.ClassContextSpecific, 1) {
		i++
	}
	if i != len(f)-1 || !isTag(f[i], asn1.ClassUniversal, asn1.TagSet) {
		return nil, malformed
	}

	var certs []*x509.Certificate
	for b := certsField; len(b) > 0; {
		if len(certs) == maxPKCS7Certificates {
			return nil, fmt.Errorf("%w: BST PKCS7 carries more than %d certificates", xmlsec.ErrUnsupportedKeyInfo, maxPKCS7Certificates)
		}
		var v asn1.RawValue
		var err error
		if b, err = asn1.Unmarshal(b, &v); err != nil {
			return nil, malformed
		}
		// CMS adds other certificate choices, each context-tagged.
		if !isTag(v, asn1.ClassUniversal, asn1.TagSequence) {
			return nil, fmt.Errorf("%w: BST PKCS7 carries a certificate other than X.509", xmlsec.ErrUnsupportedKeyInfo)
		}
		c, err := x509.ParseCertificate(v.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: BST PKCS7 certificate: %v", xmlsec.ErrMalformed, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: BST PKCS7 carries no certificate", xmlsec.ErrMalformed)
	}

	var leaf *x509.Certificate
	for _, c := range certs {
		if slices.ContainsFunc(certs, func(d *x509.Certificate) bool { return d != c && issued(c, d) }) {
			continue
		}
		if leaf != nil {
			leaf = nil
			break
		}
		leaf = c
	}
	if leaf == nil {
		return nil, fmt.Errorf("%w: BST PKCS7 has no single leaf certificate", xmlsec.ErrUnsupportedKeyInfo)
	}
	return leaf, nil
}

// isTag reports whether v is a constructed element of the given class and
// tag.
func isTag(v asn1.RawValue, class, tag int) bool {
	return v.Class == class && v.Tag == tag && v.IsCompound
}

// issued reports whether the certificate issuer names issued subject.
func issued(issuer, subject *x509.Certificate) bool {
	return bytes.Equal(subject.RawIssuer, issuer.RawSubject) &&
		(len(subject.AuthorityKeyId) == 0 || len(issuer.SubjectKeyId) == 0 || bytes.Equal(subject.AuthorityKeyId, issuer.SubjectKeyId))
}
