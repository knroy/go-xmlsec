package wss

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"

	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/keysize"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
)

// AddBinarySecurityToken adds a wsse:BinarySecurityToken carrying cert,
// ahead of the existing content like Prepend: after a leading wsu:Timestamp,
// before everything else. Add a token before the step that references it,
// and Prepend keeps it ahead of that step.
//
// valueType is xmlsec.BSTValueTypeX509v3 for a single certificate,
// xmlsec.BSTValueTypeX509PKIPath for cert plus chain (leaf first, excluding
// cert), or xmlsec.BSTValueTypePKCS7 for cert plus chain as a DER,
// certificates-only PKCS#7 SignedData. A PKCS#7 set is unordered, so the
// receiver finds the leaf as the one certificate that issued none of the
// others: cert must be that certificate. For PKIPath and PKCS7 at most 15
// may accompany cert, or the call fails with xmlsec.ErrUnsupportedKeyInfo,
// as the receiver refuses more. The returned id is
// the token's wsu:Id, for use in a SecurityTokenReference.
func (h *Header) AddBinarySecurityToken(cert *x509.Certificate, chain []*x509.Certificate, valueType string) (string, error) {
	return h.addBinarySecurityToken(cert, chain, valueType, "")
}

// AddBinarySecurityTokenWithID is AddBinarySecurityToken with the token's
// wsu:Id supplied by the caller, as AssignIDWith supplies one: for a
// byte-reproducible header. id must be an NCName not already in use in the
// document.
func (h *Header) AddBinarySecurityTokenWithID(cert *x509.Certificate, chain []*x509.Certificate, valueType, id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("%w: AddBinarySecurityTokenWithID needs an ID", xmlsec.ErrMalformed)
	}
	return h.addBinarySecurityToken(cert, chain, valueType, id)
}

func (h *Header) addBinarySecurityToken(cert *x509.Certificate, chain []*x509.Certificate, valueType, id string) (string, error) {
	if err := h.check(); err != nil {
		return "", err
	}
	if cert == nil || slices.Contains(chain, nil) {
		return "", errors.New("wss: AddBinarySecurityToken needs a certificate, and no nil in chain")
	}
	var der []byte
	switch valueType {
	case xmlsec.BSTValueTypeX509v3:
		der = cert.Raw
	case xmlsec.BSTValueTypeX509PKIPath:
		if len(chain) >= maxPKCS7Certificates {
			return "", fmt.Errorf("%w: BST PkiPath carries more than %d certificates", xmlsec.ErrUnsupportedKeyInfo, maxPKCS7Certificates)
		}
		// PkiPath is ordered from the trust anchor down, target last.
		path := []asn1.RawValue{{FullBytes: cert.Raw}}
		for _, c := range chain {
			path = append(path, asn1.RawValue{FullBytes: c.Raw})
		}
		slices.Reverse(path)
		// Marshal cannot fail on a sequence of RawValues: each is emitted
		// verbatim from FullBytes.
		der, _ = asn1.Marshal(path)
	case xmlsec.BSTValueTypePKCS7:
		der = marshalPKCS7(append([]*x509.Certificate{cert}, chain...))
		leaf, err := parsePKCS7(der)
		if err != nil {
			return "", err
		}
		if !leaf.Equal(cert) {
			return "", fmt.Errorf("%w: BST PKCS7: cert issued a certificate in chain", xmlsec.ErrUnsupportedKeyInfo)
		}
	default:
		return "", fmt.Errorf("%w: BST ValueType %q", xmlsec.ErrUnsupportedAlgorithm, valueType)
	}

	id, err := idFor(h.doc.Root(), id)
	if err != nil {
		return "", err
	}
	// Built detached and attached last: its own xmlns:wsu cannot conflict
	// with an ancestor's, and a failure leaves the header untouched.
	bst := xmltree.Element(nil, "wsse", xmlsec.NSWSSE, "BinarySecurityToken")
	bst.AddNamespace("wsu", xmlsec.NSWSU)
	xmltree.SetAttr(bst, "wsu", xmlsec.NSWSU, "Id", id)
	xmltree.SetAttr(bst, "", "", "EncodingType", xmlsec.BSTEncodingBase64)
	xmltree.SetAttr(bst, "", "", "ValueType", valueType)
	xmltree.Text(bst, base64.StdEncoding.EncodeToString(der))
	h.insert(h.front(), bst)
	return id, nil
}

// ParseBinarySecurityToken returns the certificate a
// wsse:BinarySecurityToken carries: the token itself for X509v3, the target
// (last) certificate for X509PKIPathv1, a path of from 1 to 16, and for PKCS7 the one certificate
// that issued none of the others, by issuer and subject name and, where both
// are present, authority and subject key identifier. A PKCS7 token must be a
// DER ContentInfo of type signedData, SignedData version 1 with data
// content, carrying from 1 to 16 X.509 certificates; its CRLs and signer
// infos are ignored. A token with no single such leaf, or with more
// certificates, is refused with xmlsec.ErrUnsupportedKeyInfo, as is a
// certificate whose RSA key has more than 16384 bits, before the key is used.
//
// A token that is not what its ValueType names, such as base64 that decodes
// to no certificate, is also xmlsec.ErrInvalidSecurityToken, the
// wsse:InvalidSecurityToken fault; an unsupported ValueType or EncodingType
// is only xmlsec.ErrUnsupportedKeyInfo, wsse:UnsupportedSecurityToken.
//
// A token without an EncodingType is read as Base64Binary, the default of
// SOAP Message Security 1.1.1 section 6.3;
// ResolveSecurityTokenReferenceStrict refuses it, as the Basic Security
// Profile requires the attribute (R3029).
func ParseBinarySecurityToken(bst *xdm.Node) (*x509.Certificate, error) {
	cert, err := parseBinarySecurityToken(bst)
	if err != nil && !errors.Is(err, xmlsec.ErrUnsupportedKeyInfo) {
		return nil, fmt.Errorf("%w: %w", xmlsec.ErrInvalidSecurityToken, err)
	}
	return cert, err
}

func parseBinarySecurityToken(bst *xdm.Node) (*x509.Certificate, error) {
	if bst == nil || !bst.IsElement(xmlsec.NSWSSE, "BinarySecurityToken") {
		return nil, fmt.Errorf("%w: not a wsse:BinarySecurityToken", xmlsec.ErrUnsupportedKeyInfo)
	}
	// SOAP Message Security 1.1.1 section 6.3: Base64Binary is the
	// default. BSP R3029 requires it stated; the strict resolver checks.
	if enc := bst.Attr("", "EncodingType"); enc != nil && enc.Value() != xmlsec.BSTEncodingBase64 {
		return nil, fmt.Errorf("%w: BST EncodingType %s", xmlsec.ErrUnsupportedKeyInfo, quote(enc.Value()))
	}
	der, err := xmltree.Base64(bst)
	if err != nil {
		return nil, fmt.Errorf("%w: BST content: %v", xmlsec.ErrMalformed, err)
	}
	var cert *x509.Certificate
	switch vt := bst.AttrValue("ValueType"); vt {
	case xmlsec.BSTValueTypeX509v3:
		cert, err = x509.ParseCertificate(der)
	case xmlsec.BSTValueTypeX509PKIPath:
		cert, err = parsePKIPath(der)
	case xmlsec.BSTValueTypePKCS7:
		cert, err = parsePKCS7(der)
	default:
		return nil, fmt.Errorf("%w: BST ValueType %s", xmlsec.ErrUnsupportedKeyInfo, quote(vt))
	}
	if err != nil {
		return nil, err
	}
	// Bounded before the key verifies anything: an RSA verification costs
	// the cube of the modulus length.
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		if err := keysize.CheckRSA(pub.N.BitLen()); err != nil {
			return nil, err
		}
	}
	return cert, nil
}

// parsePKIPath returns the target certificate of a PkiPath, the last of a
// DER SEQUENCE OF certificates. It walks the sequence one element at a time
// and keeps only the last, so a token of many tiny elements costs nothing
// to refuse; more than maxPKCS7Certificates is ErrUnsupportedKeyInfo, the
// same bound as a PKCS7 token.
func parsePKIPath(der []byte) (*x509.Certificate, error) {
	malformed := fmt.Errorf("%w: BST PkiPath", xmlsec.ErrMalformed)
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &seq); err != nil || len(rest) > 0 || !isTag(seq, asn1.ClassUniversal, asn1.TagSequence) {
		return nil, malformed
	}
	var last asn1.RawValue
	n := 0
	for b := seq.Bytes; len(b) > 0; n++ {
		if n == maxPKCS7Certificates {
			return nil, fmt.Errorf("%w: BST PkiPath carries more than %d certificates", xmlsec.ErrUnsupportedKeyInfo, maxPKCS7Certificates)
		}
		var err error
		if b, err = asn1.Unmarshal(b, &last); err != nil {
			return nil, malformed
		}
	}
	if n == 0 {
		return nil, malformed
	}
	return x509.ParseCertificate(last.FullBytes)
}
