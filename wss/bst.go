package wss

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// AddBinarySecurityToken adds a wsse:BinarySecurityToken carrying cert,
// ahead of the existing content like Prepend: after a leading wsu:Timestamp,
// before everything else. Add a token before the step that references it,
// and Prepend keeps it ahead of that step.
//
// valueType is xmlsec.BSTValueTypeX509v3 for a single certificate, or
// xmlsec.BSTValueTypeX509PKIPath for cert plus chain (leaf first, excluding
// cert). The returned id is the token's wsu:Id, for use in a
// SecurityTokenReference.
func (h *Header) AddBinarySecurityToken(cert *x509.Certificate, chain []*x509.Certificate, valueType string) (string, error) {
	var der []byte
	switch valueType {
	case xmlsec.BSTValueTypeX509v3:
		der = cert.Raw
	case xmlsec.BSTValueTypeX509PKIPath:
		// PkiPath is ordered from the trust anchor down, target last.
		path := []asn1.RawValue{{FullBytes: cert.Raw}}
		for _, c := range chain {
			path = append(path, asn1.RawValue{FullBytes: c.Raw})
		}
		slices.Reverse(path)
		// Marshal cannot fail on a sequence of RawValues: each is emitted
		// verbatim from FullBytes.
		der, _ = asn1.Marshal(path)
	default:
		return "", fmt.Errorf("%w: BST ValueType %q", xmlsec.ErrUnsupportedAlgorithm, valueType)
	}

	id, err := newID(h.doc)
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
// (last) certificate for X509PKIPathv1.
func ParseBinarySecurityToken(bst *xdm.Node) (*x509.Certificate, error) {
	if bst == nil || !bst.IsElement(xmlsec.NSWSSE, "BinarySecurityToken") {
		return nil, fmt.Errorf("%w: not a wsse:BinarySecurityToken", xmlsec.ErrUnsupportedKeyInfo)
	}
	if enc := bst.AttrValue("EncodingType"); enc != xmlsec.BSTEncodingBase64 {
		return nil, fmt.Errorf("%w: BST EncodingType %q", xmlsec.ErrUnsupportedKeyInfo, enc)
	}
	der, err := xmltree.Base64(bst)
	if err != nil {
		return nil, fmt.Errorf("%w: BST content: %v", xmlsec.ErrMalformed, err)
	}
	switch vt := bst.AttrValue("ValueType"); vt {
	case xmlsec.BSTValueTypeX509v3:
		return x509.ParseCertificate(der)
	case xmlsec.BSTValueTypeX509PKIPath:
		var path []asn1.RawValue
		rest, err := asn1.Unmarshal(der, &path)
		if err != nil || len(rest) > 0 || len(path) == 0 {
			return nil, fmt.Errorf("%w: BST PkiPath", xmlsec.ErrMalformed)
		}
		return x509.ParseCertificate(path[len(path)-1].FullBytes)
	default:
		return nil, fmt.Errorf("%w: BST ValueType %q", xmlsec.ErrUnsupportedKeyInfo, vt)
	}
}
