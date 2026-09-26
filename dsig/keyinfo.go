package dsig

import (
	"crypto/x509"
	"fmt"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

// resolveKeyInfo reads ds:KeyInfo, returning the certificate it describes
// and its form. Accepted forms are exactly those Sign emits: a single
// ds:X509Data/ds:X509Certificate, or a direct-reference
// wsse:SecurityTokenReference.
func resolveKeyInfo(doc, ki *xdm.Node) (*x509.Certificate, KeyInfoSpec, error) {
	if ki == nil {
		return nil, KeyInfoNone, nil
	}
	kids := ki.ChildElements()
	if len(kids) != 1 {
		return nil, 0, fmt.Errorf("%w: ds:KeyInfo must hold exactly one element", xmlsec.ErrUnsupportedKeyInfo)
	}
	k := kids[0]
	switch {
	case k.IsElement(NSDSig, "X509Data"):
		certs := k.ChildElements()
		if len(certs) != 1 || !certs[0].IsElement(NSDSig, "X509Certificate") {
			return nil, 0, fmt.Errorf("%w: ds:X509Data must hold exactly one ds:X509Certificate", xmlsec.ErrUnsupportedKeyInfo)
		}
		der, err := xmltree.Base64(certs[0])
		if err != nil {
			return nil, 0, fmt.Errorf("%w: ds:X509Certificate: %v", xmlsec.ErrMalformed, err)
		}
		cert, err := x509.ParseCertificate(der)
		return cert, KeyInfoX509Data, err
	case k.IsElement(wss.NSWSSE, "SecurityTokenReference"):
		cert, err := wss.ResolveSecurityTokenReference(doc, k)
		return cert, KeyInfoSecurityTokenReference, err
	}
	return nil, 0, fmt.Errorf("%w: %s", xmlsec.ErrUnsupportedKeyInfo, k.Name.Local)
}
