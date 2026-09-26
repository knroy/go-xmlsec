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
// and its form. Accepted: a direct-reference wsse:SecurityTokenReference, or
// ds:X509Data elements carrying exactly one ds:X509Certificate between them,
// optionally beside the subject name, issuer-serial or SKI that describe it.
func resolveKeyInfo(doc, ki *xdm.Node) (*x509.Certificate, KeyInfoSpec, error) {
	if ki == nil {
		return nil, KeyInfoNone, nil
	}
	kids := ki.ChildElements()
	if len(kids) == 1 && kids[0].IsElement(wss.NSWSSE, "SecurityTokenReference") {
		cert, err := wss.ResolveSecurityTokenReference(doc, kids[0])
		return cert, KeyInfoSecurityTokenReference, err
	}

	// One or more ds:X509Data carrying exactly one certificate between them.
	// Subject name, issuer-serial and SKI beside it only describe that
	// certificate; they are ignored, and never used to select a key.
	var certEl *xdm.Node
	for _, k := range kids {
		if !k.IsElement(NSDSig, "X509Data") {
			return nil, 0, fmt.Errorf("%w: %s", xmlsec.ErrUnsupportedKeyInfo, k.Name.Local)
		}
		for _, d := range k.ChildElements() {
			switch {
			case d.IsElement(NSDSig, "X509Certificate"):
				if certEl != nil {
					return nil, 0, fmt.Errorf("%w: more than one ds:X509Certificate", xmlsec.ErrUnsupportedKeyInfo)
				}
				certEl = d
			case d.IsElement(NSDSig, "X509SubjectName"), d.IsElement(NSDSig, "X509IssuerSerial"), d.IsElement(NSDSig, "X509SKI"):
			default:
				return nil, 0, fmt.Errorf("%w: %s in ds:X509Data", xmlsec.ErrUnsupportedKeyInfo, d.Name.Local)
			}
		}
	}
	if certEl == nil {
		return nil, 0, fmt.Errorf("%w: no ds:X509Certificate", xmlsec.ErrUnsupportedKeyInfo)
	}
	der, err := xmltree.Base64(certEl)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: ds:X509Certificate: %v", xmlsec.ErrMalformed, err)
	}
	cert, err := x509.ParseCertificate(der)
	return cert, KeyInfoX509Data, err
}
