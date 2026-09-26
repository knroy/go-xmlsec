// Package xenc implements XML Encryption: RSA-OAEP key transport with an
// explicit MGF, and AES-GCM data encryption, inline or by CipherReference.
package xenc

import (
	"crypto/x509"
	"fmt"
	"slices"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// Namespace and type URIs.
const (
	NSXEnc   = "http://www.w3.org/2001/04/xmlenc#"
	NSXEnc11 = "http://www.w3.org/2009/xmlenc11#"
	NSDSig   = "http://www.w3.org/2000/09/xmldsig#"

	TypeElement = "http://www.w3.org/2001/04/xmlenc#Element"

	// TransformAttachmentCiphertext is the CipherReference transform the
	// SwA profile requires on every encrypted attachment.
	TransformAttachmentCiphertext = "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform"
)

// EncryptOptions configures encryption.
type EncryptOptions struct {
	// DataAlgorithm is an Enc* constant. Required.
	DataAlgorithm string

	// KeyTransportAlgorithm is a KeyTransport* constant. Required.
	KeyTransportAlgorithm string

	// MGFAlgorithm is an MGF1* constant, required for RSA-OAEP. It is
	// emitted as an explicit xenc11:MGF element: omitting it means SHA-1
	// MGF by specification default.
	MGFAlgorithm string

	// DigestAlgorithm is the OAEP digest, a Digest* constant. Required.
	DigestAlgorithm string

	// OAEPParams is the optional OAEP label. Normally empty.
	OAEPParams []byte

	// Recipient is the certificate whose public key wraps the session key.
	Recipient *x509.Certificate

	// SessionKey, if non-nil, is used instead of a freshly generated key.
	// For tests only. Never set in production.
	SessionKey []byte

	// DataID, if set, becomes the Id of the xenc:EncryptedData that
	// EncryptElement or EncryptAttachment produces, for an
	// EncryptedKey.AddDataReference to point at.
	DataID string
}

// keySizes maps each data algorithm to its AES key length.
var keySizes = map[string]int{
	xmlsec.EncAES128GCM: 16,
	xmlsec.EncAES192GCM: 24,
	xmlsec.EncAES256GCM: 32,
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{xmlsec.ErrMalformed}, args...)...)
}

// allowed checks v against list, or against known when list is empty.
func allowed(kind, v string, list []string, known bool) error {
	if len(list) == 0 && known || slices.Contains(list, v) {
		return nil
	}
	return fmt.Errorf("%w: %s algorithm %q", xmlsec.ErrAlgorithmNotAllowed, kind, v)
}

func element(parent *xdm.Node, local string) *xdm.Node {
	return xmltree.Element(parent, "xenc", NSXEnc, local)
}

// newRoot creates a detached xenc root element with its namespace declared.
func newRoot(local string) *xdm.Node {
	e := element(nil, local)
	e.AddNamespace("xenc", NSXEnc)
	return e
}

func encryptionMethod(parent *xdm.Node, alg string) *xdm.Node {
	m := element(parent, "EncryptionMethod")
	xmltree.SetAttr(m, "", "", "Algorithm", alg)
	return m
}

// parseEncryptionMethod returns the Algorithm of el's xenc:EncryptionMethod,
// which must be its first element child, and the method element itself.
func parseEncryptionMethod(el *xdm.Node) (string, *xdm.Node, error) {
	kids := el.ChildElements()
	if len(kids) == 0 || !kids[0].IsElement(NSXEnc, "EncryptionMethod") {
		return "", nil, malformed("%s without xenc:EncryptionMethod", el.Name.Local)
	}
	return kids[0].AttrValue("Algorithm"), kids[0], nil
}

// cipherData returns el's xenc:CipherData child.
func cipherData(el *xdm.Node) (*xdm.Node, error) {
	for _, k := range el.ChildElements() {
		if k.IsElement(NSXEnc, "CipherData") {
			return k, nil
		}
	}
	return nil, malformed("%s without xenc:CipherData", el.Name.Local)
}

// cipherValue decodes the xenc:CipherData/xenc:CipherValue of el.
func cipherValue(el *xdm.Node) ([]byte, error) {
	cd, err := cipherData(el)
	if err != nil {
		return nil, err
	}
	kids := cd.ChildElements()
	if len(kids) != 1 || !kids[0].IsElement(NSXEnc, "CipherValue") {
		return nil, malformed("xenc:CipherData must hold one xenc:CipherValue")
	}
	b, err := xmltree.Base64(kids[0])
	if err != nil {
		return nil, malformed("xenc:CipherValue: %v", err)
	}
	return b, nil
}

func setDataID(ed *xdm.Node, opts EncryptOptions) {
	if opts.DataID != "" {
		xmltree.SetAttr(ed, "", "", "Id", opts.DataID)
	}
}
