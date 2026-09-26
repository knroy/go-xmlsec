package xenc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// EncryptedKey is a generated xenc:EncryptedKey plus the session key it wraps.
type EncryptedKey struct {
	// Element is the xenc:EncryptedKey to place in the security header.
	Element *xdm.Node

	// SessionKey is the unwrapped symmetric key, retained so the caller can
	// encrypt several EncryptedData or attachment bodies under one
	// EncryptedKey.
	//
	// Callers should zero this when done.
	SessionKey []byte
}

// oaepOptions validates the key transport parameters.
func oaepOptions(kt, mgf, digest string, label []byte) (*rsa.OAEPOptions, error) {
	if kt != xmlsec.KeyTransportRSAOAEP {
		return nil, fmt.Errorf("%w: key transport %q", xmlsec.ErrUnsupportedAlgorithm, kt)
	}
	mh, ok := xmlsec.MGFHash(mgf)
	if !ok {
		return nil, fmt.Errorf("%w: MGF %q", xmlsec.ErrUnsupportedAlgorithm, mgf)
	}
	dh, ok := xmlsec.DigestHash(digest)
	if !ok {
		return nil, fmt.Errorf("%w: OAEP digest %q", xmlsec.ErrUnsupportedAlgorithm, digest)
	}
	return &rsa.OAEPOptions{Hash: dh, MGFHash: mh, Label: label}, nil
}

// GenerateEncryptedKey creates an xenc:EncryptedKey wrapping a fresh
// session key for the recipient.
//
// The element carries no ds:KeyInfo; the caller adds one identifying the
// recipient's key in whatever form its profile requires.
func GenerateEncryptedKey(opts EncryptOptions) (*EncryptedKey, error) {
	size, ok := keySizes[opts.DataAlgorithm]
	if !ok {
		return nil, fmt.Errorf("%w: data %q", xmlsec.ErrUnsupportedAlgorithm, opts.DataAlgorithm)
	}
	oaep, err := oaepOptions(opts.KeyTransportAlgorithm, opts.MGFAlgorithm, opts.DigestAlgorithm, opts.OAEPParams)
	if err != nil {
		return nil, err
	}
	if opts.Recipient == nil {
		return nil, errors.New("xenc: no recipient certificate")
	}
	pub, ok := opts.Recipient.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: RSA-OAEP with a %T key", xmlsec.ErrUnsupportedAlgorithm, opts.Recipient.PublicKey)
	}

	key := opts.SessionKey
	if key == nil {
		key = make([]byte, size)
		rand.Read(key)
	} else if len(key) != size {
		return nil, fmt.Errorf("xenc: session key is %d bytes, %s needs %d", len(key), opts.DataAlgorithm, size)
	}
	wrapped, err := rsa.EncryptOAEPWithOptions(rand.Reader, pub, key, oaep)
	if err != nil {
		return nil, err
	}

	ek := newRoot("EncryptedKey")
	m := encryptionMethod(ek, opts.KeyTransportAlgorithm)
	// Schema order: OAEPparams, then the extension elements.
	if len(opts.OAEPParams) > 0 {
		xmltree.Text(element(m, "OAEPparams"), base64.StdEncoding.EncodeToString(opts.OAEPParams))
	}
	dm := xmltree.Element(m, "ds", NSDSig, "DigestMethod")
	dm.AddNamespace("ds", NSDSig)
	xmltree.SetAttr(dm, "", "", "Algorithm", opts.DigestAlgorithm)
	mgf := xmltree.Element(m, "xenc11", NSXEnc11, "MGF")
	mgf.AddNamespace("xenc11", NSXEnc11)
	xmltree.SetAttr(mgf, "", "", "Algorithm", opts.MGFAlgorithm)
	xmltree.Text(element(element(ek, "CipherData"), "CipherValue"), base64.StdEncoding.EncodeToString(wrapped))

	return &EncryptedKey{Element: ek, SessionKey: key}, nil
}

// DecryptEncryptedKey unwraps a session key from an xenc:EncryptedKey.
//
// The allowed lists restrict the accepted algorithms; an empty list means
// every algorithm this package implements. An absent DigestMethod or MGF
// means SHA-1 by specification default and is refused.
func DecryptEncryptedKey(el *xdm.Node, dec crypto.Decrypter,
	allowedKeyTransport, allowedMGF, allowedDigest []string) ([]byte, error) {

	if el == nil || !el.IsElement(NSXEnc, "EncryptedKey") {
		return nil, malformed("not an xenc:EncryptedKey")
	}
	if dec == nil {
		return nil, errors.New("xenc: no Decrypter")
	}
	kt, m, err := parseEncryptionMethod(el)
	if err != nil {
		return nil, err
	}
	var mgf, digest string
	var label []byte
	for _, k := range m.ChildElements() {
		switch {
		case k.IsElement(NSDSig, "DigestMethod"):
			digest = k.AttrValue("Algorithm")
		case k.IsElement(NSXEnc11, "MGF"):
			mgf = k.AttrValue("Algorithm")
		case k.IsElement(NSXEnc, "OAEPparams"):
			if label, err = xmltree.Base64(k); err != nil {
				return nil, malformed("xenc:OAEPparams: %v", err)
			}
		default:
			return nil, malformed("unexpected %s in xenc:EncryptionMethod", k.Name.Local)
		}
	}
	if mgf == "" || digest == "" {
		return nil, fmt.Errorf("%w: implicit SHA-1 OAEP digest or MGF", xmlsec.ErrAlgorithmNotAllowed)
	}
	_, mgfOK := xmlsec.MGFHash(mgf)
	_, digestOK := xmlsec.DigestHash(digest)
	for _, c := range []error{
		allowed("key transport", kt, allowedKeyTransport, kt == xmlsec.KeyTransportRSAOAEP),
		allowed("MGF", mgf, allowedMGF, mgfOK),
		allowed("OAEP digest", digest, allowedDigest, digestOK),
	} {
		if c != nil {
			return nil, c
		}
	}
	oaep, err := oaepOptions(kt, mgf, digest, label)
	if err != nil {
		return nil, err
	}
	ct, err := cipherValue(el)
	if err != nil {
		return nil, err
	}
	key, err := dec.Decrypt(rand.Reader, ct, oaep)
	if err != nil {
		// No detail: OAEP failure reasons are an oracle.
		return nil, errors.New("xenc: key unwrap failed")
	}
	return key, nil
}

// SetKeyInfo places el, such as a wsse:SecurityTokenReference to the
// recipient's certificate, in a ds:KeyInfo of the EncryptedKey, where a
// receiver looks to find which private key unwraps it.
func (ek *EncryptedKey) SetKeyInfo(el *xdm.Node) error {
	if el == nil || el.Kind != xdm.KindElement || el.Parent != nil {
		return errors.New("xenc: SetKeyInfo needs a detached element")
	}
	for _, k := range ek.Element.ChildElements() {
		if k.IsElement(NSDSig, "KeyInfo") {
			return errors.New("xenc: EncryptedKey already has a ds:KeyInfo")
		}
	}
	ki := xmltree.Element(ek.Element, "ds", NSDSig, "KeyInfo")
	ki.AddNamespace("ds", NSDSig)
	ki.AppendChild(el)
	// Schema order: EncryptionMethod, KeyInfo, CipherData, ReferenceList.
	kids := ek.Element.Children
	copy(kids[2:], kids[1:len(kids)-1])
	kids[1] = ki
	return nil
}

// AddDataReference adds an xenc:DataReference to the EncryptedKey's
// xenc:ReferenceList, creating the list if needed. id is the Id of an
// xenc:EncryptedData this key decrypts; see EncryptOptions.DataID.
func (ek *EncryptedKey) AddDataReference(id string) {
	var list *xdm.Node
	for _, k := range ek.Element.ChildElements() {
		if k.IsElement(NSXEnc, "ReferenceList") {
			list = k
		}
	}
	if list == nil {
		list = element(ek.Element, "ReferenceList")
	}
	xmltree.SetAttr(element(list, "DataReference"), "", "", "URI", "#"+id)
}
