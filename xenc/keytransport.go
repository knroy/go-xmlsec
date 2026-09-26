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

// oaepOptions validates the RSA-OAEP parameters of an encryption.
func oaepOptions(mgf, digest string, label []byte) (*rsa.OAEPOptions, error) {
	mh, ok := xmlsec.MGFHash(mgf)
	if !ok {
		return nil, unsupported("MGF %q", mgf)
	}
	dh, ok := xmlsec.DigestHash(digest)
	if !ok {
		return nil, unsupported("OAEP digest %q", digest)
	}
	return &rsa.OAEPOptions{Hash: dh, MGFHash: mh, Label: label}, nil
}

// GenerateEncryptedKey creates an xenc:EncryptedKey wrapping a fresh
// session key for opts.DataAlgorithm, by opts.KeyTransportAlgorithm:
//
//   - xmlsec.KeyTransportRSAOAEP: RSA-OAEP to the RSA key of
//     opts.Recipient, with an explicit MGF and digest.
//   - a KeyWrap* algorithm and an EC opts.Recipient: AES key wrap under a
//     key agreed by ECDH-ES (opts.KeyAgreementAlgorithm) with an ephemeral
//     key and derived by ConcatKDF with opts.DigestAlgorithm. The
//     xenc:AgreementMethod goes in the EncryptedKey's ds:KeyInfo, with the
//     ephemeral public key as OriginatorKeyInfo and the recipient's
//     certificate as RecipientKeyInfo (section 5.6).
//   - a KeyWrap* algorithm and opts.KeyEncryptionKey: AES key wrap under
//     that shared key.
//
// Except for key agreement, the element carries no ds:KeyInfo; the caller
// adds one identifying the recipient's key in whatever form its profile
// requires. opts.CarriedKeyName and opts.RecipientHint are emitted when set.
func GenerateEncryptedKey(opts EncryptOptions) (*EncryptedKey, error) {
	size, ok := keySizes[opts.DataAlgorithm]
	if !ok {
		return nil, unsupported("data %q", opts.DataAlgorithm)
	}
	key := opts.SessionKey
	if key == nil {
		key = make([]byte, size)
		rand.Read(key)
	} else if len(key) != size {
		return nil, fmt.Errorf("xenc: session key is %d bytes, %s needs %d", len(key), opts.DataAlgorithm, size)
	}

	ek := newRoot("EncryptedKey")
	if opts.RecipientHint != "" {
		xmltree.SetAttr(ek, "", "", "Recipient", opts.RecipientHint)
	}
	m := encryptionMethod(ek, opts.KeyTransportAlgorithm)
	var wrapped []byte
	var err error
	if opts.KeyTransportAlgorithm == xmlsec.KeyTransportRSAOAEP {
		wrapped, err = rsaOAEPWrap(m, key, opts)
	} else {
		wrapped, err = keyWrap(ek, key, opts)
	}
	if err != nil {
		return nil, err
	}
	xmltree.Text(element(element(ek, "CipherData"), "CipherValue"), base64.StdEncoding.EncodeToString(wrapped))
	if opts.CarriedKeyName != "" {
		xmltree.Text(element(ek, "CarriedKeyName"), opts.CarriedKeyName)
	}
	return &EncryptedKey{Element: ek, SessionKey: key}, nil
}

// rsaOAEPWrap encrypts key to opts.Recipient and writes the OAEP
// parameters under the EncryptionMethod m.
func rsaOAEPWrap(m *xdm.Node, key []byte, opts EncryptOptions) ([]byte, error) {
	oaep, err := oaepOptions(opts.MGFAlgorithm, opts.DigestAlgorithm, opts.OAEPParams)
	if err != nil {
		return nil, err
	}
	if opts.Recipient == nil {
		return nil, errors.New("xenc: no recipient certificate")
	}
	pub, ok := opts.Recipient.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, unsupported("RSA-OAEP with a %T key", opts.Recipient.PublicKey)
	}
	wrapped, err := rsa.EncryptOAEPWithOptions(rand.Reader, pub, key, oaep)
	if err != nil {
		return nil, err
	}
	// Schema order: OAEPparams, then the extension elements.
	if len(opts.OAEPParams) > 0 {
		xmltree.Text(element(m, "OAEPparams"), base64.StdEncoding.EncodeToString(opts.OAEPParams))
	}
	xmltree.SetAttr(nsElement(m, "ds", NSDSig, "DigestMethod"), "", "", "Algorithm", opts.DigestAlgorithm)
	xmltree.SetAttr(nsElement(m, "xenc11", NSXEnc11, "MGF"), "", "", "Algorithm", opts.MGFAlgorithm)
	return wrapped, nil
}

// DecryptEncryptedKey unwraps a session key from an xenc:EncryptedKey
// transported by RSA-OAEP. For AES key wrap use UnwrapEncryptedKey, and for
// key agreement DecryptAgreedKey.
//
// The allowed lists restrict the accepted algorithms; an empty list means
// the default set (see the package documentation). The key transport
// algorithm is checked first. An absent DigestMethod or MGF means SHA-1 by
// specification default and is refused. A KeySize under the
// EncryptionMethod must equal the bit length of dec's RSA modulus, the key
// size of RSA-OAEP key transport (section 3.2).
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
	if err := allowed("key transport", kt, allowedKeyTransport, defaultKeyTransport); err != nil {
		return nil, err
	}
	if kt != xmlsec.KeyTransportRSAOAEP {
		return nil, unsupported("key transport %q", kt)
	}
	pub, ok := dec.Public().(*rsa.PublicKey)
	if !ok {
		return nil, unsupported("RSA-OAEP with a %T key", dec.Public())
	}
	p, err := methodParams(m, pub.N.BitLen(),
		xdm.QName{URI: NSDSig, Local: "DigestMethod"}, xdm.QName{URI: NSXEnc11, Local: "MGF"}, xdm.QName{URI: NSXEnc, Local: "OAEPparams"})
	if err != nil {
		return nil, err
	}
	if p["MGF"] == nil || p["DigestMethod"] == nil {
		return nil, fmt.Errorf("%w: implicit SHA-1 OAEP digest or MGF", xmlsec.ErrAlgorithmNotAllowed)
	}
	mgf := p["MGF"].AttrValue("Algorithm")
	if err := allowed("MGF", mgf, allowedMGF, defaultMGF); err != nil {
		return nil, err
	}
	mh, ok := xmlsec.MGFHash(mgf)
	if !ok {
		return nil, unsupported("MGF %q", mgf)
	}
	dh, err := digest("OAEP digest", p["DigestMethod"].AttrValue("Algorithm"), allowedDigest)
	if err != nil {
		return nil, err
	}
	var label []byte
	if k := p["OAEPparams"]; k != nil {
		if label, err = xmltree.Base64(k); err != nil {
			return nil, malformed("xenc:OAEPparams: %v", err)
		}
	}
	ct, err := cipherValue(el)
	if err != nil {
		return nil, err
	}
	key, err := dec.Decrypt(rand.Reader, ct, &rsa.OAEPOptions{Hash: dh, MGFHash: mh, Label: label})
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
	ki := nsElement(ek.Element, "ds", NSDSig, "KeyInfo")
	ki.AppendChild(el)
	// Schema order: EncryptionMethod, KeyInfo, CipherData, ReferenceList,
	// CarriedKeyName.
	kids := ek.Element.Children
	copy(kids[2:], kids[1:len(kids)-1])
	kids[1] = ki
	return nil
}

// AddDataReference adds an xenc:DataReference to the EncryptedKey's
// xenc:ReferenceList, creating the list if needed. id is the Id of an
// xenc:EncryptedData this key decrypts, see EncryptOptions.DataID; it must
// be an NCName.
func (ek *EncryptedKey) AddDataReference(id string) error {
	if !xdm.IsNCName(id) {
		return fmt.Errorf("xenc: data reference %q is not an NCName", id)
	}
	var list, name *xdm.Node
	for _, k := range ek.Element.ChildElements() {
		switch {
		case k.IsElement(NSXEnc, "ReferenceList"):
			list = k
		case k.IsElement(NSXEnc, "CarriedKeyName"):
			name = k
		}
	}
	if list == nil {
		list = element(ek.Element, "ReferenceList")
		if name != nil {
			// Schema order: ReferenceList before CarriedKeyName.
			kids := ek.Element.Children
			kids[len(kids)-2], kids[len(kids)-1] = list, name
		}
	}
	xmltree.SetAttr(element(list, "DataReference"), "", "", "URI", "#"+id)
	return nil
}
