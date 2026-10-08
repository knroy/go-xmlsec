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
	"github.com/knroy/go-xmlsec/internal/hashes"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// EncryptedKey is a generated xenc:EncryptedKey plus the session key it wraps.
type EncryptedKey struct {
	// Element is the xenc:EncryptedKey to place in the security header.
	Element *xdm.Node

	// SessionKey is the symmetric key the EncryptedKey wraps. Pass it to
	// every Encrypt call whose data this EncryptedKey is to cover: several
	// EncryptedData and attachment bodies can share one EncryptedKey.
	//
	// Callers should zero this when done.
	SessionKey []byte
}

// oaepOptions validates the RSA-OAEP parameters of an encryption.
func oaepOptions(mgf, digest string, label []byte) (*rsa.OAEPOptions, error) {
	mh, ok := hashes.MGF(mgf)
	if !ok {
		return nil, unsupported("MGF %q", mgf)
	}
	dh, ok := encDigest(digest)
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
//   - a KeyWrap* algorithm and opts.RecipientDH: AES key wrap under a key
//     agreed by finite-field Diffie-Hellman with an ephemeral key in the
//     recipient's group, xmlsec.KeyAgreementDHES with ConcatKDF or
//     xmlsec.KeyAgreementDH with the Legacy KDF, each with
//     opts.DigestAlgorithm. The OriginatorKeyInfo holds the ephemeral
//     xenc:DHKeyValue with its group, and the RecipientKeyInfo the
//     recipient's public value.
//   - a KeyWrap* algorithm and opts.Password: AES key wrap under a key
//     derived by PBKDF2 with HMAC-SHA256, a fresh salt and
//     opts.PBKDF2Iterations, named by an xenc11:DerivedKey in the
//     EncryptedKey's ds:KeyInfo.
//   - a KeyWrap* algorithm and opts.KeyEncryptionKey: AES key wrap under
//     that shared key.
//
// Except for key agreement and a password, the element carries no ds:KeyInfo; the caller
// adds one identifying the recipient's key in whatever form its profile
// requires. opts.CarriedKeyName and opts.RecipientHint are emitted when set.
//
// For WS-Security output that conforms to the WS-I Basic Security Profile,
// use RSA-OAEP and give the EncryptedKey, with SetKeyInfo, a ds:KeyInfo
// holding one wsse:SecurityTokenReference (R5424, R5426), and no
// RecipientHint (R5602). The ds:KeyInfo that key agreement or a password
// produces, an xenc:AgreementMethod or xenc11:DerivedKey, is outside the
// profile.
//
// A legacy algorithm (see the package documentation) in any of opts'
// algorithm fields is refused with xmlsec.ErrUnsupportedAlgorithm: those are
// implemented for decryption only. An option that does not apply to the
// EncryptedKey made, or contradicts another, is refused before any
// cryptographic work, as EncryptOptions documents.
func GenerateEncryptedKey(opts EncryptOptions) (*EncryptedKey, error) {
	if err := encryptable(opts.DataAlgorithm, opts.KeyTransportAlgorithm, opts.MGFAlgorithm, opts.DigestAlgorithm); err != nil {
		return nil, err
	}
	if err := inapplicable(opts); err != nil {
		return nil, err
	}
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

// inapplicable refuses, before any cryptographic work, options that have
// no effect on the EncryptedKey GenerateEncryptedKey makes under opts, or
// contradict it: see EncryptOptions.
func inapplicable(opts EncryptOptions) error {
	keys := 0
	for _, set := range []bool{opts.Recipient != nil, opts.KeyEncryptionKey != nil, opts.RecipientDH != nil, len(opts.Password) > 0} {
		if set {
			keys++
		}
	}
	if keys > 1 {
		return errors.New("xenc: more than one of Recipient, RecipientDH, KeyEncryptionKey and Password")
	}
	oaep := opts.KeyTransportAlgorithm == xmlsec.KeyTransportRSAOAEP
	agreed := !oaep && (opts.Recipient != nil || opts.RecipientDH != nil)
	for _, f := range []struct {
		name         string
		set, applies bool
	}{
		{"KeyEncryptionKey", opts.KeyEncryptionKey != nil, !oaep},
		{"Password", len(opts.Password) > 0, !oaep},
		{"RecipientDH", opts.RecipientDH != nil, !oaep},
		{"MGFAlgorithm", opts.MGFAlgorithm != "", oaep},
		{"OAEPParams", len(opts.OAEPParams) > 0, oaep},
		{"DigestAlgorithm", opts.DigestAlgorithm != "", oaep || agreed},
		{"KeyAgreementAlgorithm", opts.KeyAgreementAlgorithm != "", agreed},
		{"RecipientKeyName", opts.RecipientKeyName != "", agreed && opts.RecipientDH != nil},
		{"MasterKey", opts.MasterKey != nil, false},
		{"DirectKeyAgreement", opts.DirectKeyAgreement, false},
	} {
		if f.set && !f.applies {
			return fmt.Errorf("xenc: EncryptOptions.%s does not apply to an EncryptedKey by %s with this key", f.name, opts.KeyTransportAlgorithm)
		}
	}
	return pbkdf2Iterations(opts)
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
	xmltree.SetAttr(nsElement(m, "ds", xmlsec.NSDSig, "DigestMethod"), "", "", "Algorithm", opts.DigestAlgorithm)
	xmltree.SetAttr(nsElement(m, "xenc11", xmlsec.NSXEnc11, "MGF"), "", "", "Algorithm", opts.MGFAlgorithm)
	return wrapped, nil
}

// DecryptEncryptedKey unwraps a session key from an xenc:EncryptedKey
// transported by RSA-OAEP. For AES key wrap use UnwrapEncryptedKey, for key
// agreement DecryptAgreedKey, and for RSA v1.5 DecryptEncryptedKeyPKCS1v15.
//
// opts' key transport, MGF and digest lists restrict the accepted
// algorithms, the key transport algorithm first. An absent DigestMethod or
// MGF means SHA-1 by specification default (section 5.5.2), and is accepted
// only when AllowedDigestAlgorithms names xmlsec.DigestSHA1 or
// AllowedMGFAlgorithms names xmlsec.MGF1SHA1, exactly as an explicit SHA-1
// is. The legacy xmlsec.KeyTransportRSAOAEPMGF1P, decrypted only when
// AllowedKeyTransportAlgorithms names it, fixes MGF1 with SHA-1, so it also
// needs xmlsec.MGF1SHA1 in AllowedMGFAlgorithms, and must not carry an
// xenc11:MGF. A KeySize under the
// EncryptionMethod must equal the bit length of dec's RSA modulus, the key
// size of RSA-OAEP key transport (section 3.2). The wrapped key may be
// named by an xenc:CipherReference, as for UnwrapEncryptedKey.
func DecryptEncryptedKey(el *xdm.Node, dec crypto.Decrypter, opts DecryptOptions) ([]byte, error) {
	if err := strictKey(el, opts); err != nil {
		return nil, err
	}
	if el == nil || !el.IsElement(xmlsec.NSXEnc, "EncryptedKey") {
		return nil, malformed("not an xenc:EncryptedKey")
	}
	if dec == nil {
		return nil, errors.New("xenc: no Decrypter")
	}
	kt, m, err := parseEncryptionMethod(el, opts.ImpliedKeyTransportAlgorithm)
	if err != nil {
		return nil, err
	}
	if err := allowed("key transport", kt, opts.AllowedKeyTransportAlgorithms, defaultKeyTransport); err != nil {
		return nil, err
	}
	permitted := []xdm.QName{{URI: xmlsec.NSDSig, Local: "DigestMethod"}, {URI: xmlsec.NSXEnc, Local: "OAEPparams"}}
	switch kt {
	case xmlsec.KeyTransportRSAOAEP:
		permitted = append(permitted, xdm.QName{URI: xmlsec.NSXEnc11, Local: "MGF"})
	case xmlsec.KeyTransportRSAOAEPMGF1P:
		// Section 5.5.2: xenc11:MGF MUST NOT be provided.
	case xmlsec.KeyTransportRSA15:
		return nil, unsupported("key transport %q: use DecryptEncryptedKeyPKCS1v15", kt)
	default:
		return nil, unsupported("key transport %q", kt)
	}
	pub, ok := dec.Public().(*rsa.PublicKey)
	if !ok {
		return nil, unsupported("RSA-OAEP with a %T key", dec.Public())
	}
	p, err := methodParams(m, pub.N.BitLen(), permitted...)
	if err != nil {
		return nil, err
	}
	mgf, mgfKind := xmlsec.MGF1SHA1, "implicit MGF"
	if k := p["MGF"]; k != nil {
		mgf, mgfKind = k.AttrValue("Algorithm"), "MGF"
	}
	if err := allowed(mgfKind, mgf, opts.AllowedMGFAlgorithms, defaultMGF); err != nil {
		return nil, err
	}
	mh, ok := mgfHash(mgf)
	if !ok {
		return nil, unsupported("MGF %q", mgf)
	}
	dm, dmKind := xmlsec.DigestSHA1, "implicit OAEP digest"
	if k := p["DigestMethod"]; k != nil {
		dm, dmKind = k.AttrValue("Algorithm"), "OAEP digest"
	}
	dh, err := digest(dmKind, dm, opts.AllowedDigestAlgorithms)
	if err != nil {
		return nil, err
	}
	var label []byte
	if k := p["OAEPparams"]; k != nil {
		if label, err = xmltree.Base64(k); err != nil {
			return nil, malformed("xenc:OAEPparams: %v", err)
		}
	}
	ct, err := keyCiphertext(el, opts)
	if err != nil {
		return nil, err
	}
	key, err := dec.Decrypt(rand.Reader, ct, &rsa.OAEPOptions{Hash: dh, MGFHash: mh, Label: label})
	if err != nil {
		// No detail: OAEP failure reasons are an oracle.
		return nil, errUnwrap
	}
	return key, nil
}

// check refuses a nil EncryptedKey, or one whose Element is not an
// xenc:EncryptedKey, such as the zero value.
func (ek *EncryptedKey) check() error {
	if ek == nil || ek.Element == nil || !ek.Element.IsElement(xmlsec.NSXEnc, "EncryptedKey") {
		return errors.New("xenc: EncryptedKey without an xenc:EncryptedKey Element")
	}
	return nil
}

// SetKeyInfo places el, such as a wsse:SecurityTokenReference to the
// recipient's certificate, in a ds:KeyInfo of the EncryptedKey, where a
// receiver looks to find which private key unwraps it.
func (ek *EncryptedKey) SetKeyInfo(el *xdm.Node) error {
	if err := ek.check(); err != nil {
		return err
	}
	if el == nil || el.Kind != xdm.KindElement || el.Parent != nil {
		return errors.New("xenc: SetKeyInfo needs a detached element")
	}
	for _, k := range ek.Element.ChildElements() {
		if k.IsElement(xmlsec.NSDSig, "KeyInfo") {
			return errors.New("xenc: EncryptedKey already has a ds:KeyInfo")
		}
	}
	newKeyInfo(ek.Element).AppendChild(el)
	return nil
}

// AddDataReference adds an xenc:DataReference to the EncryptedKey's
// xenc:ReferenceList, creating the list if needed. id is the Id of an
// xenc:EncryptedData this key decrypts, see EncryptOptions.DataID; it must
// be an NCName.
func (ek *EncryptedKey) AddDataReference(id string) error {
	if err := ek.check(); err != nil {
		return err
	}
	if !xdm.IsNCName(id) {
		return fmt.Errorf("xenc: data reference %q is not an NCName", id)
	}
	var list *xdm.Node
	for _, k := range ek.Element.ChildElements() {
		if k.IsElement(xmlsec.NSXEnc, "ReferenceList") {
			list = k
		}
	}
	if list == nil {
		list = element(ek.Element, "ReferenceList")
		place(ek.Element)
	}
	xmltree.SetAttr(element(list, "DataReference"), "", "", "URI", "#"+id)
	return nil
}
