package xenc

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/hashes"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// curveURIs are the dsig11:NamedCurve URIs of the curves ECDH-ES accepts.
var curveURIs = map[ecdh.Curve]string{
	ecdh.P256(): "urn:oid:1.2.840.10045.3.1.7",
	ecdh.P384(): "urn:oid:1.3.132.0.34",
	ecdh.P521(): "urn:oid:1.3.132.0.35",
}

// concatKDF is the single-step key derivation of NIST SP 800-56A section
// 5.8.1 with a hash: size octets of H(counter || z || otherInfo), counter
// from 1, 32-bit big-endian.
func concatKDF(h crypto.Hash, z, otherInfo []byte, size int) []byte {
	var out []byte
	for counter := uint32(1); len(out) < size; counter++ {
		d := h.New()
		d.Write(binary.BigEndian.AppendUint32(nil, counter))
		d.Write(z)
		d.Write(otherInfo)
		out = d.Sum(out)
	}
	return out[:size]
}

// kdfParams are the ConcatKDFParams attributes, concatenated in this order
// to form OtherInfo.
var kdfParams = []string{"AlgorithmID", "PartyUInfo", "PartyVInfo", "SuppPubInfo", "SuppPrivInfo"}

// otherInfo decodes and concatenates the ConcatKDFParams attributes. Each
// is hexBinary whose first octet counts the padding bits of the last
// (section 5.4.1); only byte-aligned strings are accepted, as xmlsec1 and
// Santuario do, and the count octet is dropped. An absent or empty
// attribute is the empty string.
func otherInfo(p *xdm.Node) ([]byte, error) {
	var out []byte
	for _, name := range kdfParams {
		v := p.AttrValue(name)
		if v == "" {
			continue
		}
		b, err := hex.DecodeString(v)
		if err != nil || b[0] != 0 {
			return nil, unsupported("ConcatKDFParams %s %q: only a byte-aligned hexBinary bit string is supported", name, v)
		}
		out = append(out, b[1:]...)
	}
	return out, nil
}

// agree derives a key of size octets for alg, a key wrap or data
// algorithm, and opts.Recipient's EC key by ECDH-ES with a fresh ephemeral
// key and ConcatKDF, and adds the ds:KeyInfo holding the
// xenc:AgreementMethod to ek, an EncryptedKey or EncryptedData.
func agree(ek *xdm.Node, alg string, size int, opts EncryptOptions) ([]byte, error) {
	if opts.KeyAgreementAlgorithm != xmlsec.KeyAgreementECDHES {
		return nil, unsupported("key agreement %q", opts.KeyAgreementAlgorithm)
	}
	pub, ok := opts.Recipient.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, unsupported("ECDH-ES with a %T key", opts.Recipient.PublicKey)
	}
	rpub, err := pub.ECDH()
	if err != nil {
		return nil, unsupported("ECDH-ES on %s: %v", pub.Curve.Params().Name, err)
	}
	h, ok := hashes.Digest(opts.DigestAlgorithm)
	if !ok {
		return nil, unsupported("ConcatKDF digest %q", opts.DigestAlgorithm)
	}
	// Neither can fail: crypto/rand does not fail, and both keys are on
	// the same NIST curve.
	eph, _ := rpub.Curve().GenerateKey(rand.Reader)
	z, _ := eph.ECDH(rpub)
	kek := concatKDF(h, z, []byte(alg), size)

	am := newAgreementMethod(ek, xmlsec.KeyAgreementECDHES)
	concatKDFMethod(am, alg, nil, opts.DigestAlgorithm)
	kv := xmltree.Element(element(am, "OriginatorKeyInfo"), "ds", xmlsec.NSDSig, "KeyValue")
	ec := nsElement(kv, "dsig11", xmlsec.NSDSig11, "ECKeyValue")
	xmltree.SetAttr(xmltree.Element(ec, "dsig11", xmlsec.NSDSig11, "NamedCurve"), "", "", "URI", curveURIs[rpub.Curve()])
	xmltree.Text(xmltree.Element(ec, "dsig11", xmlsec.NSDSig11, "PublicKey"), base64.StdEncoding.EncodeToString(eph.PublicKey().Bytes()))
	x509 := xmltree.Element(element(am, "RecipientKeyInfo"), "ds", xmlsec.NSDSig, "X509Data")
	xmltree.Text(xmltree.Element(x509, "ds", xmlsec.NSDSig, "X509Certificate"), base64.StdEncoding.EncodeToString(opts.Recipient.Raw))
	return kek, nil
}

// newAgreementMethod adds to ek a ds:KeyInfo holding an
// xenc:AgreementMethod of alg, and returns the AgreementMethod.
func newAgreementMethod(ek *xdm.Node, alg string) *xdm.Node {
	am := element(nsElement(ek, "ds", xmlsec.NSDSig, "KeyInfo"), "AgreementMethod")
	xmltree.SetAttr(am, "", "", "Algorithm", alg)
	return am
}

// concatKDFMethod adds to parent the xenc11:KeyDerivationMethod of a
// ConcatKDF with digest. AlgorithmID names alg, the algorithm the key is
// for; PartyUInfo is partyU, and PartyVInfo is present and empty. Santuario
// refuses a lone "00" octet, which the specification allows, so
// AlgorithmID is not empty, and an empty PartyUInfo is written empty.
func concatKDFMethod(parent *xdm.Node, alg string, partyU []byte, digest string) {
	kdm := nsElement(parent, "xenc11", xmlsec.NSXEnc11, "KeyDerivationMethod")
	xmltree.SetAttr(kdm, "", "", "Algorithm", xmlsec.KeyDerivationConcatKDF)
	params := xmltree.Element(kdm, "xenc11", xmlsec.NSXEnc11, "ConcatKDFParams")
	xmltree.SetAttr(params, "", "", "AlgorithmID", "00"+hex.EncodeToString([]byte(alg)))
	u := ""
	if partyU != nil {
		u = "00" + hex.EncodeToString(partyU)
	}
	xmltree.SetAttr(params, "", "", "PartyUInfo", u)
	xmltree.SetAttr(params, "", "", "PartyVInfo", "")
	xmltree.SetAttr(xmltree.Element(params, "ds", xmlsec.NSDSig, "DigestMethod"), "", "", "Algorithm", digest)
}

// only returns the single element child of n, which must be named uri,
// local.
func only(n *xdm.Node, uri, local string) (*xdm.Node, error) {
	kids := n.ChildElements()
	if len(kids) != 1 || !kids[0].IsElement(uri, local) {
		return nil, malformed("%s must hold exactly one %s", n.Name.Local, local)
	}
	return kids[0], nil
}

// keyValue returns the one ds:KeyValue of an OriginatorKeyInfo. A
// ds:KeyName beside it, as xmlsec1 writes when its template names the
// originator key, is ignored.
func keyValue(oki *xdm.Node) (*xdm.Node, error) {
	var kv *xdm.Node
	for _, k := range oki.ChildElements() {
		switch {
		case k.IsElement(xmlsec.NSDSig, "KeyName"):
		case k.IsElement(xmlsec.NSDSig, "KeyValue") && kv == nil:
			kv = k
		default:
			return nil, malformed("OriginatorKeyInfo must hold one ds:KeyValue, and at most ds:KeyName beside it")
		}
	}
	if kv == nil {
		return nil, malformed("OriginatorKeyInfo without ds:KeyValue")
	}
	return kv, nil
}

// originatorKey reads the originator's public key from
// OriginatorKeyInfo/ds:KeyValue/dsig11:ECKeyValue, which must name one of
// the accepted curves.
func originatorKey(oki *xdm.Node) (*ecdh.PublicKey, error) {
	kv, err := keyValue(oki)
	if err != nil {
		return nil, err
	}
	ec, err := only(kv, xmlsec.NSDSig11, "ECKeyValue")
	if err != nil {
		return nil, err
	}
	kids := ec.ChildElements()
	if len(kids) != 2 || !kids[0].IsElement(xmlsec.NSDSig11, "NamedCurve") || !kids[1].IsElement(xmlsec.NSDSig11, "PublicKey") {
		return nil, malformed("dsig11:ECKeyValue must hold dsig11:NamedCurve, then dsig11:PublicKey")
	}
	uri := kids[0].AttrValue("URI")
	for curve, u := range curveURIs {
		if u == uri {
			b, err := xmltree.Base64(kids[1])
			if err != nil {
				return nil, malformed("dsig11:PublicKey: %v", err)
			}
			pub, err := curve.NewPublicKey(b)
			if err != nil {
				return nil, malformed("dsig11:PublicKey: %v", err)
			}
			return pub, nil
		}
	}
	return nil, fmt.Errorf("%w: curve %q", xmlsec.ErrUnsupportedKeyInfo, uri)
}

// agreed is an xenc:EncryptedKey whose KEK is agreed, or an
// xenc:EncryptedData whose key is, as the Decrypt functions receive it: its
// key wrap or data algorithm and that algorithm's key size, the allowed
// agreement algorithm, and the children of its xenc:AgreementMethod, each
// present at most once.
type agreed struct {
	alg, agreement             string
	size                       int
	nonce, digest, kdm, origin *xdm.Node
}

// parseAgreed reads el, an xenc:EncryptedKey, or with data an
// xenc:EncryptedData, whose ds:KeyInfo holds exactly one
// xenc:AgreementMethod with an OriginatorKeyInfo, and checks its wrap or
// data algorithm and its agreement algorithm against opts.
// RecipientKeyInfo is ignored: the private key is the caller's choice.
// noKey reports a nil private key, refused once the wrap or data algorithm
// is checked.
func parseAgreed(el *xdm.Node, data, noKey bool, opts DecryptOptions) (*agreed, error) {
	a := &agreed{}
	var err error
	if data {
		a.alg, err = dataAlgorithm(el, opts)
		a.size, _ = dataKeySize(a.alg)
	} else {
		a.alg, err = wrapMethod(el, opts)
		a.size, _ = wrapSize(a.alg)
	}
	if err != nil {
		return nil, err
	}
	if noKey {
		return nil, errors.New("xenc: no private key")
	}
	ki := keyInfo(el)
	if ki == nil {
		return nil, fmt.Errorf("%w: no ds:KeyInfo holding an xenc:AgreementMethod", xmlsec.ErrUnsupportedKeyInfo)
	}
	am, err := only(ki, xmlsec.NSXEnc, "AgreementMethod")
	if err != nil {
		return nil, err
	}
	a.agreement = am.AttrValue("Algorithm")
	if err := allowed("key agreement", a.agreement, opts.AllowedKeyAgreementAlgorithms, defaultAgreement); err != nil {
		return nil, err
	}
	for _, k := range am.ChildElements() {
		switch {
		case k.IsElement(xmlsec.NSXEnc, "KA-Nonce") && a.nonce == nil:
			a.nonce = k
		case k.IsElement(xmlsec.NSDSig, "DigestMethod") && a.digest == nil:
			a.digest = k
		case k.IsElement(xmlsec.NSXEnc11, "KeyDerivationMethod") && a.kdm == nil:
			a.kdm = k
		case k.IsElement(xmlsec.NSXEnc, "OriginatorKeyInfo") && a.origin == nil:
			a.origin = k
		case k.IsElement(xmlsec.NSXEnc, "RecipientKeyInfo"):
		default:
			return nil, malformed("unexpected %s in xenc:AgreementMethod", k.Name.Local)
		}
	}
	if a.origin == nil {
		return nil, malformed("xenc:AgreementMethod without xenc:OriginatorKeyInfo")
	}
	return a, nil
}

// explicitKDF returns the key derivation of an agreement with an explicit
// xenc11:KeyDerivationMethod (ECDH-ES and dh-es), which takes no Legacy
// KDF ds:DigestMethod. A KA-Nonce, which the schema allows, is ignored:
// neither ConcatKDF nor PBKDF2 defines a use for it (section 5.6).
func (a *agreed) explicitKDF(opts DecryptOptions) (func([]byte) []byte, error) {
	if a.digest != nil || a.kdm == nil {
		return nil, malformed("xenc:AgreementMethod of %s needs an xenc11:KeyDerivationMethod, and takes no ds:DigestMethod", a.agreement)
	}
	return keyDerivation(a.kdm, a.size, opts)
}

// keyDerivation checks an xenc11:KeyDerivationMethod against opts and
// returns the function deriving a key of size octets from a secret: the
// ConcatKDF of section 5.4.1 or the PBKDF2 of section 5.4.2. Every
// parameter is checked here, before any cryptographic work.
func keyDerivation(kdm *xdm.Node, size int, opts DecryptOptions) (func([]byte) []byte, error) {
	alg := kdm.AttrValue("Algorithm")
	if err := allowed("key derivation", alg, opts.AllowedKeyDerivationAlgorithms, defaultDerivation); err != nil {
		return nil, err
	}
	switch alg {
	case xmlsec.KeyDerivationConcatKDF:
		return concatKDFParams(kdm, size, opts)
	case xmlsec.KeyDerivationPBKDF2:
		return pbkdf2Params(kdm, size, opts)
	}
	return nil, unsupported("key derivation %q", alg)
}

// concatKDFParams reads the xenc11:ConcatKDFParams of kdm.
func concatKDFParams(kdm *xdm.Node, size int, opts DecryptOptions) (func([]byte) []byte, error) {
	params, err := only(kdm, xmlsec.NSXEnc11, "ConcatKDFParams")
	if err != nil {
		return nil, err
	}
	dm, err := only(params, xmlsec.NSDSig, "DigestMethod")
	if err != nil {
		return nil, err
	}
	h, err := digest("ConcatKDF digest", dm.AttrValue("Algorithm"), opts.AllowedDigestAlgorithms)
	if err != nil {
		return nil, err
	}
	info, err := otherInfo(params)
	if err != nil {
		return nil, err
	}
	return func(z []byte) []byte { return concatKDF(h, z, info, size) }, nil
}

// DecryptAgreedKey unwraps a session key from an xenc:EncryptedKey whose
// key encryption key is agreed: AES key wrap under a KEK derived by ECDH-ES
// between priv, the recipient's static key, and the originator's ephemeral
// key, then ConcatKDF (sections 5.6.4 and 5.4.1). The EncryptedKey's
// ds:KeyInfo must hold exactly one xenc:AgreementMethod, with an
// xenc11:KeyDerivationMethod and an OriginatorKeyInfo holding a
// ds:KeyValue/dsig11:ECKeyValue on priv's curve. RecipientKeyInfo is
// ignored: priv is the caller's choice. A KA-Nonce is ignored: ConcatKDF
// defines no use for it.
//
// opts' key wrap, key agreement and digest lists restrict the key wrap,
// key agreement and ConcatKDF digest algorithms. Its key derivation list
// restricts the KDF: PBKDF2 (section 5.4.2), with the shared secret as its
// password, is accepted only when named there, and its PRF only from
// AllowedPRFAlgorithms. Callers with an *ecdsa.PrivateKey pass its ECDH().
// For finite-field Diffie-Hellman use DecryptAgreedKeyDH, and for an
// AgreementMethod directly under an EncryptedData DecryptAgreedDataKey.
func DecryptAgreedKey(el *xdm.Node, priv *ecdh.PrivateKey, opts DecryptOptions) ([]byte, error) {
	if err := strictKey(el, opts); err != nil {
		return nil, err
	}
	a, kek, err := agreedECDH(el, false, priv, opts)
	if err != nil {
		return nil, err
	}
	return unwrap(el, a.alg, kek, opts)
}

// DecryptAgreedDataKey returns the key of ed, an xenc:EncryptedData whose
// ds:KeyInfo holds an xenc:AgreementMethod directly, with no EncryptedKey
// (section 5.6): the key ECDH-ES between priv and the originator's key
// agrees, derived to the size of ed's data algorithm, which is checked
// against opts.AllowedDataAlgorithms first. Everything else is as for
// DecryptAgreedKey. Decrypt ed with the result by DecryptData.
func DecryptAgreedDataKey(ed *xdm.Node, priv *ecdh.PrivateKey, opts DecryptOptions) ([]byte, error) {
	if err := strictData(ed, opts); err != nil {
		return nil, err
	}
	_, key, err := agreedECDH(ed, true, priv, opts)
	return key, err
}

// agreedECDH parses el, an EncryptedKey or with data an EncryptedData,
// and returns the key ECDH-ES agrees for it with priv.
func agreedECDH(el *xdm.Node, data bool, priv *ecdh.PrivateKey, opts DecryptOptions) (*agreed, []byte, error) {
	a, err := parseAgreed(el, data, priv == nil, opts)
	if err != nil {
		return nil, nil, err
	}
	if a.agreement != xmlsec.KeyAgreementECDHES {
		return nil, nil, unsupported("key agreement %q", a.agreement)
	}
	kdf, err := a.explicitKDF(opts)
	if err != nil {
		return nil, nil, err
	}
	pub, err := originatorKey(a.origin)
	if err != nil {
		return nil, nil, err
	}
	z, err := priv.ECDH(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: originator key: %v", xmlsec.ErrUnsupportedKeyInfo, err)
	}
	return a, kdf(z), nil
}
