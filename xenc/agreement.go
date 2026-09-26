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

// agree derives a KEK of size octets for opts.Recipient's EC key by ECDH-ES
// with a fresh ephemeral key and ConcatKDF, and adds the ds:KeyInfo holding
// the xenc:AgreementMethod to ek.
func agree(ek *xdm.Node, size int, opts EncryptOptions) ([]byte, error) {
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
	h, ok := xmlsec.DigestHash(opts.DigestAlgorithm)
	if !ok {
		return nil, unsupported("ConcatKDF digest %q", opts.DigestAlgorithm)
	}
	// Neither can fail: crypto/rand does not fail, and both keys are on
	// the same NIST curve.
	eph, _ := rpub.Curve().GenerateKey(rand.Reader)
	z, _ := eph.ECDH(rpub)

	// AlgorithmID names the wrap algorithm the KEK is for. PartyUInfo and
	// PartyVInfo are present and empty. Santuario refuses a lone "00"
	// octet, which the specification allows, so AlgorithmID is not empty.
	algID := "00" + hex.EncodeToString([]byte(opts.KeyTransportAlgorithm))
	kek := concatKDF(h, z, []byte(opts.KeyTransportAlgorithm), size)

	ki := nsElement(ek, "ds", NSDSig, "KeyInfo")
	am := element(ki, "AgreementMethod")
	xmltree.SetAttr(am, "", "", "Algorithm", xmlsec.KeyAgreementECDHES)
	kdm := nsElement(am, "xenc11", NSXEnc11, "KeyDerivationMethod")
	xmltree.SetAttr(kdm, "", "", "Algorithm", xmlsec.KeyDerivationConcatKDF)
	params := xmltree.Element(kdm, "xenc11", NSXEnc11, "ConcatKDFParams")
	xmltree.SetAttr(params, "", "", "AlgorithmID", algID)
	xmltree.SetAttr(params, "", "", "PartyUInfo", "")
	xmltree.SetAttr(params, "", "", "PartyVInfo", "")
	xmltree.SetAttr(xmltree.Element(params, "ds", NSDSig, "DigestMethod"), "", "", "Algorithm", opts.DigestAlgorithm)

	kv := xmltree.Element(element(am, "OriginatorKeyInfo"), "ds", NSDSig, "KeyValue")
	ec := nsElement(kv, "dsig11", nsDSig11, "ECKeyValue")
	xmltree.SetAttr(xmltree.Element(ec, "dsig11", nsDSig11, "NamedCurve"), "", "", "URI", curveURIs[rpub.Curve()])
	xmltree.Text(xmltree.Element(ec, "dsig11", nsDSig11, "PublicKey"), base64.StdEncoding.EncodeToString(eph.PublicKey().Bytes()))
	x509 := xmltree.Element(element(am, "RecipientKeyInfo"), "ds", NSDSig, "X509Data")
	xmltree.Text(xmltree.Element(x509, "ds", NSDSig, "X509Certificate"), base64.StdEncoding.EncodeToString(opts.Recipient.Raw))
	return kek, nil
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

// originatorKey reads the originator's public key from
// OriginatorKeyInfo/ds:KeyValue/dsig11:ECKeyValue, which must name one of
// the accepted curves. A ds:KeyName beside the ds:KeyValue, as xmlsec1
// writes when its template names the originator key, is ignored.
func originatorKey(oki *xdm.Node) (*ecdh.PublicKey, error) {
	var kv *xdm.Node
	for _, k := range oki.ChildElements() {
		switch {
		case k.IsElement(NSDSig, "KeyName"):
		case k.IsElement(NSDSig, "KeyValue") && kv == nil:
			kv = k
		default:
			return nil, malformed("OriginatorKeyInfo must hold one ds:KeyValue, and at most ds:KeyName beside it")
		}
	}
	if kv == nil {
		return nil, malformed("OriginatorKeyInfo without ds:KeyValue")
	}
	ec, err := only(kv, nsDSig11, "ECKeyValue")
	if err != nil {
		return nil, err
	}
	kids := ec.ChildElements()
	if len(kids) != 2 || !kids[0].IsElement(nsDSig11, "NamedCurve") || !kids[1].IsElement(nsDSig11, "PublicKey") {
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

// DecryptAgreedKey unwraps a session key from an xenc:EncryptedKey whose
// key encryption key is agreed: AES key wrap under a KEK derived by ECDH-ES
// between priv, the recipient's static key, and the originator's ephemeral
// key, then ConcatKDF (sections 5.6.4 and 5.4.1). The EncryptedKey's
// ds:KeyInfo must hold exactly one xenc:AgreementMethod, with an
// xenc11:KeyDerivationMethod and an OriginatorKeyInfo holding a
// ds:KeyValue/dsig11:ECKeyValue on priv's curve. RecipientKeyInfo is
// ignored: priv is the caller's choice. A KA-Nonce is refused.
//
// The allowed lists restrict the key wrap, key agreement and ConcatKDF
// digest algorithms; an empty list means the default set. Callers with an
// *ecdsa.PrivateKey pass its ECDH().
func DecryptAgreedKey(el *xdm.Node, priv *ecdh.PrivateKey,
	allowedKeyWrap, allowedAgreement, allowedDigest []string) ([]byte, error) {

	alg, err := wrapMethod(el, allowedKeyWrap)
	if err != nil {
		return nil, err
	}
	if priv == nil {
		return nil, errors.New("xenc: no private key")
	}
	kids := el.ChildElements()
	if len(kids) < 2 || !kids[1].IsElement(NSDSig, "KeyInfo") {
		return nil, fmt.Errorf("%w: no ds:KeyInfo holding an xenc:AgreementMethod", xmlsec.ErrUnsupportedKeyInfo)
	}
	am, err := only(kids[1], NSXEnc, "AgreementMethod")
	if err != nil {
		return nil, err
	}
	agreement := am.AttrValue("Algorithm")
	if err := allowed("key agreement", agreement, allowedAgreement, defaultAgreement); err != nil {
		return nil, err
	}
	if agreement != xmlsec.KeyAgreementECDHES {
		return nil, unsupported("key agreement %q", agreement)
	}
	var kdm, oki *xdm.Node
	for _, k := range am.ChildElements() {
		switch {
		case k.IsElement(NSXEnc11, "KeyDerivationMethod") && kdm == nil:
			kdm = k
		case k.IsElement(NSXEnc, "OriginatorKeyInfo") && oki == nil:
			oki = k
		case k.IsElement(NSXEnc, "RecipientKeyInfo"):
		default:
			return nil, malformed("unexpected %s in xenc:AgreementMethod", k.Name.Local)
		}
	}
	if kdm == nil || oki == nil {
		return nil, malformed("xenc:AgreementMethod needs xenc11:KeyDerivationMethod and xenc:OriginatorKeyInfo")
	}
	if kdf := kdm.AttrValue("Algorithm"); kdf != xmlsec.KeyDerivationConcatKDF {
		return nil, unsupported("key derivation %q", kdf)
	}
	params, err := only(kdm, NSXEnc11, "ConcatKDFParams")
	if err != nil {
		return nil, err
	}
	dm, err := only(params, NSDSig, "DigestMethod")
	if err != nil {
		return nil, err
	}
	h, err := digest("ConcatKDF digest", dm.AttrValue("Algorithm"), allowedDigest)
	if err != nil {
		return nil, err
	}
	info, err := otherInfo(params)
	if err != nil {
		return nil, err
	}
	pub, err := originatorKey(oki)
	if err != nil {
		return nil, err
	}
	z, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: originator key: %v", xmlsec.ErrUnsupportedKeyInfo, err)
	}
	return unwrap(el, alg, concatKDF(h, z, info, wrapSizes[alg]))
}
