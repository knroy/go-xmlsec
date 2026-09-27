package xenc

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/hashes"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// partyUSize is the length of the fresh PartyUInfo a MasterKey derivation
// carries, so that no two derived keys are the same.
const partyUSize = 16

// derivedKeyMethod returns the xenc11:KeyDerivationMethod of dk, an
// xenc11:DerivedKey. Beside it the schema allows an xenc:ReferenceList, a
// DerivedKeyName and a MasterKeyName (section 3.5.2), which are ignored
// here: the master key is the caller's choice.
func derivedKeyMethod(dk *xdm.Node) (*xdm.Node, error) {
	if dk == nil || !dk.IsElement(xmlsec.NSXEnc11, "DerivedKey") {
		return nil, malformed("not an xenc11:DerivedKey")
	}
	var kdm *xdm.Node
	for _, k := range dk.ChildElements() {
		switch {
		case k.IsElement(xmlsec.NSXEnc11, "KeyDerivationMethod") && kdm == nil:
			kdm = k
		case k.IsElement(xmlsec.NSXEnc, "ReferenceList"),
			k.IsElement(xmlsec.NSXEnc11, "MasterKeyName"), k.IsElement(xmlsec.NSXEnc11, "DerivedKeyName"):
		default:
			return nil, malformed("unexpected %s in xenc11:DerivedKey", k.Name.Local)
		}
	}
	if kdm == nil {
		return nil, malformed("xenc11:DerivedKey without xenc11:KeyDerivationMethod")
	}
	return kdm, nil
}

// DeriveKey derives from master the key that dk, an xenc11:DerivedKey,
// describes for target: an xenc:EncryptedData, whose data it decrypts, or
// an xenc:EncryptedKey, which it unwraps (section 3.5.2). Find dk with
// FindDerivedKey; master is the key the caller shares with the sender,
// such as the one dk's MasterKeyName names, or a password.
//
// The key's size is that of target's algorithm, checked first against
// opts.AllowedDataAlgorithms or opts.AllowedKeyWrapAlgorithms. The
// derivation is checked next against opts.AllowedKeyDerivationAlgorithms:
// ConcatKDF (section 5.4.1) by default, with its digest from
// opts.AllowedDigestAlgorithms, and PBKDF2 (section 5.4.2) only when named
// there, with the limits UnwrapEncryptedKeyPassword documents. Pass the
// result to DecryptData or UnwrapEncryptedKey.
func DeriveKey(dk, target *xdm.Node, master []byte, opts DecryptOptions) ([]byte, error) {
	var size int
	if target != nil && target.IsElement(xmlsec.NSXEnc, "EncryptedKey") {
		alg, err := wrapMethod(target, opts)
		if err != nil {
			return nil, err
		}
		size, _ = wrapSize(alg)
	} else {
		alg, err := dataAlgorithm(target, opts)
		if err != nil {
			return nil, err
		}
		size, _ = dataKeySize(alg)
	}
	kdm, err := derivedKeyMethod(dk)
	if err != nil {
		return nil, err
	}
	derive, err := keyDerivation(kdm, size, opts)
	if err != nil {
		return nil, err
	}
	if len(master) == 0 {
		return nil, errors.New("xenc: no master key")
	}
	return derive(master), nil
}

// dataKey returns the key an Encrypt function encrypts ed under:
// sessionKey, or, when that is nil, one ed's ds:KeyInfo conveys, which it
// adds: derived from opts.MasterKey or opts.Password, or agreed by
// opts.DirectKeyAgreement. With none of those it returns nil, which the
// encryption refuses.
func dataKey(ed *xdm.Node, sessionKey []byte, opts EncryptOptions) ([]byte, error) {
	master, direct, password := opts.MasterKey != nil, opts.DirectKeyAgreement, len(opts.Password) > 0
	if sessionKey != nil {
		if master || direct {
			return nil, errors.New("xenc: a session key, and MasterKey or DirectKeyAgreement")
		}
		return sessionKey, nil
	}
	n := 0
	for _, set := range []bool{master, direct, password} {
		if set {
			n++
		}
	}
	switch {
	case n == 0:
		return nil, nil
	case n > 1:
		return nil, errors.New("xenc: more than one of MasterKey, DirectKeyAgreement and Password")
	}
	if err := encryptable(opts.DataAlgorithm, opts.DigestAlgorithm); err != nil {
		return nil, err
	}
	size, ok := keySizes[opts.DataAlgorithm]
	if !ok {
		return nil, unsupported("data %q", opts.DataAlgorithm)
	}
	switch {
	case master:
		return masterKey(ed, size, opts)
	case password:
		return passwordKEK(ed, size, opts)
	case opts.Recipient != nil && opts.RecipientDH == nil:
		return agree(ed, opts.DataAlgorithm, size, opts)
	case opts.RecipientDH != nil && opts.Recipient == nil:
		return agreeDH(ed, opts.DataAlgorithm, size, opts)
	}
	return nil, errors.New("xenc: DirectKeyAgreement needs exactly one of Recipient and RecipientDH")
}

// masterKey derives a data key of size octets from opts.MasterKey by
// ConcatKDF with opts.DigestAlgorithm, and adds to ed the ds:KeyInfo
// holding the xenc11:DerivedKey that names it. OtherInfo is the data
// algorithm and a fresh PartyUInfo.
func masterKey(ed *xdm.Node, size int, opts EncryptOptions) ([]byte, error) {
	h, ok := hashes.Digest(opts.DigestAlgorithm)
	if !ok {
		return nil, unsupported("ConcatKDF digest %q", opts.DigestAlgorithm)
	}
	if len(opts.MasterKey) < size {
		return nil, fmt.Errorf("xenc: MasterKey is %d bytes, under the %d of the data key", len(opts.MasterKey), size)
	}
	partyU := make([]byte, partyUSize)
	rand.Read(partyU)
	key := concatKDF(h, opts.MasterKey, append([]byte(opts.DataAlgorithm), partyU...), size)

	dk := nsElement(nsElement(ed, "ds", xmlsec.NSDSig, "KeyInfo"), "xenc11", xmlsec.NSXEnc11, "DerivedKey")
	concatKDFMethod(dk, opts.DataAlgorithm, partyU, opts.DigestAlgorithm)
	if opts.DerivedKeyName != "" {
		xmltree.Text(xmltree.Element(dk, "xenc11", xmlsec.NSXEnc11, "DerivedKeyName"), opts.DerivedKeyName)
	}
	if opts.MasterKeyName != "" {
		xmltree.Text(xmltree.Element(dk, "xenc11", xmlsec.NSXEnc11, "MasterKeyName"), opts.MasterKeyName)
	}
	return key, nil
}
