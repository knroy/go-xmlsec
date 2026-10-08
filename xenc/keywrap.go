package xenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
)

// kwIV is the RFC 3394 default initial value.
var kwIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// kwCipher returns the AES block cipher for a KEK of alg's size.
func kwCipher(alg string, kek []byte) (cipher.Block, error) {
	b, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	if len(kek) != wrapSizes[alg] {
		return nil, fmt.Errorf("xenc: key encryption key is %d bytes, %s needs %d", len(kek), alg, wrapSizes[alg])
	}
	return b, nil
}

// kwWrap is the RFC 3394 section 2.2.1 wrap of key, a multiple of 8 bytes
// of at least 16, which every AES key is.
func kwWrap(b cipher.Block, key []byte) []byte {
	n := len(key) / 8
	out := make([]byte, 8+len(key))
	copy(out[8:], key)
	a := kwIV
	var buf [16]byte
	var t uint64 // n*j + i, counted rather than computed
	for range 6 {
		for i := 1; i <= n; i++ {
			t++
			copy(buf[:8], a[:])
			copy(buf[8:], out[8*i:8*i+8])
			b.Encrypt(buf[:], buf[:])
			binary.BigEndian.PutUint64(a[:], binary.BigEndian.Uint64(buf[:8])^t)
			copy(out[8*i:], buf[8:])
		}
	}
	copy(out, a[:])
	return out
}

// kwUnwrap is the RFC 3394 section 2.2.2 unwrap, with the integrity check
// of section 2.2.3. Every failure is the same error.
func kwUnwrap(b cipher.Block, ct []byte) ([]byte, error) {
	if len(ct)%8 != 0 || len(ct) < 24 {
		return nil, errUnwrap
	}
	n := len(ct)/8 - 1
	out := make([]byte, len(ct)-8)
	copy(out, ct[8:])
	var a [8]byte
	copy(a[:], ct)
	var buf [16]byte
	t := uint64(len(out)) / 8 * 6 // n*j + i, counted down from j = 5, i = n
	for range 6 {
		for i := n; i >= 1; i-- {
			binary.BigEndian.PutUint64(buf[:8], binary.BigEndian.Uint64(a[:])^t)
			t--
			copy(buf[8:], out[8*(i-1):8*i])
			b.Decrypt(buf[:], buf[:])
			copy(a[:], buf[:8])
			copy(out[8*(i-1):], buf[8:])
		}
	}
	if subtle.ConstantTimeCompare(a[:], kwIV[:]) != 1 {
		return nil, errUnwrap
	}
	return out, nil
}

// keyWrap wraps key under opts.KeyTransportAlgorithm, a KeyWrap* one, with
// a KEK agreed with opts.Recipient or opts.RecipientDH, derived from
// opts.Password, or given as opts.KeyEncryptionKey.
func keyWrap(ek *xdm.Node, key []byte, opts EncryptOptions) ([]byte, error) {
	size, ok := wrapSizes[opts.KeyTransportAlgorithm]
	if !ok {
		return nil, unsupported("key transport %q", opts.KeyTransportAlgorithm)
	}
	// GenerateEncryptedKey has refused more than one of these.
	kek := opts.KeyEncryptionKey
	var err error
	switch {
	case opts.Recipient != nil:
		kek, err = agree(ek, opts.KeyTransportAlgorithm, size, opts)
	case opts.RecipientDH != nil:
		kek, err = agreeDH(ek, opts.KeyTransportAlgorithm, size, opts)
	case len(opts.Password) > 0:
		kek, err = passwordKEK(ek, size, opts)
	}
	if err != nil {
		return nil, err
	}
	b, err := kwCipher(opts.KeyTransportAlgorithm, kek)
	if err != nil {
		return nil, err
	}
	return kwWrap(b, key), nil
}

// wrapMethod validates el as an xenc:EncryptedKey under an allowed,
// implemented key wrap algorithm, whose EncryptionMethod may hold only a
// consistent KeySize, and returns the algorithm, or
// opts.ImpliedKeyWrapAlgorithm when it has no EncryptionMethod.
func wrapMethod(el *xdm.Node, opts DecryptOptions) (string, error) {
	if el == nil || !el.IsElement(xmlsec.NSXEnc, "EncryptedKey") {
		return "", malformed("not an xenc:EncryptedKey")
	}
	alg, m, err := parseEncryptionMethod(el, opts.ImpliedKeyWrapAlgorithm)
	if err != nil {
		return "", err
	}
	if err := allowed("key wrap", alg, opts.AllowedKeyWrapAlgorithms, defaultKeyWrap); err != nil {
		return "", err
	}
	size, ok := wrapSize(alg)
	if !ok {
		return "", unsupported("key wrap %q", alg)
	}
	if _, err := methodParams(m, size*8); err != nil {
		return "", err
	}
	return alg, nil
}

// unwrap opens the ciphertext of el, an EncryptedKey under alg, with kek.
func unwrap(el *xdm.Node, alg string, kek []byte, opts DecryptOptions) ([]byte, error) {
	var b cipher.Block
	var err error
	if alg == xmlsec.KeyWrapTripleDES {
		b, err = tripleDES(kek)
	} else {
		b, err = kwCipher(alg, kek)
	}
	if err != nil {
		return nil, err
	}
	ct, err := keyCiphertext(el, opts)
	if err != nil {
		return nil, err
	}
	if alg == xmlsec.KeyWrapTripleDES {
		return cmsUnwrap(b, ct)
	}
	return kwUnwrap(b, ct)
}

// UnwrapEncryptedKey unwraps a session key from an xenc:EncryptedKey
// wrapped by AES key wrap (xmlsec.KeyWrapAES128, 192 or 256) under kek, a
// key the caller already shares with the sender, such as one it found by
// the EncryptedKey's ds:KeyName. The EncryptedKey's ds:KeyInfo is not read.
// For a KEK from key agreement use DecryptAgreedKey or DecryptAgreedKeyDH,
// and for one derived from a password UnwrapEncryptedKeyPassword.
//
// opts.AllowedKeyWrapAlgorithms restricts the accepted algorithms; empty
// means the default set, AES key wrap. The legacy xmlsec.KeyWrapTripleDES,
// the RFC 3217 CMS Triple DES key wrap of section 5.7.1 with a 24-octet
// kek, is unwrapped only when named there; its integrity check is a truncated
// SHA-1 of the key. kek must be the algorithm's size. A failed integrity
// check is reported without detail.
//
// The wrapped key may be inline in xenc:CipherValue or named by an
// xenc:CipherReference, resolved as DecryptData resolves one, through
// opts.ResolveURI for an external URI, after the algorithm is accepted.
func UnwrapEncryptedKey(el *xdm.Node, kek []byte, opts DecryptOptions) ([]byte, error) {
	if err := strictKey(el, opts); err != nil {
		return nil, err
	}
	alg, err := wrapMethod(el, opts)
	if err != nil {
		return nil, err
	}
	return unwrap(el, alg, kek, opts)
}

// keyCiphertext returns the ciphertext of an EncryptedKey: its CipherValue,
// or what its CipherReference names, found as for an EncryptedData
// (section 3.3.1). Every caller has checked the algorithms first.
func keyCiphertext(el *xdm.Node, opts DecryptOptions) ([]byte, error) {
	return dataCiphertext(el, opts)
}
