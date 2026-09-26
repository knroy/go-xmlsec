package xenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/knroy/go-xml/xdm"
)

// kwIV is the RFC 3394 default initial value.
var kwIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

var errUnwrap = errors.New("xenc: key unwrap failed")

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
// a KEK agreed with opts.Recipient or given as opts.KeyEncryptionKey.
func keyWrap(ek *xdm.Node, key []byte, opts EncryptOptions) ([]byte, error) {
	size, ok := wrapSizes[opts.KeyTransportAlgorithm]
	if !ok {
		return nil, unsupported("key transport %q", opts.KeyTransportAlgorithm)
	}
	kek := opts.KeyEncryptionKey
	switch {
	case opts.Recipient != nil && kek != nil:
		return nil, errors.New("xenc: both a Recipient and a KeyEncryptionKey")
	case opts.Recipient != nil:
		var err error
		if kek, err = agree(ek, size, opts); err != nil {
			return nil, err
		}
	}
	b, err := kwCipher(opts.KeyTransportAlgorithm, kek)
	if err != nil {
		return nil, err
	}
	return kwWrap(b, key), nil
}

// wrapMethod validates el as an xenc:EncryptedKey under an allowed,
// implemented key wrap algorithm, whose EncryptionMethod may hold only a
// consistent KeySize, and returns the algorithm.
func wrapMethod(el *xdm.Node, allowedKeyWrap []string) (string, error) {
	if el == nil || !el.IsElement(NSXEnc, "EncryptedKey") {
		return "", malformed("not an xenc:EncryptedKey")
	}
	alg, m, err := parseEncryptionMethod(el)
	if err != nil {
		return "", err
	}
	if err := allowed("key wrap", alg, allowedKeyWrap, defaultKeyWrap); err != nil {
		return "", err
	}
	size, ok := wrapSizes[alg]
	if !ok {
		return "", unsupported("key wrap %q", alg)
	}
	if _, err := methodParams(m, size*8); err != nil {
		return "", err
	}
	return alg, nil
}

// unwrap opens the CipherValue of el, an EncryptedKey under alg, with kek.
func unwrap(el *xdm.Node, alg string, kek []byte) ([]byte, error) {
	b, err := kwCipher(alg, kek)
	if err != nil {
		return nil, err
	}
	ct, err := cipherValue(el)
	if err != nil {
		return nil, err
	}
	return kwUnwrap(b, ct)
}

// UnwrapEncryptedKey unwraps a session key from an xenc:EncryptedKey
// wrapped by AES key wrap (xmlsec.KeyWrapAES128, 192 or 256) under kek, a
// key the caller already shares with the sender, such as one it found by
// the EncryptedKey's ds:KeyName. The EncryptedKey's ds:KeyInfo is not read.
// For a KEK from key agreement use DecryptAgreedKey.
//
// allowedKeyWrap restricts the accepted algorithms; empty means the default
// set. kek must be the algorithm's size. A failed integrity check is
// reported without detail.
func UnwrapEncryptedKey(el *xdm.Node, kek []byte, allowedKeyWrap []string) ([]byte, error) {
	alg, err := wrapMethod(el, allowedKeyWrap)
	if err != nil {
		return nil, err
	}
	return unwrap(el, alg, kek)
}
