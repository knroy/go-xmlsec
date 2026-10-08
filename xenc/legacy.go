package xenc

// The legacy algorithms XML Encryption 1.1 still requires, implemented for
// decryption only and accepted only when a caller names them (see the
// package documentation). Everything here is reachable only past an
// allow-list check that the default sets never pass.

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // #nosec G502 -- decryption-only legacy algorithm, opt-in, never in default set: tripledes-cbc and kw-tripledes (XML Encryption 1.1 sections 5.2.2, 5.7.1)
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- decryption-only legacy algorithm, opt-in, never in default set: the RFC 3217 key checksum of kw-tripledes, and the SHA-1 OAEP digest and MGF1
	"crypto/subtle"
	"errors"
	"slices"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/hashes"
)

// legacy lists every decryption-only algorithm. No encryption path accepts
// one, whatever the tables in the xmlsec package come to hold.
var legacy = []string{
	xmlsec.EncTripleDESCBC, xmlsec.EncAES128CBC, xmlsec.EncAES192CBC, xmlsec.EncAES256CBC,
	xmlsec.KeyTransportRSAOAEPMGF1P, xmlsec.KeyTransportRSA15, xmlsec.KeyWrapTripleDES,
	xmlsec.MGF1SHA1, xmlsec.DigestSHA1,
}

// cbcSizes maps each CBC data algorithm to its key length.
var cbcSizes = map[string]int{
	xmlsec.EncTripleDESCBC: 24,
	xmlsec.EncAES128CBC:    16,
	xmlsec.EncAES192CBC:    24,
	xmlsec.EncAES256CBC:    32,
}

// encryptable refuses any legacy algorithm among algs.
func encryptable(algs ...string) error {
	for _, a := range algs {
		if slices.Contains(legacy, a) {
			return unsupported("%s is a legacy algorithm, implemented for decryption only", a)
		}
	}
	return nil
}

// dataKeySize returns the key length of a data algorithm, GCM or CBC.
func dataKeySize(alg string) (int, bool) {
	if n, ok := keySizes[alg]; ok {
		return n, true
	}
	n, ok := cbcSizes[alg]
	return n, ok
}

// wrapSize returns the KEK length of a key wrap algorithm, AES or 3DES.
func wrapSize(alg string) (int, bool) {
	if alg == xmlsec.KeyWrapTripleDES {
		return 24, true
	}
	n, ok := wrapSizes[alg]
	return n, ok
}

// tripleDES is the only construction of a DES cipher in this package, for
// tripledes-cbc data and kw-tripledes key wrap.
func tripleDES(key []byte) (cipher.Block, error) {
	return des.NewTripleDESCipher(key) // #nosec G405 -- decryption-only legacy algorithm, opt-in, never in default set: tripledes-cbc and kw-tripledes (sections 5.2.2, 5.7.1)
}

// cbcOpen decrypts IV || ciphertext under a CBC algorithm and removes the
// section 5.2.1 padding: N-1 arbitrary octets and a last octet N, 1 <= N <=
// the block size. Only that last octet is checked, as the section says; the
// pad octets are arbitrary and a sender such as xmlsec1 fills them at
// random.
//
// Every failure is errDecrypt, and the whole ciphertext is decrypted before
// the padding is judged, in constant time. The length checks return early,
// but the length is public. This narrows the padding oracle of section
// 6.1.1 and does not close it: CBC has no integrity, so an attacker who can
// submit ciphertext still learns from whatever the application does with
// the plaintext, such as fail to parse it.
func cbcOpen(alg string, key, data []byte) ([]byte, error) {
	var b cipher.Block
	var err error
	if alg == xmlsec.EncTripleDESCBC {
		b, err = tripleDES(key)
	} else {
		b, err = aes.NewCipher(key)
	}
	if err != nil || len(key) != cbcSizes[alg] {
		return nil, errDecrypt
	}
	bs := b.BlockSize()
	if len(data) < 2*bs || len(data)%bs != 0 {
		return nil, errDecrypt
	}
	pt := make([]byte, len(data)-bs)
	cipher.NewCBCDecrypter(b, data[:bs]).CryptBlocks(pt, data[bs:])
	n := int(pt[len(pt)-1])
	if subtle.ConstantTimeLessOrEq(1, n)&subtle.ConstantTimeLessOrEq(n, bs) != 1 {
		return nil, errDecrypt
	}
	return pt[:len(pt)-n], nil
}

// cmsIV is the fixed IV of the second encryption in RFC 3217 section 3.1.
var cmsIV = []byte{0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05}

// cmsUnwrap is the RFC 3217 section 3.2 Triple-DES key unwrap. The RFC
// fixes 40 octets, a 168-bit key; section 5.7.1 lets other keys be wrapped,
// so any whole number of 8-octet blocks is accepted. Every failure is the
// same error.
func cmsUnwrap(b cipher.Block, ct []byte) ([]byte, error) {
	if len(ct)%8 != 0 || len(ct) < 24 {
		return nil, errUnwrap
	}
	temp := make([]byte, len(ct))
	cipher.NewCBCDecrypter(b, cmsIV).CryptBlocks(temp, ct)
	slices.Reverse(temp)
	wkcks := make([]byte, len(temp)-8)
	cipher.NewCBCDecrypter(b, temp[:8]).CryptBlocks(wkcks, temp[8:])
	wk, cks := wkcks[:len(wkcks)-8], wkcks[len(wkcks)-8:]
	sum := sha1.Sum(wk) // #nosec G401 -- decryption-only legacy algorithm, opt-in, never in default set: the RFC 3217 CMS key checksum kw-tripledes defines
	// RFC 3217 section 3.2 step 8 also checks the odd parity of each
	// octet of a Triple-DES CEK. It is deliberately not checked: xmlsec1
	// wraps random des-192 keys without setting parity, DES ignores the
	// parity bits, so such a key decrypts correctly, and a 24-octet CEK
	// may be an AES-192 key, which has no parity (section 5.7.1).
	if subtle.ConstantTimeCompare(sum[:8], cks) != 1 {
		return nil, errUnwrap
	}
	return wk, nil
}

// mgfHash resolves an MGF URI that has passed the allow-list, including
// MGF1 with SHA-1, which hashes.MGF deliberately lacks.
func mgfHash(uri string) (crypto.Hash, bool) {
	if uri == xmlsec.MGF1SHA1 {
		return crypto.SHA1, true
	}
	return hashes.MGF(uri)
}

// DecryptEncryptedKeyPKCS1v15 unwraps the session key of ed, an
// xenc:EncryptedData, from el, an xenc:EncryptedKey transported by RSA
// PKCS#1 v1.5 (xmlsec.KeyTransportRSA15, XML Encryption 1.1 section 5.5.1).
// It is a legacy algorithm, implemented for decryption only: it is refused
// unless opts.AllowedKeyTransportAlgorithms names xmlsec.KeyTransportRSA15, which the
// default set never includes, and calling this function rather than
// DecryptEncryptedKey is itself the opt-in.
//
// It implements the section 6.1.2 countermeasure to Bleichenbacher's
// attack. The key length comes from ed's data algorithm, which must pass
// opts.AllowedDataAlgorithms (empty: the default set, AES-GCM). When the decrypted block
// is not PKCS#1 v1.5 conformant, or holds a key of another length, or dec
// fails in any way, the result is a random key of that length and no
// error, in constant time with an *rsa.PrivateKey. The failure then
// surfaces only when DecryptData or DecryptAttachment with that key fails,
// as the same generic error any wrong key gives. Do not treat the key as
// verified until the data has decrypted and, for CBC, parsed.
//
// Limits: section 6.1.2 says this is no countermeasure against an attacker
// who also modifies CBC EncryptedData, which leaves a few million queries
// to recover the key; only AES-GCM data closes that. dec must honour
// rsa.PKCS1v15DecryptOptions.SessionKeyLen in constant time, as
// *rsa.PrivateKey does; a hardware Decrypter that fails faster on bad
// padding reopens the timing channel. And dec's key pair must be used for
// nothing else (section 6.1.3): an attacker who can make it decrypt PKCS#1
// v1.5 can recover what the same key protects under RSA-OAEP, and forge
// its RSA signatures. Give this function a Decrypter that DecryptEncryptedKey
// and signing never see.
//
// A KeySize under the EncryptionMethod must equal the bit length of dec's
// RSA modulus; the method may hold nothing else. The ciphertext may be
// named by an xenc:CipherReference, as for UnwrapEncryptedKey: it is
// obtained, and a failure to obtain it reported, before any RSA operation,
// so the countermeasure above is unchanged.
func DecryptEncryptedKeyPKCS1v15(el, ed *xdm.Node, dec crypto.Decrypter, opts DecryptOptions) ([]byte, error) {
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
	if kt != xmlsec.KeyTransportRSA15 {
		return nil, unsupported("key transport %q: DecryptEncryptedKeyPKCS1v15 is for %s only", kt, xmlsec.KeyTransportRSA15)
	}
	alg, err := dataAlgorithm(ed, opts)
	if err != nil {
		return nil, err
	}
	pub, ok := dec.Public().(*rsa.PublicKey)
	if !ok {
		return nil, unsupported("RSA v1.5 with a %T key", dec.Public())
	}
	if _, err := methodParams(m, pub.N.BitLen()); err != nil {
		return nil, err
	}
	ct, err := keyCiphertext(el, opts)
	if err != nil {
		return nil, err
	}
	size, _ := dataKeySize(alg)
	//lint:ignore SA1019 decryption-only legacy algorithm, opt-in, never in default set: rsa-1_5 (section 5.5.1) with implicit rejection
	key, err := dec.Decrypt(rand.Reader, ct, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: size})
	if err != nil || len(key) != size {
		// A Decrypter that reports bad padding instead of rejecting
		// implicitly: reject implicitly here.
		key = make([]byte, size)
		rand.Read(key)
	}
	return key, nil
}
