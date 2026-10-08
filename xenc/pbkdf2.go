package xenc

import (
	"crypto"
	"crypto/pbkdf2"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// PBKDF2 iteration counts (XML Encryption 1.1 section 5.4.2).
const (
	// MinPBKDF2Iterations is the least count accepted, on encryption and
	// decryption: the minimum PKCS #5 v2.1 (RFC 8018 section 4.2)
	// recommends.
	MinPBKDF2Iterations = 1000

	// MaxPBKDF2Iterations is the greatest count accepted. A received count
	// above it is refused with xmlsec.ErrLimitExceeded before any
	// derivation: the count is chosen by the sender, and each iteration
	// costs the receiver an HMAC.
	MaxPBKDF2Iterations = 10_000_000

	// DefaultPBKDF2Iterations is the count EncryptOptions.PBKDF2Iterations
	// zero means: the OWASP Password Storage Cheat Sheet's figure for
	// PBKDF2-HMAC-SHA256.
	DefaultPBKDF2Iterations = 600_000
)

// minPBKDF2Salt is the shortest salt accepted, in octets: the minimum RFC
// 8018 section 4.1 recommends. Encryption uses pbkdf2SaltSize, the 128
// bits of NIST SP 800-132 section 5.1.
const (
	minPBKDF2Salt  = 8
	pbkdf2SaltSize = 16
)

// prfs maps each PBKDF2 PRF, named by its HMAC URI, to its hash.
var prfs = map[string]crypto.Hash{
	xmlsec.SigHMACSHA1:   crypto.SHA1, // allowed only by name: never in defaultPRF
	xmlsec.SigHMACSHA256: crypto.SHA256,
	xmlsec.SigHMACSHA384: crypto.SHA384,
	xmlsec.SigHMACSHA512: crypto.SHA512,
}

// pbkdf2Params reads the xenc11:PBKDF2-params of kdm: Salt/Specified,
// IterationCount, KeyLength and PRF, in that order. KeyLength must be
// size, the length the context implies (section 5.4.2); the salt must come
// from xenc11:Specified.
func pbkdf2Params(kdm *xdm.Node, size int, opts DecryptOptions) (func([]byte) []byte, error) {
	params, err := only(kdm, xmlsec.NSXEnc11, "PBKDF2-params")
	if err != nil {
		return nil, err
	}
	kids := params.ChildElements()
	if len(kids) != 4 || !kids[0].IsElement(xmlsec.NSXEnc11, "Salt") || !kids[1].IsElement(xmlsec.NSXEnc11, "IterationCount") ||
		!kids[2].IsElement(xmlsec.NSXEnc11, "KeyLength") || !kids[3].IsElement(xmlsec.NSXEnc11, "PRF") {
		return nil, malformed("xenc11:PBKDF2-params must hold Salt, IterationCount, KeyLength and PRF")
	}
	prf := kids[3].AttrValue("Algorithm")
	if err := allowed("PBKDF2 PRF", prf, opts.AllowedPRFAlgorithms, defaultPRF); err != nil {
		return nil, err
	}
	h, ok := prfs[prf]
	if !ok {
		return nil, unsupported("PBKDF2 PRF %q", prf)
	}
	if len(kids[3].ChildElements()) > 0 {
		return nil, malformed("the HMAC PRF of PBKDF2 takes no Parameters")
	}
	src := kids[0].ChildElements()
	if len(src) != 1 || !src[0].IsElement(xmlsec.NSXEnc11, "Specified") {
		return nil, unsupported("PBKDF2 salt: only xenc11:Specified is supported")
	}
	salt, err := xmltree.Base64(src[0])
	if err != nil {
		return nil, malformed("PBKDF2 salt: %v", err)
	}
	if len(salt) < minPBKDF2Salt {
		return nil, fmt.Errorf("%w: PBKDF2 salt of %d octets, under %d", xmlsec.ErrAlgorithmNotAllowed, len(salt), minPBKDF2Salt)
	}
	iter, err := positiveInteger(kids[1])
	switch {
	case errors.Is(err, strconv.ErrRange) || err == nil && iter > MaxPBKDF2Iterations:
		return nil, fmt.Errorf("%w: PBKDF2 IterationCount %q, over %d", xmlsec.ErrLimitExceeded, kids[1].StringValue(), MaxPBKDF2Iterations)
	case err != nil:
		return nil, err
	case iter < MinPBKDF2Iterations:
		return nil, fmt.Errorf("%w: PBKDF2 IterationCount %d, under %d", xmlsec.ErrAlgorithmNotAllowed, iter, MinPBKDF2Iterations)
	}
	if n, err := positiveInteger(kids[2]); err != nil || n != size {
		return nil, malformed("PBKDF2 KeyLength %q, where the key wrap algorithm needs %d", kids[2].StringValue(), size)
	}
	return func(secret []byte) []byte {
		// pbkdf2.Key fails only for a key length out of range, which size
		// never is, or in FIPS 140-only mode, whose nil key the key wrap
		// then refuses.
		k, _ := pbkdf2.Key(h.New, string(secret), salt, iter, size)
		return k
	}, nil
}

// positiveInteger parses the xs:positiveInteger content of e, whose
// whitespace collapses. An out-of-range value is strconv.ErrRange.
func positiveInteger(e *xdm.Node) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(e.StringValue()))
	if errors.Is(err, strconv.ErrRange) {
		return 0, err
	}
	if err != nil || n <= 0 {
		return 0, malformed("%s %q is not a positive integer", e.Name.Local, e.StringValue())
	}
	return n, nil
}

// pbkdf2Iterations refuses an EncryptOptions.PBKDF2Iterations set without
// a Password, which it would have no effect on, or outside
// MinPBKDF2Iterations to MaxPBKDF2Iterations.
func pbkdf2Iterations(opts EncryptOptions) error {
	switch n := opts.PBKDF2Iterations; {
	case n == 0:
		return nil
	case len(opts.Password) == 0:
		return errors.New("xenc: EncryptOptions.PBKDF2Iterations without a Password")
	case n < MinPBKDF2Iterations || n > MaxPBKDF2Iterations:
		return fmt.Errorf("xenc: PBKDF2Iterations %d, outside %d to %d", n, MinPBKDF2Iterations, MaxPBKDF2Iterations)
	}
	return nil
}

// passwordKEK derives a KEK of size octets from opts.Password by PBKDF2
// with HMAC-SHA256, and adds to ek the ds:KeyInfo holding the
// xenc11:DerivedKey that names its parameters.
func passwordKEK(ek *xdm.Node, size int, opts EncryptOptions) ([]byte, error) {
	iter := opts.PBKDF2Iterations // checked by pbkdf2Iterations
	if iter == 0 {
		iter = DefaultPBKDF2Iterations
	}
	salt := make([]byte, pbkdf2SaltSize)
	rand.Read(salt)
	// Cannot fail: size is a key wrap length, the salt is 128 bits and the
	// PRF is SHA-256, which even FIPS 140-only mode accepts.
	kek, _ := pbkdf2.Key(crypto.SHA256.New, string(opts.Password), salt, iter, size)

	dk := nsElement(newKeyInfo(ek), "xenc11", xmlsec.NSXEnc11, "DerivedKey")
	kdm := xmltree.Element(dk, "xenc11", xmlsec.NSXEnc11, "KeyDerivationMethod")
	xmltree.SetAttr(kdm, "", "", "Algorithm", xmlsec.KeyDerivationPBKDF2)
	params := xmltree.Element(kdm, "xenc11", xmlsec.NSXEnc11, "PBKDF2-params")
	xmltree.Text(xmltree.Element(xmltree.Element(params, "xenc11", xmlsec.NSXEnc11, "Salt"), "xenc11", xmlsec.NSXEnc11, "Specified"), base64.StdEncoding.EncodeToString(salt))
	xmltree.Text(xmltree.Element(params, "xenc11", xmlsec.NSXEnc11, "IterationCount"), strconv.Itoa(iter))
	xmltree.Text(xmltree.Element(params, "xenc11", xmlsec.NSXEnc11, "KeyLength"), strconv.Itoa(size))
	xmltree.SetAttr(xmltree.Element(params, "xenc11", xmlsec.NSXEnc11, "PRF"), "", "", "Algorithm", xmlsec.SigHMACSHA256)
	return kek, nil
}

// UnwrapEncryptedKeyPassword unwraps a session key from an
// xenc:EncryptedKey whose key encryption key is derived from password by
// PBKDF2 (section 5.4.2): its ds:KeyInfo must hold exactly one
// xenc11:DerivedKey whose xenc11:KeyDerivationMethod is
// xmlsec.KeyDerivationPBKDF2, with the salt Specified and a KeyLength equal
// to the key wrap algorithm's. An xenc11:MasterKeyName, DerivedKeyName or
// ReferenceList is ignored: password is the caller's choice. For a
// DerivedKey elsewhere, or one directly under an EncryptedData, use
// FindDerivedKey and DeriveKey.
//
// PBKDF2 is accepted only when opts.AllowedKeyDerivationAlgorithms names
// it, and its PRF only from opts.AllowedPRFAlgorithms (default HMAC-SHA256,
// 384 and 512; the legacy HMAC-SHA1 only when named). An IterationCount
// above MaxPBKDF2Iterations is xmlsec.ErrLimitExceeded, and one under
// MinPBKDF2Iterations or a salt under 8 octets xmlsec.ErrAlgorithmNotAllowed,
// all before any derivation. opts.AllowedKeyWrapAlgorithms restricts the
// key wrap as for UnwrapEncryptedKey.
func UnwrapEncryptedKeyPassword(el *xdm.Node, password []byte, opts DecryptOptions) ([]byte, error) {
	if err := strictKey(el, opts); err != nil {
		return nil, err
	}
	alg, err := wrapMethod(el, opts)
	if err != nil {
		return nil, err
	}
	if len(password) == 0 {
		return nil, errors.New("xenc: no password")
	}
	ki := keyInfo(el)
	if ki == nil {
		return nil, fmt.Errorf("%w: no ds:KeyInfo holding an xenc11:DerivedKey", xmlsec.ErrUnsupportedKeyInfo)
	}
	dk, err := only(ki, xmlsec.NSXEnc11, "DerivedKey")
	if err != nil {
		return nil, err
	}
	kdm, err := derivedKeyMethod(dk, opts.ImpliedKeyDerivationMethod)
	if err != nil {
		return nil, err
	}
	kdf := kdm.AttrValue("Algorithm")
	if err := allowed("key derivation", kdf, opts.AllowedKeyDerivationAlgorithms, defaultDerivation); err != nil {
		return nil, err
	}
	if kdf != xmlsec.KeyDerivationPBKDF2 {
		return nil, unsupported("key derivation %q from a password", kdf)
	}
	size, _ := wrapSize(alg)
	derive, err := pbkdf2Params(kdm, size, opts)
	if err != nil {
		return nil, err
	}
	return unwrap(el, alg, derive(password), opts)
}
