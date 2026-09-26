//lint:file-ignore SA1019 crypto/dsa is deprecated; DSA-SHA1 is a verification-only legacy algorithm, opt-in, never in the default set (XML-DSig 1.1 section 6.4.1), confined to this file.

package dsig

import (
	"crypto"
	"crypto/dsa"
	_ "crypto/sha1" // #nosec G505 -- SHA-1 backs verification-only legacy algorithms (sha1, rsa-sha1, dsa-sha1, hmac-sha1), opt-in, never in the default set, never produced by Sign.
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/hashes"
)

// The legacy algorithms of XML-DSig 1.1 section 6.1, implemented for
// verification only. They are outside the default sets (defaultSignature
// and defaultDigest consult only hashes.Signature and hashes.Digest),
// so Verify accepts one only when an allow-list names it, and Sign refuses
// every one of them.
var (
	legacySignatures = map[string]crypto.Hash{
		xmlsec.SigRSASHA1:    crypto.SHA1,
		xmlsec.SigDSASHA1:    crypto.SHA1,
		xmlsec.SigHMACSHA1:   crypto.SHA1,
		xmlsec.SigHMACSHA256: crypto.SHA256,
		xmlsec.SigHMACSHA384: crypto.SHA384,
		xmlsec.SigHMACSHA512: crypto.SHA512,
	}
	legacyDigests = map[string]crypto.Hash{
		xmlsec.DigestSHA1: crypto.SHA1,
	}
	hmacAlgorithms = map[string]bool{
		xmlsec.SigHMACSHA1:   true,
		xmlsec.SigHMACSHA256: true,
		xmlsec.SigHMACSHA384: true,
		xmlsec.SigHMACSHA512: true,
	}
)

// signatureHash returns the hash of any signature algorithm Verify
// implements, the legacy ones included.
func signatureHash(alg string) (crypto.Hash, bool) {
	if h, ok := hashes.Signature(alg); ok {
		return h, true
	}
	h, ok := legacySignatures[alg]
	return h, ok
}

// digestHash returns the hash of any digest algorithm Verify implements.
func digestHash(alg string) (crypto.Hash, bool) {
	if h, ok := hashes.Digest(alg); ok {
		return h, true
	}
	h, ok := legacyDigests[alg]
	return h, ok
}

// refuseLegacy refuses, for generation, an algorithm implemented for
// verification only.
func refuseLegacy(alg string) error {
	_, sig := legacySignatures[alg]
	_, dig := legacyDigests[alg]
	if sig || dig {
		return fmt.Errorf("%w: %s is a legacy algorithm implemented for verification only; Sign never produces it", xmlsec.ErrUnsupportedAlgorithm, alg)
	}
	return nil
}

// hmacOutputLength reads the optional ds:HMACOutputLength child of an HMAC
// ds:SignatureMethod and returns how many leading MAC octets are compared.
// XML-DSig 4.4.2: "Signatures MUST be deemed invalid if the truncation length
// is below the larger of (a) half the underlying hash algorithm's output
// length, and (b) 80 bits" (CVE-2009-0217); 6.3.1: it must be "a multiple of
// 8". A length above the hash output is invalid too.
func hmacOutputLength(sm *xdm.Node, h crypto.Hash) (int, error) {
	full := 8 * h.Size()
	kids := sm.ChildElements()
	switch {
	case len(kids) == 0:
		return h.Size(), nil
	case len(kids) > 1 || !kids[0].IsElement(xmlsec.NSDSig, "HMACOutputLength"):
		return 0, malformed("an HMAC ds:SignatureMethod may hold only ds:HMACOutputLength")
	}
	bits, err := strconv.Atoi(strings.TrimSpace(kids[0].StringValue()))
	if err != nil {
		return 0, malformed("ds:HMACOutputLength is not an integer")
	}
	floor := max(full/2, 80)
	if bits < floor || bits > full || bits%8 != 0 {
		return 0, fmt.Errorf("%w: HMACOutputLength %d; it must be a multiple of 8 from %d to %d", xmlsec.ErrSignatureInvalid, bits, floor, full)
	}
	return bits / 8, nil
}

// parseDSAKeyValue reads ds:DSAKeyValue (XML-DSig 4.5.2.1): P, Q, G, Y, J,
// Seed, PgenCounter in schema order. P, Q and G are optional in the schema,
// as "known from application context"; there is no such context here, so
// they are required. J must equal (P-1)/Q; Seed and PgenCounter must come
// together and are not otherwise checked, as the section permits. The
// parameters themselves are checked by checkDSAKey when the key is used.
func parseDSAKeyValue(e *xdm.Node) (crypto.PublicKey, error) {
	names := []string{"P", "Q", "G", "Y", "J", "Seed", "PgenCounter"}
	v := map[string]*big.Int{}
	i := 0
	for _, k := range e.ChildElements() {
		for i < len(names) && !k.IsElement(xmlsec.NSDSig, names[i]) {
			i++
		}
		if i == len(names) {
			return nil, malformed("unexpected or out-of-order %s in ds:DSAKeyValue", k.Name.Local)
		}
		n, err := cryptoBinary(k)
		if err != nil {
			return nil, err
		}
		v[names[i]] = n
		i++
	}
	switch {
	case v["Y"] == nil, (v["P"] == nil) != (v["Q"] == nil), (v["Seed"] == nil) != (v["PgenCounter"] == nil):
		return nil, malformed("ds:DSAKeyValue needs Y, P with Q, and Seed with PgenCounter")
	case v["P"] == nil || v["G"] == nil:
		return nil, fmt.Errorf("%w: ds:DSAKeyValue without P, Q and G", xmlsec.ErrUnsupportedKeyInfo)
	case v["J"] != nil && v["J"].Cmp(new(big.Int).Quo(new(big.Int).Sub(v["P"], big.NewInt(1)), v["Q"])) != 0:
		return nil, malformed("ds:DSAKeyValue J is not (P-1)/Q")
	}
	return &dsa.PublicKey{Parameters: dsa.Parameters{P: v["P"], Q: v["Q"], G: v["G"]}, Y: v["Y"]}, nil
}

// checkDSAKey accepts only the (L, N) = (1024, 160) keys of dsa-sha1
// (XML-DSig 6.4.1), with prime P and Q, Q dividing P-1, and G and Y in the
// order-Q subgroup. It applies to a DSA key from any source.
func checkDSAKey(k *dsa.PublicKey) error {
	if k.P == nil || k.Q == nil || k.G == nil || k.Y == nil {
		return malformed("DSA key with missing parameters")
	}
	if k.P.BitLen() != 1024 || k.Q.BitLen() != 160 {
		return fmt.Errorf("%w: DSA (L, N) = (%d, %d); dsa-sha1 takes (1024, 160)", xmlsec.ErrUnsupportedKeyInfo, k.P.BitLen(), k.Q.BitLen())
	}
	one := big.NewInt(1)
	inSubgroup := func(x *big.Int) bool {
		return x.Cmp(one) > 0 && x.Cmp(k.P) < 0 && new(big.Int).Exp(x, k.Q, k.P).Cmp(one) == 0
	}
	switch {
	case !k.P.ProbablyPrime(20) || !k.Q.ProbablyPrime(20) || new(big.Int).Mod(new(big.Int).Sub(k.P, one), k.Q).Sign() != 0:
		return malformed("DSA P and Q are not primes with Q dividing P-1")
	case !inSubgroup(k.G):
		return malformed("DSA G does not generate the order-Q subgroup")
	case !inSubgroup(k.Y):
		return malformed("DSA Y is out of range or outside the order-Q subgroup")
	}
	return nil
}

// verifyDSA verifies a dsa-sha1 SignatureValue: r||s, each 20 octets
// (XML-DSig 6.4.1, I2OSP with l = 20).
func verifyDSA(pub crypto.PublicKey, digest, sig []byte) error {
	k, ok := pub.(*dsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: %s with a %T key", xmlsec.ErrUnsupportedAlgorithm, xmlsec.SigDSASHA1, pub)
	}
	if err := checkDSAKey(k); err != nil {
		return err
	}
	if len(sig) != 40 {
		return xmlsec.ErrSignatureInvalid
	}
	if !dsa.Verify(k, digest, new(big.Int).SetBytes(sig[:20]), new(big.Int).SetBytes(sig[20:])) {
		return xmlsec.ErrSignatureInvalid
	}
	return nil
}
