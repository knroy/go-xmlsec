package xenc

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/hashes"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// Finite-field Diffie-Hellman group sizes accepted, in bits of P.
const (
	// MinDHBits is the smallest P accepted, on encryption and decryption:
	// 112-bit security (NIST SP 800-57 part 1, table 2). Section 5.6.2's
	// floor of 512 bits is long broken.
	MinDHBits = 2048

	// MaxDHBits is the largest P accepted, which bounds the modular
	// exponentiations a received message can cost.
	MaxDHBits = 8192

	// minDHQBits is the smallest subgroup order accepted: the 224 bits
	// NIST SP 800-56A pairs with a 2048-bit P.
	minDHQBits = 224
)

// DHPublicKey is a finite-field Diffie-Hellman public key with its domain
// parameters, as an xenc:DHKeyValue carries them (section 5.6.1): the
// prime P, the prime order Q of the subgroup G generates, and the public
// value Y = G^x mod P.
//
// Q is required: section 5.6.1 has P = j*Q + 1, and it is what lets a
// public value be checked to lie in the subgroup (Y^Q mod P = 1), without
// which a peer can confine the shared secret to a small subgroup. For a
// safe-prime group, such as those of RFC 3526 and RFC 7919, Q is
// (P-1)/2.
type DHPublicKey struct {
	P, Q, G, Y *big.Int
}

// DHPrivateKey is a finite-field Diffie-Hellman key pair: X is the private
// exponent, from 1 to Q-1.
type DHPrivateKey struct {
	DHPublicKey
	X *big.Int
}

var one = big.NewInt(1)

// checkGroup validates the domain parameters of k: P from MinDHBits to
// MaxDHBits, Q of at least 224 bits dividing P-1, both prime, and G of
// order Q. Failures are xmlsec.ErrUnsupportedKeyInfo.
func (k *DHPublicKey) checkGroup() error {
	if k == nil || k.P == nil || k.Q == nil || k.G == nil {
		return dhRefused("no P, Q or Generator")
	}
	if n := k.P.BitLen(); n < MinDHBits || n > MaxDHBits {
		return dhRefused("a %d-bit P, outside %d to %d bits", n, MinDHBits, MaxDHBits)
	}
	pm1 := new(big.Int).Sub(k.P, one)
	if k.Q.BitLen() < minDHQBits || new(big.Int).Mod(pm1, k.Q).Sign() != 0 {
		return dhRefused("Q must have at least %d bits and divide P-1", minDHQBits)
	}
	// Baillie-PSW: no composite is known to pass it.
	if !k.P.ProbablyPrime(0) || !k.Q.ProbablyPrime(0) {
		return dhRefused("P and Q must be prime")
	}
	if k.G.Cmp(one) <= 0 || k.G.Cmp(pm1) >= 0 || new(big.Int).Exp(k.G, k.Q, k.P).Cmp(one) != 0 {
		return dhRefused("the Generator must have order Q")
	}
	return nil
}

// checkPublic validates y as a public value in k's group: 1 < y < P-1
// and y^Q mod P = 1 (NIST SP 800-56A section 5.6.2.3.1), which refuses
// 0, 1, P-1 and every value outside the order-Q subgroup.
func (k *DHPublicKey) checkPublic(y *big.Int) bool {
	pm1 := new(big.Int).Sub(k.P, one)
	return y.Cmp(one) > 0 && y.Cmp(pm1) < 0 && new(big.Int).Exp(y, k.Q, k.P).Cmp(one) == 0
}

func dhRefused(format string, args ...any) error {
	return fmt.Errorf("%w: Diffie-Hellman key with "+format, append([]any{xmlsec.ErrUnsupportedKeyInfo}, args...)...)
}

// GenerateDHKey returns a fresh key pair in the group p, q, g, which must
// pass the checks DHPublicKey documents: P from MinDHBits to MaxDHBits, Q
// a prime of at least 224 bits dividing P-1, and G of order Q.
func GenerateDHKey(p, q, g *big.Int) (*DHPrivateKey, error) {
	k := &DHPrivateKey{DHPublicKey: DHPublicKey{P: p, Q: q, G: g}}
	if err := k.checkGroup(); err != nil {
		return nil, err
	}
	return k.generate(), nil
}

// generate sets a fresh X in [1, Q-1], and Y, in k's checked group.
func (k *DHPrivateKey) generate() *DHPrivateKey {
	// Cannot fail: crypto/rand does not fail, and Q-1 is positive.
	x, _ := rand.Int(rand.Reader, new(big.Int).Sub(k.Q, one))
	k.X = x.Add(x, one)
	k.Y = new(big.Int).Exp(k.G, k.X, k.P)
	return k
}

// sharedSecret is y^x mod P as the octets ZZ, with its leading zeros kept
// so that it is as long as P (section 5.6.2).
func sharedSecret(y, x, p *big.Int) []byte {
	return new(big.Int).Exp(y, x, p).FillBytes(make([]byte, (p.BitLen()+7)/8))
}

// legacyKDF is the Diffie-Hellman Legacy KDF of section 5.6.2.2: size
// octets of KM(1) | KM(2) | ..., where KM(counter) = H(ZZ | counter |
// EncryptionAlg | KA-Nonce | KeySize), counter being two upper-case hex
// digits and KeySize the key's bits in decimal.
func legacyKDF(h crypto.Hash, zz []byte, alg string, nonce []byte, size int) []byte {
	var out []byte
	for counter := 1; len(out) < size; counter++ {
		d := h.New()
		d.Write(zz)
		fmt.Fprintf(d, "%02X", counter)
		d.Write([]byte(alg))
		d.Write(nonce)
		d.Write([]byte(strconv.Itoa(size * 8)))
		out = d.Sum(out)
	}
	return out[:size]
}

// agreeDH derives a KEK of size octets for opts.RecipientDH by dh-es with
// ConcatKDF or dh with the Legacy KDF, from a fresh ephemeral key in the
// recipient's group, and adds the ds:KeyInfo holding the
// xenc:AgreementMethod to ek. The ephemeral public key, with the group, is
// the OriginatorKeyInfo; the RecipientKeyInfo is opts.RecipientKeyName as
// a ds:KeyName, or else the recipient's public value.
func agreeDH(ek *xdm.Node, size int, opts EncryptOptions) ([]byte, error) {
	alg := opts.KeyAgreementAlgorithm
	if alg != xmlsec.KeyAgreementDHES && alg != xmlsec.KeyAgreementDH {
		return nil, unsupported("key agreement %q with a Diffie-Hellman key", alg)
	}
	h, ok := hashes.Digest(opts.DigestAlgorithm)
	if !ok {
		return nil, unsupported("key derivation digest %q", opts.DigestAlgorithm)
	}
	r := opts.RecipientDH
	if err := r.checkGroup(); err != nil {
		return nil, err
	}
	if r.Y == nil || !r.checkPublic(r.Y) {
		return nil, dhRefused("a public value outside the group")
	}
	eph := (&DHPrivateKey{DHPublicKey: DHPublicKey{P: r.P, Q: r.Q, G: r.G}}).generate()
	zz := sharedSecret(r.Y, eph.X, r.P)

	am := newAgreementMethod(ek, alg)
	var kek []byte
	if alg == xmlsec.KeyAgreementDHES {
		kek = concatKDF(h, zz, []byte(opts.KeyTransportAlgorithm), size)
		concatKDFMethod(am, opts)
	} else {
		kek = legacyKDF(h, zz, opts.KeyTransportAlgorithm, nil, size)
		xmltree.SetAttr(nsElement(am, "ds", xmlsec.NSDSig, "DigestMethod"), "", "", "Algorithm", opts.DigestAlgorithm)
	}
	dhKeyValue(element(am, "OriginatorKeyInfo"), &eph.DHPublicKey, true)
	rki := element(am, "RecipientKeyInfo")
	if opts.RecipientKeyName != "" {
		xmltree.Text(xmltree.Element(rki, "ds", xmlsec.NSDSig, "KeyName"), opts.RecipientKeyName)
	} else {
		dhKeyValue(rki, r, false)
	}
	return kek, nil
}

// dhKeyValue adds ds:KeyValue/xenc:DHKeyValue holding k's public value to
// parent, preceded by its group when group is set.
func dhKeyValue(parent *xdm.Node, k *DHPublicKey, group bool) {
	kv := element(xmltree.Element(parent, "ds", xmlsec.NSDSig, "KeyValue"), "DHKeyValue")
	add := func(local string, v *big.Int) {
		xmltree.Text(element(kv, local), base64.StdEncoding.EncodeToString(v.Bytes()))
	}
	if group {
		add("P", k.P)
		add("Q", k.Q)
		add("Generator", k.G)
	}
	add("Public", k.Y)
}

// dhOriginatorKey reads the originator's public value from
// OriginatorKeyInfo/ds:KeyValue/xenc:DHKeyValue, in the schema order
// [P, Q, Generator,] Public [, seed, pgenCounter]. Parameters, when
// present, must be priv's own group; seed and pgenCounter are not used,
// since the group is checked rather than regenerated.
func dhOriginatorKey(oki *xdm.Node, priv *DHPrivateKey) (*big.Int, error) {
	kv, err := keyValue(oki)
	if err != nil {
		return nil, err
	}
	dh, err := only(kv, xmlsec.NSXEnc, "DHKeyValue")
	if err != nil {
		return nil, err
	}
	kids := dh.ChildElements()
	names := make([]string, len(kids))
	vals := map[string]*big.Int{}
	for i, k := range kids {
		if k.Name.URI != xmlsec.NSXEnc {
			return nil, malformed("%s in xenc:DHKeyValue", k.Name.Local)
		}
		b, err := xmltree.Base64(k)
		if err != nil {
			return nil, malformed("xenc:%s: %v", k.Name.Local, err)
		}
		names[i] = k.Name.Local
		vals[k.Name.Local] = new(big.Int).SetBytes(b)
	}
	switch strings.TrimSuffix(strings.Join(names, " "), " seed pgenCounter") {
	case "Public":
	case "P Q Generator Public":
		p := vals["P"]
		if n := p.BitLen(); n < MinDHBits || n > MaxDHBits {
			return nil, dhRefused("a %d-bit P, outside %d to %d bits", n, MinDHBits, MaxDHBits)
		}
		if p.Cmp(priv.P) != 0 || vals["Q"].Cmp(priv.Q) != 0 || vals["Generator"].Cmp(priv.G) != 0 {
			return nil, dhRefused("another group than the recipient's")
		}
	default:
		return nil, malformed("xenc:DHKeyValue must hold [P, Q, Generator,] Public [, seed, pgenCounter]")
	}
	y := vals["Public"]
	if !priv.checkPublic(y) {
		return nil, malformed("xenc:DHKeyValue Public outside the group")
	}
	return y, nil
}

// DecryptAgreedKeyDH unwraps a session key from an xenc:EncryptedKey whose
// key encryption key is agreed by finite-field Diffie-Hellman (section
// 5.6.2) between priv, the recipient's static key, and the originator's
// key in OriginatorKeyInfo/ds:KeyValue/xenc:DHKeyValue:
//
//   - xmlsec.KeyAgreementDHES: an explicit xenc11:KeyDerivationMethod,
//     ConcatKDF or, when named in opts.AllowedKeyDerivationAlgorithms,
//     PBKDF2 (section 5.6.2.1). A KA-Nonce is refused.
//   - xmlsec.KeyAgreementDH: the Legacy KDF of section 5.6.2.2, with the
//     AgreementMethod's ds:DigestMethod and optional KA-Nonce.
//
// Neither is in the default key agreement list: each is accepted only
// when opts.AllowedKeyAgreementAlgorithms names it. The digest list
// restricts the ConcatKDF and Legacy KDF digests; SHA-1, the Legacy KDF's
// example digest, is accepted only when named there. RecipientKeyInfo is
// ignored: priv is the caller's choice.
//
// priv's group must pass the checks DHPublicKey documents, and the
// originator's key must be in it: a DHKeyValue naming P, Q and Generator
// must name priv's, and its Public must satisfy 1 < Y < P-1 and
// Y^Q mod P = 1. A group of another size is xmlsec.ErrUnsupportedKeyInfo,
// refused before any arithmetic in it, so an oversized one costs nothing;
// an invalid Public is xmlsec.ErrMalformed.
func DecryptAgreedKeyDH(el *xdm.Node, priv *DHPrivateKey, opts DecryptOptions) ([]byte, error) {
	a, err := parseAgreed(el, priv == nil, opts)
	if err != nil {
		return nil, err
	}
	var kdf func([]byte) []byte
	switch a.agreement {
	case xmlsec.KeyAgreementDHES:
		kdf, err = a.explicitKDF(opts)
	case xmlsec.KeyAgreementDH:
		kdf, err = a.legacyKDF(opts)
	default:
		return nil, unsupported("key agreement %q with a Diffie-Hellman key", a.agreement)
	}
	if err != nil {
		return nil, err
	}
	if err := priv.checkGroup(); err != nil {
		return nil, err
	}
	if priv.X == nil || priv.X.Sign() <= 0 || priv.X.Cmp(priv.Q) >= 0 {
		return nil, dhRefused("a private X outside 1 to Q-1")
	}
	y, err := dhOriginatorKey(a.origin, priv)
	if err != nil {
		return nil, err
	}
	return unwrap(el, a.wrap, kdf(sharedSecret(y, priv.X, priv.P)))
}

// legacyKDF returns the Legacy KDF of a dh agreement: its ds:DigestMethod,
// checked against opts, and optional KA-Nonce. It takes no
// xenc11:KeyDerivationMethod.
func (a *agreed) legacyKDF(opts DecryptOptions) (func([]byte) []byte, error) {
	if a.kdm != nil || a.digest == nil {
		return nil, malformed("xenc:AgreementMethod of %s needs a ds:DigestMethod, and takes no xenc11:KeyDerivationMethod", a.agreement)
	}
	h, err := digest("Legacy KDF digest", a.digest.AttrValue("Algorithm"), opts.AllowedDigestAlgorithms)
	if err != nil {
		return nil, err
	}
	var nonce []byte
	if a.nonce != nil {
		if nonce, err = xmltree.Base64(a.nonce); err != nil {
			return nil, malformed("xenc:KA-Nonce: %v", err)
		}
	}
	return func(zz []byte) []byte { return legacyKDF(h, zz, a.wrap, nonce, a.size) }, nil
}
