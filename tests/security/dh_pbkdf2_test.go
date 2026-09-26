package security

import (
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

// Attacks on the OPTIONAL finite-field Diffie-Hellman and PBKDF2 of XML
// Encryption 1.1 section 5: each is refused unless named, a received DH
// public value must lie in the recipient's order-Q subgroup, a received
// group must be the recipient's and of at least 2048 bits, and a received
// PBKDF2 iteration count is bounded before any derivation.

// ffdhe2048 is the RFC 7919 appendix A.1 group: generator 2, Q = (P-1)/2.
var ffdhe2048, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF", 16)

func dhRecipient(t *testing.T) *xenc.DHPrivateKey {
	t.Helper()
	k, err := xenc.GenerateDHKey(ffdhe2048, new(big.Int).Rsh(ffdhe2048, 1), big.NewInt(2))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// dhMessage is a genuine dh-es EncryptedKey for k, as a string to tamper
// with.
func dhMessage(t *testing.T, k *xenc.DHPrivateKey) string {
	t.Helper()
	ek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES128,
		KeyAgreementAlgorithm: xmlsec.KeyAgreementDHES, DigestAlgorithm: xmlsec.DigestSHA256, RecipientDH: &k.DHPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	return c14nString(t, ek)
}

// originator replaces the originator's DHKeyValue content in msg.
func originator(msg string, kv ...[2]any) string {
	const open = `<xenc:OriginatorKeyInfo><ds:KeyValue><xenc:DHKeyValue>`
	i := strings.Index(msg, open) + len(open)
	j := i + strings.Index(msg[i:], `</xenc:DHKeyValue>`)
	var s strings.Builder
	for _, e := range kv {
		name, v := e[0].(string), e[1].(*big.Int)
		s.WriteString(`<xenc:` + name + `>` + base64.StdEncoding.EncodeToString(v.Bytes()) + `</xenc:` + name + `>`)
	}
	return msg[:i] + s.String() + msg[j:]
}

var dhES = xenc.DecryptOptions{AllowedKeyAgreementAlgorithms: []string{xmlsec.KeyAgreementDHES, xmlsec.KeyAgreementDH}}

// Neither DH form nor PBKDF2 is accepted under empty allow-lists; the
// genuine messages decrypt once named.
func TestDHAndPBKDF2NotAllowedByDefault(t *testing.T) {
	k := dhRecipient(t)
	for _, agreement := range []string{xmlsec.KeyAgreementDHES, xmlsec.KeyAgreementDH} {
		ek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES128,
			KeyAgreementAlgorithm: agreement, DigestAlgorithm: xmlsec.DigestSHA256, RecipientDH: &k.DHPublicKey})
		if err != nil {
			t.Fatal(err)
		}
		el := legacyParse(t, c14nString(t, ek))
		if _, err := xenc.DecryptAgreedKeyDH(el, k, xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
			t.Fatalf("%s, empty lists: %v", agreement, err)
		}
		if _, err := xenc.DecryptAgreedKeyDH(el, k, xenc.DecryptOptions{AllowedKeyAgreementAlgorithms: []string{agreement}}); err != nil {
			t.Fatalf("%s, named: %v", agreement, err)
		}
	}

	ek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES128,
		Password: []byte("pw"), PBKDF2Iterations: xenc.MinPBKDF2Iterations})
	if err != nil {
		t.Fatal(err)
	}
	el := legacyParse(t, c14nString(t, ek))
	if _, err := xenc.UnwrapEncryptedKeyPassword(el, []byte("pw"), xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("PBKDF2, empty lists: %v", err)
	}
	if _, err := xenc.UnwrapEncryptedKeyPassword(el, []byte("pw"), xenc.DecryptOptions{AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2}}); err != nil {
		t.Fatalf("PBKDF2, named: %v", err)
	}
}

func c14nString(t *testing.T, ek *xenc.EncryptedKey) string {
	t.Helper()
	b, err := c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Exclusive10})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Small-subgroup and weak-group attacks: the originator's public value
// must satisfy 1 < Y < P-1 and Y^Q mod P = 1, and a group it names must be
// the recipient's and of 2048 to 8192 bits. Oversized groups are refused
// before any exponentiation, so they cost nothing.
func TestDHSubgroupAndGroupAttacksRefused(t *testing.T) {
	k := dhRecipient(t)
	msg := dhMessage(t, k)
	pm1 := new(big.Int).Sub(k.P, big.NewInt(1))
	// 3 or more: a generator of the whole group, of order 2Q.
	full := big.NewInt(3)
	for new(big.Int).Exp(full, k.Q, k.P).Cmp(big.NewInt(1)) == 0 {
		full.Add(full, big.NewInt(1))
	}
	small := new(big.Int).Rsh(k.P, 1536)             // a 512-bit "export" group
	huge := new(big.Int).Lsh(big.NewInt(1), 16384-1) // 16384 bits
	huge.Add(huge, big.NewInt(1))
	for name, c := range map[string]struct {
		el   string
		want error
	}{
		"Y = 0":                  {originator(msg, [2]any{"Public", big.NewInt(0)}), xmlsec.ErrMalformed},
		"Y = 1":                  {originator(msg, [2]any{"Public", big.NewInt(1)}), xmlsec.ErrMalformed},
		"Y = P-1, order 2":       {originator(msg, [2]any{"Public", pm1}), xmlsec.ErrMalformed},
		"Y = P":                  {originator(msg, [2]any{"Public", k.P}), xmlsec.ErrMalformed},
		"Y outside the subgroup": {originator(msg, [2]any{"Public", full}), xmlsec.ErrMalformed},
		"512-bit group":          {originator(msg, [2]any{"P", small}, [2]any{"Q", k.Q}, [2]any{"Generator", k.G}, [2]any{"Public", big.NewInt(2)}), xmlsec.ErrUnsupportedKeyInfo},
		"16384-bit group":        {originator(msg, [2]any{"P", huge}, [2]any{"Q", k.Q}, [2]any{"Generator", k.G}, [2]any{"Public", big.NewInt(2)}), xmlsec.ErrUnsupportedKeyInfo},
		"attacker's generator":   {originator(msg, [2]any{"P", k.P}, [2]any{"Q", k.Q}, [2]any{"Generator", full}, [2]any{"Public", full}), xmlsec.ErrUnsupportedKeyInfo},
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			key, err := xenc.DecryptAgreedKeyDH(legacyParse(t, c.el), k, dhES)
			if !errors.Is(err, c.want) || key != nil {
				t.Fatalf("got %x, %v; want %v", key, err, c.want)
			}
			if d := time.Since(start); d > time.Second {
				t.Fatalf("refusal took %v", d)
			}
		})
	}

	// A recipient key in a weak group is refused too, so a caller cannot
	// be talked into one.
	weak := &xenc.DHPrivateKey{DHPublicKey: xenc.DHPublicKey{P: small, Q: k.Q, G: k.G}, X: k.X}
	if _, err := xenc.DecryptAgreedKeyDH(legacyParse(t, msg), weak, dhES); !errors.Is(err, xmlsec.ErrUnsupportedKeyInfo) {
		t.Fatalf("weak recipient group: %v", err)
	}
}

// A received PBKDF2 IterationCount above xenc.MaxPBKDF2Iterations is
// refused before any derivation: the refusal takes no longer than parsing,
// where honouring 4,000,000,000 iterations would take hours. Under
// MinPBKDF2Iterations is refused as weak.
func TestPBKDF2IterationCountBounded(t *testing.T) {
	ek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES128,
		Password: []byte("pw"), PBKDF2Iterations: xenc.MinPBKDF2Iterations})
	if err != nil {
		t.Fatal(err)
	}
	msg := c14nString(t, ek)
	const count = `<xenc11:IterationCount>1000</xenc11:IterationCount>`
	if !strings.Contains(msg, count) {
		t.Fatalf("no %s in %s", count, msg)
	}
	opts := xenc.DecryptOptions{AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2}}
	for n, want := range map[string]error{
		"4000000000":              xmlsec.ErrLimitExceeded,
		"10000001":                xmlsec.ErrLimitExceeded,
		"99999999999999999999999": xmlsec.ErrLimitExceeded,
		"999":                     xmlsec.ErrAlgorithmNotAllowed,
		"1":                       xmlsec.ErrAlgorithmNotAllowed,
	} {
		el := legacyParse(t, strings.Replace(msg, count, `<xenc11:IterationCount>`+n+`</xenc11:IterationCount>`, 1))
		start := time.Now()
		key, err := xenc.UnwrapEncryptedKeyPassword(el, []byte("pw"), opts)
		elapsed := time.Since(start)
		if !errors.Is(err, want) || key != nil {
			t.Fatalf("%s iterations: %v, want %v", n, err, want)
		}
		// Parsing takes well under a millisecond, a derivation at the cap
		// seconds; the margin is for slow, race-instrumented runners.
		if elapsed > 250*time.Millisecond {
			t.Fatalf("%s iterations refused after %v: work was done", n, elapsed)
		}
	}
}
