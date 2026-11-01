package dsig

import (
	"crypto/sha256"
	"math/rand/v2"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"
)

// nfcHash, fed in any split, decides as norm.NFC.IsNormal does on the
// whole input.
func TestNFCHashSplits(t *testing.T) {
	pieces := []string{
		"a", "e", "é", "́", "̧", "̣", "̇", // combining marks, in and out of order
		"ᄀ", "ᅡ", "ᆨ", "각", "가", // Hangul jamo L V T and syllables
		"Å", "Ω", "̀", "̈́", "Å", // singletons and their targets
		"ཱི", "ཱི", // a decomposition that never recomposes
		"<", " ", "\n", "\xcc", "\x81", "\xff", // markup and broken UTF-8
	}
	r := rand.New(rand.NewPCG(1, 2))
	gen := func() string {
		var b strings.Builder
		for range r.IntN(40) {
			b.WriteString(pieces[r.IntN(len(pieces))])
		}
		return b.String()
	}
	inputs := []string{
		"", strings.Repeat("́", 100), "a" + strings.Repeat("́", 100), // no boundary, past the stream-safe limit
		strings.Repeat("̣́", 40) + "e",
		strings.Repeat("café ", 2000) + "é", // larger than one chunk
		strings.Repeat("x", nfcChunk-1) + "é",
	}
	for range 3000 {
		inputs = append(inputs, gen())
	}
	for _, in := range inputs {
		want := norm.NFC.IsNormal([]byte(in))
		for range 20 {
			h := &nfcHash{Hash: sha256.New(), normal: true}
			for rest := in; len(rest) > 0; {
				n := r.IntN(len(rest) + 1)
				h.Write([]byte(rest[:n]))
				rest = rest[n:]
			}
			if got := h.isNormal(); got != want {
				t.Fatalf("%q: got %v, want %v", in, got, want)
			}
		}
	}
}
