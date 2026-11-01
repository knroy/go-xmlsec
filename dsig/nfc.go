package dsig

import (
	"fmt"
	"hash"
	"sync"

	"github.com/knroy/go-xmlsec/v2"
	"golang.org/x/text/unicode/norm"
)

// nfcChunk is how much of a write nfcHash takes into its tail at a time, so
// that a large write is never copied whole.
const nfcChunk = 4096

// nfcHash passes octets on to a hash and checks them for NFC as they pass:
// it keeps only the tail after the last normalization boundary, checks what
// comes before it, and leaves the tail to finish.
type nfcHash struct {
	hash.Hash
	tail   []byte
	normal bool
}

func (h *nfcHash) Write(p []byte) (int, error) {
	for q := p; h.normal && len(q) > 0; {
		n := min(len(q), nfcChunk)
		h.tail, q = append(h.tail, q[:n]...), q[n:]
		// Normalization does not reach across a boundary, so the octets
		// before it are NFC exactly when they are on their own. A boundary
		// before a non-starter is the stream-safe cut after 30 of them,
		// which IsNormal refuses across: the run stays in the tail.
		if i := norm.NFC.LastBoundary(h.tail); i > 0 && (i == len(h.tail) || norm.NFC.Properties(h.tail[i:]).LeadCCC() == 0) {
			h.normal = norm.NFC.IsNormal(h.tail[:i])
			h.tail = h.tail[:copy(h.tail, h.tail[i:])]
		}
	}
	return h.Hash.Write(p)
}

// isNormal reports whether everything written is in NFC.
func (h *nfcHash) isNormal() bool {
	return h.normal && norm.NFC.IsNormal(h.tail)
}

// nfcTails holds tail buffers for nfcHash, which grow to about two
// chunks, so that a signature's references reuse them. One that grew
// further, over a run with no boundary, is not kept.
var nfcTails = sync.Pool{New: func() any { return new([]byte) }}

// checkNFC runs f, which writes octets into h, and with check set refuses
// them with xmlsec.ErrNotNFC unless they are in Unicode Normalization Form C
// (XML-DSig 8.1.3 and 7: a signature over non-NFC content may break when
// an intermediary normalizes it).
//
// ponytail: input with no boundary (a run of combining marks only) is kept
// whole until the end, as before; real text has a boundary every few runes.
func checkNFC(check bool, h hash.Hash, what string, f func(hash.Hash) error) error {
	if !check {
		return f(h)
	}
	tail := nfcTails.Get().(*[]byte)
	w := &nfcHash{Hash: h, tail: (*tail)[:0], normal: true}
	defer func() {
		if cap(w.tail) <= 2*nfcChunk {
			*tail = w.tail
			nfcTails.Put(tail)
		}
	}()
	if err := f(w); err != nil {
		return err
	}
	if !w.isNormal() {
		return fmt.Errorf("%w: %s", xmlsec.ErrNotNFC, what)
	}
	return nil
}
