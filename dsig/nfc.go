package dsig

import (
	"fmt"
	"hash"

	"github.com/knroy/go-xmlsec"
	"golang.org/x/text/unicode/norm"
)

// nfcHash passes octets on to a hash and keeps them for an NFC check.
type nfcHash struct {
	hash.Hash
	buf []byte
}

func (h *nfcHash) Write(p []byte) (int, error) {
	h.buf = append(h.buf, p...)
	return h.Hash.Write(p)
}

// checkNFC runs f, which writes octets into h, and with check set refuses
// them with xmlsec.ErrNotNFC unless they are in Unicode Normalization Form C
// (XML-DSig 8.1.3 and 7: a signature over non-NFC content may break when
// an intermediary normalizes it).
//
// ponytail: buffers the octets of one reference or ds:SignedInfo; an
// incremental check across writes would bound memory if that matters.
func checkNFC(check bool, h hash.Hash, what string, f func(hash.Hash) error) error {
	if !check {
		return f(h)
	}
	w := &nfcHash{Hash: h}
	if err := f(w); err != nil {
		return err
	}
	if !norm.NFC.IsNormal(w.buf) {
		return fmt.Errorf("%w: %s", xmlsec.ErrNotNFC, what)
	}
	return nil
}
