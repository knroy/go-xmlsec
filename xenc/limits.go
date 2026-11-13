package xenc

import (
	"fmt"

	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
)

// DefaultMaxEncryptedParts is the number of xenc:EncryptedData,
// xenc:EncryptedKey and xenc11:DerivedKey elements, together, one document
// may hold when DecryptOptions.MaxEncryptedParts is zero. A document
// holding more is refused with xmlsec.ErrLimitExceeded by every Decrypt,
// Unwrap and Derive function, before any key is looked up, any ciphertext
// dereferenced or any cryptographic work done. Each call costs time in the
// size of the document, so bounding the parts of one message keeps
// decrypting all of them linear in it.
const DefaultMaxEncryptedParts = 64

// checkParts refuses el's document when it holds more encryption parts
// than opts allows. A nil el is left to the caller's own element check.
func checkParts(el *xdm.Node, opts DecryptOptions) error {
	if el == nil {
		return nil
	}
	limit := opts.MaxEncryptedParts
	if limit <= 0 {
		limit = DefaultMaxEncryptedParts
	}
	n := 0
	xmltree.Walk(el.Root(), func(e *xdm.Node) {
		if e.IsElement(xmlsec.NSXEnc, "EncryptedData") || e.IsElement(xmlsec.NSXEnc, "EncryptedKey") ||
			e.IsElement(xmlsec.NSXEnc11, "DerivedKey") {
			n++
		}
	})
	if n > limit {
		return fmt.Errorf("%w: %d xenc:EncryptedData, xenc:EncryptedKey and xenc11:DerivedKey elements in one document, more than %d",
			xmlsec.ErrLimitExceeded, n, limit)
	}
	return nil
}
