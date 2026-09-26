package xmlsec

import (
	"bytes"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
)

// Resource limits, set explicitly so that a change to an upstream default
// cannot silently alter what this module accepts. The two depth limits
// differ: a document can parse and then fail to canonicalize, which is a
// correct and bounded outcome.
const (
	MaxParseDepth = 1000
	MaxParseBytes = 64 << 20
	MaxParseNodes = 10_000_000
	MaxC14NDepth  = 500
)

func init() {
	// ponytail: process-global, as c14n exposes it; this also bounds any
	// other c14n user in the process.
	c14n.MaxDepth = MaxC14NDepth
}

// Parse parses a document with the one set of options this module verifies
// against. The parse is part of the signature: the same octets parsed with
// different options can canonicalize differently, so these options are not
// configurable.
//
// A DOCTYPE is refused and no EntityResolver is ever supplied.
//
// Memory use can reach about 40 times len(b) within the limits above, before
// anything is authenticated. Cap the size of b to what the profile needs.
func Parse(b []byte) (*xdm.Tree, error) {
	opts := xdm.ParseOptions{
		MaxDepth: MaxParseDepth,
		MaxBytes: MaxParseBytes,
		MaxNodes: MaxParseNodes,
	}.WithEntityBudget(xdm.NewEntityBudget())
	return xdm.Parse(bytes.NewReader(b), opts)
}
