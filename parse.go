package xmlsec

import (
	"bytes"
	"errors"
	"fmt"

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

// ParseLimits tightens the pinned parse limits for one call. A zero field
// keeps the pinned value; a value above it is refused, because the limits
// are part of what this module promises to accept.
type ParseLimits struct {
	MaxBytes int64
	MaxDepth int
	MaxNodes int
}

// ParseWithLimits parses like Parse under limits at most as generous as the
// pinned ones. Memory use scales with MaxBytes and MaxNodes, so a server
// sets them to what its profile needs. Exceeding a limit is
// ErrLimitExceeded.
func ParseWithLimits(b []byte, l ParseLimits) (*xdm.Tree, error) {
	bytesLimit, err := tighten("MaxBytes", l.MaxBytes, MaxParseBytes)
	if err != nil {
		return nil, err
	}
	depth, err := tighten("MaxDepth", int64(l.MaxDepth), MaxParseDepth)
	if err != nil {
		return nil, err
	}
	nodes, err := tighten("MaxNodes", int64(l.MaxNodes), MaxParseNodes)
	if err != nil {
		return nil, err
	}
	opts := xdm.ParseOptions{
		MaxDepth: int(depth),
		MaxBytes: bytesLimit,
		MaxNodes: int(nodes),
	}.WithEntityBudget(xdm.NewEntityBudget())
	tree, err := xdm.Parse(bytes.NewReader(b), opts)
	if errors.Is(err, xdm.ErrResourceLimit) {
		return nil, fmt.Errorf("%w: %w", ErrLimitExceeded, err)
	}
	return tree, err
}

// tighten returns v, or pinned when v is zero, refusing a negative value or
// one above pinned.
func tighten(name string, v, pinned int64) (int64, error) {
	switch {
	case v == 0:
		return pinned, nil
	case v < 0 || v > pinned:
		return 0, fmt.Errorf("xmlsec: %s %d outside 1..%d; limits can only be tightened", name, v, pinned)
	}
	return v, nil
}

// Parse parses a document with the one set of options this module verifies
// against. The parse is part of the signature: the same octets parsed with
// different options can canonicalize differently, so these options are not
// configurable.
//
// A DOCTYPE is refused and no EntityResolver is ever supplied.
//
// Memory use can reach about 40 times len(b) within the limits above, before
// anything is authenticated. Cap the size of b to what the profile needs, or
// use ParseWithLimits.
func Parse(b []byte) (*xdm.Tree, error) {
	return ParseWithLimits(b, ParseLimits{})
}
