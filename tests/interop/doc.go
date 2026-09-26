// Package interop holds the differential harness that checks whole signed
// and encrypted documents against independent implementations. The tests
// are build-tagged `interop` and need the reference tools on the PATH; see
// docs/testing.md.
//
// Canonicalization itself is proved upstream in go-xml. This proves that a
// signature or ciphertext produced here is accepted elsewhere, and the
// reverse.
package interop
