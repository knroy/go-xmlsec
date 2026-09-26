package wss

import (
	"io"
	"testing"
)

// SetRandReader makes generated wsu:Id values come from r for the rest of
// t, so that external tests in this directory (package wss_test) can produce
// reproducible documents. It exists only in test builds.
func SetRandReader(t testing.TB, r io.Reader) {
	t.Helper()
	old := randReader
	randReader = r
	t.Cleanup(func() { randReader = old })
}
