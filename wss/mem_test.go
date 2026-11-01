package wss

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
)

// peakHeap runs fn and returns the most heap it had in use at once beyond
// what was in use before, sampled; a copy of internal/swa's.
func peakHeap(fn func()) uint64 {
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak atomic.Uint64
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak.Load() {
				peak.Store(m.HeapAlloc)
			}
			select {
			case <-done:
				return
			case <-time.After(200 * time.Microsecond):
			}
		}
	}()
	fn()
	close(done)
	<-stopped
	if peak.Load() < before.HeapAlloc {
		return 0
	}
	return peak.Load() - before.HeapAlloc
}

// memSizes returns the sizes, in MiB, WSS_PEAK_MIB names, comma-separated;
// 1 by default.
func memSizes() []int {
	s := os.Getenv("WSS_PEAK_MIB")
	if s == "" {
		s = "1"
	}
	var out []int
	for _, f := range strings.Split(s, ",") {
		var n int
		fmt.Sscan(f, &n)
		out = append(out, n)
	}
	return out
}

// nullFlood returns BinarySecurityTokens of about size bytes whose DER is
// millions of 2-byte NULLs: a PkiPath of them, and a PKCS7 SignedData with
// them as its fields.
func nullFlood(t testing.TB, size int) (pki, pkcs7 *xdm.Node) {
	nulls := bytes.Repeat([]byte{5, 0}, size*3/4/2)
	seq := der(asn1.ClassUniversal, asn1.TagSequence, nulls)
	ci := der(asn1.ClassUniversal, asn1.TagSequence, mustMarshal(oidSignedData), der(asn1.ClassContextSpecific, 0, seq))
	tok := func(vt string, b []byte) *xdm.Node {
		doc := bst(`EncodingType="`+xmlsec.BSTEncodingBase64+`" ValueType="`+vt+`"`, base64.StdEncoding.EncodeToString(b))
		tree, err := xmlsec.Parse([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		return xmltree.DocumentElement(tree.Root)
	}
	return tok(xmlsec.BSTValueTypeX509PKIPath, seq), tok(xmlsec.BSTValueTypePKCS7, ci)
}

// A token of millions of tiny elements is refused, before the signature is
// checked, with no more heap than about twice the token: the base64 decode,
// not a slice of every element.
func TestBinarySecurityTokenFloodHeap(t *testing.T) {
	const size = 8 << 20
	pki, pkcs7 := nullFlood(t, size)
	for name, c := range map[string]struct {
		el   *xdm.Node
		want error
	}{"PkiPath": {pki, xmlsec.ErrUnsupportedKeyInfo}, "PKCS7": {pkcs7, xmlsec.ErrMalformed}} {
		t.Run(name, func(t *testing.T) {
			var err error
			peak := peakHeap(func() { _, err = ParseBinarySecurityToken(c.el) })
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if peak > 2*size {
				t.Fatalf("peak heap %d for a %d-byte token", peak, size)
			}
		})
	}
}

// BenchmarkBinarySecurityTokenFloodMemory reports the peak heap per token
// byte of refusing a token of tiny elements. WSS_PEAK_MIB sets the sizes.
//
//	WSS_PEAK_MIB=1,10 go test -run '^$' -bench FloodMemory -benchtime 1x ./wss
func BenchmarkBinarySecurityTokenFloodMemory(b *testing.B) {
	for _, mib := range memSizes() {
		pki, pkcs7 := nullFlood(b, mib<<20)
		for name, el := range map[string]*xdm.Node{"PkiPath": pki, "PKCS7": pkcs7} {
			b.Run(fmt.Sprintf("%s/%dMiB", name, mib), func(b *testing.B) {
				for b.Loop() {
					peak := peakHeap(func() { _, _ = ParseBinarySecurityToken(el) })
					b.ReportMetric(float64(peak)/float64(mib<<20), "peak-B/B")
				}
			})
		}
	}
}
