package dsig_test

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/dsig"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
)

// peakHeap runs fn and returns how far the live heap rose above where it
// started, sampled every 200µs with the collector running often.
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

// memSizes is the input sizes, in MiB, of the Memory benchmarks: 1, or
// DSIG_PEAK_MIB, comma-separated.
//
//	DSIG_PEAK_MIB=1,10 go test -run '^$' -bench Memory -benchtime 1x ./dsig
func memSizes() []int {
	s := os.Getenv("DSIG_PEAK_MIB")
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

// memDoc is a document of about mib MiB of lines, some in x:drop, with
// non-ASCII text for the NFC check.
func memDoc(mib int) string {
	var b strings.Builder
	b.WriteString(`<r xmlns:x="urn:x">`)
	for i := 0; b.Len() < mib<<20; i++ {
		if i%10 == 0 {
			fmt.Fprintf(&b, `<x:drop n="%d">dropped</x:drop>`, i)
		} else {
			fmt.Fprintf(&b, `<l n="%d">café ünïcode line</l>`, i)
		}
	}
	b.WriteString(`</r>`)
	return b.String()
}

// memRun reports fn's peak heap and allocation per input byte.
func memRun(b *testing.B, size int, fn func() error) {
	for b.Loop() {
		var err error
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		peak := peakHeap(func() { err = fn() })
		runtime.ReadMemStats(&after)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(peak)/float64(size), "peak-B/B")
		b.ReportMetric(float64(after.TotalAlloc-before.TotalAlloc)/float64(size), "alloc-B/B")
	}
}

func memSign(b *testing.B, doc *xdm.Node, parent bool, ts ...dsig.TransformSpec) (*xdm.Node, *xdm.Node, error) {
	opts := dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References:                []dsig.Reference{{URI: "", Transforms: append([]dsig.TransformSpec{xpEnv}, ts...), DigestAlgorithm: xmlsec.DigestSHA256}},
	}
	if parent {
		opts.Parent = xmltree.DocumentElement(doc)
	}
	sig, err := signAt(&doc, newKey(b, rsaKey), opts)
	return doc, sig, err
}

// BenchmarkNFCMemory measures the NFC check Sign always runs, and Verify
// with RequireNFC, over the canonical form of a whole document.
func BenchmarkNFCMemory(b *testing.B) {
	for _, mib := range memSizes() {
		src := memDoc(mib)
		doc := parse(b, []byte(src))
		for _, parent := range []bool{false, true} {
			b.Run(fmt.Sprintf("sign/parent=%v/%dMiB", parent, mib), func(b *testing.B) {
				memRun(b, len(src), func() error {
					_, _, err := memSign(b, doc, parent, xpExc)
					return err
				})
			})
		}
		signed, sig, err := memSign(b, doc, true, xpExc)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("verify/%dMiB", mib), func(b *testing.B) {
			opts := dsig.VerifyOptions{Certificate: newKey(b, rsaKey).Certificate, RequireNFC: true}
			memRun(b, len(src), func() error {
				_, err := dsig.Verify(signed, sig, opts)
				return err
			})
		})
	}
}

// BenchmarkXPathMemory measures an XPath transform, which evaluates its
// expression once per input node.
func BenchmarkXPathMemory(b *testing.B) {
	for _, mib := range memSizes() {
		src := memDoc(mib)
		doc := parse(b, []byte(src))
		b.Run(fmt.Sprintf("%dMiB", mib), func(b *testing.B) {
			memRun(b, len(src), func() error {
				_, _, err := memSign(b, doc, false, xp(xpNoX, xpNS), xpExc)
				return err
			})
		})
	}
}

// BenchmarkXPathFilter2Memory measures an XPath Filter 2.0 transform that
// keeps most nodes (subtract) and one that keeps few (intersect).
func BenchmarkXPathFilter2Memory(b *testing.B) {
	for _, mib := range memSizes() {
		src := memDoc(mib)
		doc := parse(b, []byte(src))
		for _, f := range []dsig.TransformSpec{
			filter2(xpNS, "subtract", "//x:drop"),
			filter2(xpNS, "intersect", "/r/l[1]"),
		} {
			b.Run(fmt.Sprintf("%s/%dMiB", f.XPathFilters[0].Filter, mib), func(b *testing.B) {
				memRun(b, len(src), func() error {
					_, _, err := memSign(b, doc, false, f, xpExc)
					return err
				})
			})
		}
	}
}
