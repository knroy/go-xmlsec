package dsig_test

import (
	"encoding/base64"
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

// BenchmarkNFCRefsMemory measures the NFC check over 50 references of
// 9 KB, where its working buffer is a large part of what it costs.
func BenchmarkNFCRefsMemory(b *testing.B) {
	var src strings.Builder
	src.WriteString(`<r>`)
	var refs []dsig.Reference
	for i := range 50 {
		fmt.Fprintf(&src, `<e xml:id="e%d">%s</e>`, i, strings.Repeat("café ünïcode line ", 500))
		refs = append(refs, dsig.Reference{URI: fmt.Sprintf("#e%d", i), Transforms: []dsig.TransformSpec{xpExc}, DigestAlgorithm: xmlsec.DigestSHA256})
	}
	src.WriteString(`</r>`)
	doc := parse(b, []byte(src.String()))
	opts := dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References:                refs,
		Parent:                    xmltree.DocumentElement(doc),
	}
	var signed, sig *xdm.Node
	b.Run("sign", func(b *testing.B) {
		memRun(b, src.Len(), func() error {
			d := xmlsec.NewDocument(doc)
			var err error
			sig, err = dsig.Sign(d, newKey(b, rsaKey), opts)
			signed = d.Root()
			return err
		})
	})
	b.Run("verify", func(b *testing.B) {
		memRun(b, src.Len(), func() error {
			_, err := dsig.Verify(signed, sig, dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey, RequireNFC: true})
			return err
		})
	})
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

// BenchmarkBase64TransformMemory measures the base64 transform over the
// text of an element, wrapped at 76 columns: as the last transform, and
// followed by canonicalization of the XML it decodes to.
func BenchmarkBase64TransformMemory(b *testing.B) {
	for _, mib := range memSizes() {
		enc := base64.StdEncoding.EncodeToString([]byte(memDoc(mib)))
		var w strings.Builder
		w.WriteString(`<r><o xml:id="o">`)
		for len(enc) > 76 {
			w.WriteString(enc[:76] + "\n")
			enc = enc[76:]
		}
		w.WriteString(enc + `</o></r>`)
		src := w.String()
		for _, c := range []struct {
			name string
			ts   []dsig.TransformSpec
		}{
			{"last", []dsig.TransformSpec{{Algorithm: xmlsec.TransformBase64}}},
			{"then-c14n", []dsig.TransformSpec{{Algorithm: xmlsec.TransformBase64}, xpExc}},
		} {
			doc := parse(b, []byte(src))
			opts := dsig.SignOptions{
				SignatureAlgorithm:        xmlsec.SigRSASHA256,
				CanonicalizationAlgorithm: string(c14n.Exclusive10),
				References:                []dsig.Reference{{URI: "#o", Transforms: c.ts, DigestAlgorithm: xmlsec.DigestSHA256}},
				Parent:                    xmltree.DocumentElement(doc),
			}
			var signed, sig *xdm.Node
			b.Run(fmt.Sprintf("sign/%s/%dMiB", c.name, mib), func(b *testing.B) {
				memRun(b, len(src), func() error {
					d := xmlsec.NewDocument(doc)
					var err error
					sig, err = dsig.Sign(d, newKey(b, rsaKey), opts)
					signed = d.Root()
					return err
				})
			})
			b.Run(fmt.Sprintf("verify/%s/%dMiB", c.name, mib), func(b *testing.B) {
				memRun(b, len(src), func() error {
					_, err := dsig.Verify(signed, sig, dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey})
					return err
				})
			})
		}
	}
}

// memSheet copies its input.
const memSheet = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">` +
	`<xsl:template match="@*|node()"><xsl:copy><xsl:apply-templates select="@*|node()"/></xsl:copy></xsl:template>` +
	`</xsl:stylesheet>`

// BenchmarkXSLTMemory measures an XSLT transform that copies a document, as
// the last transform.
func BenchmarkXSLTMemory(b *testing.B) {
	for _, mib := range memSizes() {
		src := memDoc(mib)
		sheet := xmltree.DocumentElement(parse(b, []byte(memSheet)))
		doc := parse(b, []byte(src))
		ts := dsig.TransformSpec{Algorithm: xmlsec.TransformXSLT, Stylesheet: sheet}
		b.Run(fmt.Sprintf("sign/%dMiB", mib), func(b *testing.B) {
			memRun(b, len(src), func() error {
				_, _, err := memSign(b, doc, false, ts)
				return err
			})
		})
		signed, sig, err := memSign(b, doc, true, ts)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("verify/%dMiB", mib), func(b *testing.B) {
			opts := dsig.VerifyOptions{Certificate: newKey(b, rsaKey).Certificate, AllowedXSLTStylesheets: []*xdm.Node{sheet}}
			memRun(b, len(src), func() error {
				_, err := dsig.Verify(signed, sig, opts)
				return err
			})
		})
	}
}
