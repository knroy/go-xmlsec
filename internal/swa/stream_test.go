package swa

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xmlsec/v2"
)

// legacyContent and legacyComplete are Content and Complete as v2.0.0
// shipped them, building the whole canonical form with c14n.Bytes. The
// streamed forms must match them octet for octet.
func legacyContent(att *xmlsec.Attachment) ([]byte, error) {
	sel, err := selected(att)
	if err != nil {
		return nil, err
	}
	return legacyBody(sel["Content-Type"], att.Body)
}

func legacyComplete(att *xmlsec.Attachment) ([]byte, error) {
	sel, err := selected(att)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, name := range Headers {
		v, ok := sel[name]
		if !ok {
			continue
		}
		c, err := canonicalValue(name, v)
		if err != nil {
			return nil, err
		}
		out = append(out, name+":"+c+"\r\n"...)
	}
	body, err := legacyBody(sel["Content-Type"], att.Body)
	return append(out, body...), err
}

func legacyBody(contentType string, body []byte) ([]byte, error) {
	mt, _, err := mediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("%w: Content-Type: %v", xmlsec.ErrMalformed, err)
	}
	switch {
	case mt == "text/xml", mt == "application/xml", strings.HasSuffix(mt, "+xml"):
		tree, err := xmlsec.Parse(body)
		if err != nil {
			return nil, fmt.Errorf("%w: XML attachment: %w", xmlsec.ErrMalformed, err)
		}
		return c14n.Bytes(tree.Root, c14n.Options{Algorithm: c14n.Exclusive10})
	case strings.HasPrefix(mt, "text/"):
		b := bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))
		b = bytes.ReplaceAll(b, []byte("\r"), []byte("\n"))
		return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")), nil
	}
	return body, nil
}

// largeXML is an element-dense document of about n bytes, the shape whose
// parsed tree costs the most per input byte.
func largeXML(n int) []byte { return repeatedXML(n, `<e/>`) }

// invoiceXML is a document of about n bytes shaped like invoice lines:
// short elements with text and an attribute, about 30 bytes a node.
func invoiceXML(n int) []byte {
	return repeatedXML(n, `<p:Line id="1"><Item>Widget, blue</Item><Qty unit="EA">12</Qty><Price>9.99</Price></p:Line>`)
}

func repeatedXML(n int, unit string) []byte {
	var b bytes.Buffer
	b.WriteString(`<r xmlns="urn:r" xmlns:p="urn:p"><p:s z="2" a="1">`)
	for b.Len() < n {
		b.WriteString(unit)
	}
	b.WriteString(`</p:s></r>`)
	return b.Bytes()
}

var xmlCorpus = map[string]string{
	"namespaces":         `<a:r xmlns:a="urn:a" xmlns:b="urn:b" xmlns:unused="urn:u"><b:c a:x="1"/></a:r>`,
	"inherited xmlns":    `<r xmlns="urn:d" xmlns:p="urn:p"><c><p:d><e xmlns="urn:d"/></p:d><f xmlns=""/></c></r>`,
	"comments":           "<!-- before --><r><!-- in --><c>t<!--x-->u</c></r><!-- after -->",
	"PIs":                "<?xml version=\"1.0\"?><?pi before?><r><?pi in  data ?></r><?pi after?>",
	"CDATA":              `<r><![CDATA[<not markup> & ]]]]><![CDATA[> ]]></r>`,
	"entities":           `<r a="&lt;&amp;&quot;&#9;&#10;&#13;">&lt;&gt;&amp;&#xD;&#x20AC;&apos;</r>`,
	"attribute sorting":  `<r xmlns:z="urn:a" xmlns:a="urn:z" z:b="1" a:b="2" c="3" b="4" xml:lang="en"/>`,
	"whitespace":         "<r  a = '1'\r\n  b='2\t3' >\r\n line\r\n</r  >\n",
	"xml prefix":         `<r xml:space="preserve" xml:lang="en"><c xml:lang="fr"/></r>`,
	"empty default":      `<r xmlns="urn:x"><c xmlns=""><d/></c></r>`,
	"utf8 and BOM":       "\xef\xbb\xbf<r>café \U0001F600</r>",
	"DOCTYPE refused":    `<!DOCTYPE r [<!ENTITY e "x">]><r>&e;</r>`,
	"malformed":          `<r><c></r>`,
	"relative namespace": `<r xmlns="rel"/>`,
	"large":              string(largeXML(2 << 20)),
}

func corpus() []*xmlsec.Attachment {
	var atts []*xmlsec.Attachment
	for _, ct := range []string{"text/xml", "application/xml; charset=UTF-8", "application/soap+xml"} {
		for _, body := range xmlCorpus {
			atts = append(atts, attachment(ct, []byte(body)))
		}
	}
	for _, body := range []string{"", "a\r\nb\rc\nd\r\r\n\n\r", "\r", "\n", "no ending", strings.Repeat("line\r\n", 100_000)} {
		atts = append(atts, attachment("text/plain", []byte(body)))
	}
	atts = append(atts,
		attachment("application/octet-stream", []byte{0, 1, '\r', '\n', 0xff}),
		attachment("not a type", []byte("x")),
		&xmlsec.Attachment{Body: []byte("default\ntype")},
		&xmlsec.Attachment{Body: []byte("<r/>"), MIMEHeaders: map[string][]string{
			"Content-Type": {"text/xml (comment); charset=utf-8"}, "Content-ID": {"<a@b>"},
			"Content-Description": {"desc (c)"}, "Content-Disposition": {`attachment; filename="A.XML"`},
		}},
		&xmlsec.Attachment{Body: []byte("<r/>"), MIMEHeaders: map[string][]string{"Content-Disposition": {"; bad"}}},
	)
	return atts
}

func attachment(contentType string, body []byte) *xmlsec.Attachment {
	return &xmlsec.Attachment{Body: body, MIMEHeaders: map[string][]string{"Content-Type": {contentType}}}
}

// sameOutput fails unless the streamed write produces what the legacy
// function returned, digest included, or fails the same way.
func sameOutput(t *testing.T, att *xmlsec.Attachment, legacy func(*xmlsec.Attachment) ([]byte, error),
	collected func(*xmlsec.Attachment) ([]byte, error), write func(w io.Writer, att *xmlsec.Attachment) error) {
	t.Helper()
	want, wantErr := legacy(att)
	got, gotErr := collected(att)
	h := sha256.New()
	writeErr := write(h, att)
	if (wantErr == nil) != (gotErr == nil) || (wantErr == nil) != (writeErr == nil) {
		t.Fatalf("errors differ: legacy %v, collected %v, streamed %v", wantErr, gotErr, writeErr)
	}
	if wantErr != nil {
		if wantErr.Error() != gotErr.Error() || wantErr.Error() != writeErr.Error() {
			t.Fatalf("errors differ: legacy %v, collected %v, streamed %v", wantErr, gotErr, writeErr)
		}
		return
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("octets differ:\n got %.200q\nwant %.200q", got, want)
	}
	if sum := sha256.Sum256(want); !bytes.Equal(h.Sum(nil), sum[:]) {
		t.Fatalf("streamed digest differs from the digest of the legacy octets")
	}
}

func TestStreamedMatchesLegacy(t *testing.T) {
	for i, att := range corpus() {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			sameOutput(t, att, legacyContent, Content, WriteContent)
			sameOutput(t, att, legacyComplete, Complete, WriteComplete)
		})
	}
}

// The corpus must exercise both outcomes, or the error comparison above
// proves nothing.
func TestCorpusHasErrors(t *testing.T) {
	var ok, failed int
	for _, att := range corpus() {
		if _, err := legacyContent(att); err != nil {
			failed++
		} else {
			ok++
		}
	}
	if ok == 0 || failed < 4 {
		t.Fatalf("%d ok, %d failed", ok, failed)
	}
}

var errSink = errors.New("sink full")

type failingWriter struct{ left int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if len(p) > w.left {
		return 0, errSink
	}
	w.left -= len(p)
	return len(p), nil
}

// A write error from w reaches the caller, for each kind of content.
func TestWriteError(t *testing.T) {
	for _, att := range []*xmlsec.Attachment{
		attachment("text/xml", largeXML(1<<20)),
		attachment("text/plain", bytes.Repeat([]byte("a\n"), 1<<19)),
		attachment("application/octet-stream", make([]byte, 1<<20)),
	} {
		if err := WriteContent(&failingWriter{left: 1000}, att); !errors.Is(err, errSink) {
			t.Errorf("%s: got %v", att.MIMEHeaders["Content-Type"], err)
		}
	}
	att := attachment("text/xml", []byte("<r/>"))
	if err := WriteComplete(&failingWriter{}, att); !errors.Is(err, errSink) {
		t.Errorf("headers: got %v", err)
	}
}

func FuzzWriteContent(f *testing.F) {
	for _, body := range xmlCorpus {
		if len(body) < 4096 {
			f.Add("text/xml", []byte(body))
		}
	}
	f.Add("text/plain", []byte("a\r\nb\rc\nd\r\r\n"))
	f.Add("application/octet-stream", []byte{0, 1})
	f.Fuzz(func(t *testing.T, contentType string, body []byte) {
		att := attachment(contentType, body)
		sameOutput(t, att, legacyContent, Content, WriteContent)
		sameOutput(t, att, legacyComplete, Complete, WriteComplete)
	})
}

// peakHeap runs fn and returns the most heap it held at once beyond what
// was live before it, sampled every 200µs with GOGC at 10 so that the
// sample is close to live data rather than uncollected garbage.
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

// BenchmarkContentPeakHeap reports the peak heap per attachment byte of
// digesting an attachment, the old way (canonical form built in memory, then
// hashed) and streamed: an element-dense XML document, one shaped like
// invoice lines, and a text/plain one with LF line endings. SWA_PEAK_MIB sets the sizes, comma-separated.
// xmlsec.Parse refuses more than 64 MiB or 10,000,000 nodes, which an
// element-dense document reaches at about 38 MiB.
//
//	SWA_PEAK_MIB=1,10,60 go test -run '^$' -bench ContentPeakHeap -benchtime 1x ./internal/swa
func BenchmarkContentPeakHeap(b *testing.B) {
	sizes := os.Getenv("SWA_PEAK_MIB")
	if sizes == "" {
		sizes = "1"
	}
	textLines := func(n int) []byte { return bytes.Repeat([]byte("a line of text\n"), n/15) }
	shapes := []struct {
		name, contentType string
		make              func(int) []byte
	}{{"dense", "text/xml", largeXML}, {"invoice", "text/xml", invoiceXML}, {"text", "text/plain", textLines}}
	for _, mib := range strings.Split(sizes, ",") {
		var n int
		fmt.Sscan(mib, &n)
		for _, shape := range shapes {
			att := attachment(shape.contentType, shape.make(n<<20))
			size := float64(len(att.Body))
			b.Run(shape.name+"/"+mib+"MiB/legacy", func(b *testing.B) {
				for b.Loop() {
					var err error
					peak := peakHeap(func() {
						var out []byte
						if out, err = legacyContent(att); err == nil {
							sha256.Sum256(out)
						}
					})
					if err != nil {
						b.Skip(err)
					}
					b.ReportMetric(float64(peak)/size, "peak-B/B")
				}
			})
			b.Run(shape.name+"/"+mib+"MiB/streamed", func(b *testing.B) {
				for b.Loop() {
					var err error
					peak := peakHeap(func() { err = WriteContent(sha256.New(), att) })
					if err != nil {
						b.Skip(err)
					}
					b.ReportMetric(float64(peak)/size, "peak-B/B")
				}
			})
		}
	}
}
