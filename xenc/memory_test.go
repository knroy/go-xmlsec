package xenc_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
	"github.com/knroy/go-xmlsec/v2/xenc"
)

var memKey = bytes.Repeat([]byte{1}, 16)

var memOpts = xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM}

// memItems is about n octets of element-dense content.
func memItems(n int) string {
	return strings.Repeat("<item id=\"x\">a line of text &amp; more</item>\n", max(n/48, 1))
}

// memDoc is a SOAP envelope with a header block of about header octets
// and a Body payload, in no namespace under a default one, of about body.
func memDoc(t testing.TB, header, body int) (doc, block, sec, bodyEl, payload *xdm.Node) {
	t.Helper()
	src := `<s:Envelope xmlns:s="` + xmlsec.NSSOAP11 + `"><s:Header><wsse:Security xmlns:wsse="` + xmlsec.NSWSSE + `"/>` +
		`<h:Block xmlns:h="urn:h">` + memItems(header) + `</h:Block></s:Header>` +
		`<s:Body xmlns="urn:d">` + "\n" + `<Payload xmlns="">` + memItems(body) + `</Payload>` + "\n" + `</s:Body></s:Envelope>`
	tree, err := xmlsec.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	doc = tree.Root
	env := xmltree.DocumentElement(doc)
	h, b := env.ChildElements()[0], env.ChildElements()[1]
	return doc, h.ChildElements()[1], h.ChildElements()[0], b, b.ChildElements()[0]
}

func memC14N(t testing.TB, n *xdm.Node) []byte {
	t.Helper()
	b, err := c14n.Bytes(n, c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestEncryptOutputUnchanged pins every encryption output, for a fixed key
// and random stream, to what the code wrote before it sealed in place and
// streamed its base64.
func TestEncryptOutputUnchanged(t *testing.T) {
	att := func() *xmlsec.Attachment {
		return &xmlsec.Attachment{ID: "a@x", Body: []byte("<doc/>\r\n"), MIMEHeaders: map[string][]string{
			"Content-Type": {"text/xml"}, "Content-Id": {"<a@x>"}, "Content-Description": {"d"}}}
	}
	cases := []struct {
		name string
		run  func(t *testing.T) []byte
		want string
	}{
		{"EncryptElement", func(t *testing.T) []byte {
			doc, _, _, _, payload := memDoc(t, 100, 300)
			out, err := xenc.EncryptElement(doc, payload, memKey, memOpts)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}, "0567fe237852c493f64822239faea3c5df66efe63a15ecc50cb910df2e3e3bcc"},
		{"EncryptContent", func(t *testing.T) []byte {
			doc, _, _, body, _ := memDoc(t, 100, 300)
			out, err := xenc.EncryptContent(doc, body, memKey, memOpts)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}, "7fe127544ebfb5b31806ecf38bcb84fb69f29b0901c1e51ccbb1e6cbd6d33404"},
		{"EncryptHeader", func(t *testing.T) []byte {
			doc, block, sec, _, _ := memDoc(t, 300, 100)
			out, err := xenc.EncryptHeader(doc, block, sec, memKey, memOpts)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}, "5c5738f267938f0cb62fba19840085c2a5dcfe9eb39aace79beca403e979be64"},
		{"EncryptOctets/inline", func(t *testing.T) []byte {
			_, ed, err := xenc.EncryptOctets([]byte("some octets of any length"), memKey, memOpts)
			if err != nil {
				t.Fatal(err)
			}
			return memC14N(t, ed)
		}, "b6f6d27409b76be97ee0471093e29866e1593de1f49372c0241ea0e6f7810a46"},
		{"EncryptOctets/reference", func(t *testing.T) []byte {
			o := memOpts
			o.CipherReferenceURI = "https://example.com/ct"
			ct, ed, err := xenc.EncryptOctets([]byte("some octets of any length"), memKey, o)
			if err != nil {
				t.Fatal(err)
			}
			return append(ct, memC14N(t, ed)...)
		}, "ddf469dc419cef2fe49048d73f54ce5cd26db6d11d18ce4f2d2269fa6e6fa37b"},
		{"EncryptAttachment/ContentOnly", func(t *testing.T) []byte {
			ct, ed, err := xenc.EncryptAttachment(att(), memKey, xmlsec.TransformAttachmentContentOnly, memOpts)
			if err != nil {
				t.Fatal(err)
			}
			return append(ct, memC14N(t, ed)...)
		}, "7cc2288ee48ebefb8c73b04453e3ddc4864c7a546c6f401442b2d850d59ae802"},
		{"EncryptAttachment/Complete", func(t *testing.T) []byte {
			ct, ed, err := xenc.EncryptAttachment(att(), memKey, xmlsec.TransformAttachmentComplete, memOpts)
			if err != nil {
				t.Fatal(err)
			}
			return append(ct, memC14N(t, ed)...)
		}, "63bae64da3207e0f8e832d93c22a83f42e69ec6a525c28144288715d92e6fcc3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cryptotest.SetGlobalRandom(t, 1)
			sum := sha256.Sum256(c.run(t))
			if got := hex.EncodeToString(sum[:]); got != c.want {
				t.Errorf("output sha256 %s, want %s", got, c.want)
			}
		})
	}
}

// TestDecryptLeavesCallerBytes checks that the ciphertext the caller holds,
// an attachment body or what ResolveURI returned, is not decrypted in place.
func TestDecryptLeavesCallerBytes(t *testing.T) {
	o := memOpts
	o.CipherReferenceURI = "https://example.com/ct"
	ct, ed, err := xenc.EncryptOctets([]byte("plaintext"), memKey, o)
	if err != nil {
		t.Fatal(err)
	}
	keep := bytes.Clone(ct)
	pt, err := xenc.DecryptData(covParse(t, string(memC14N(t, ed))), memKey, xenc.DecryptOptions{
		ResolveURI: func(string) ([]byte, error) { return ct, nil },
	})
	if err != nil || string(pt) != "plaintext" || !bytes.Equal(ct, keep) {
		t.Fatalf("ResolveURI: %q, %v; ciphertext changed: %v", pt, err, !bytes.Equal(ct, keep))
	}

	att := &xmlsec.Attachment{ID: "a@x", Body: []byte("body")}
	ct, ed, err = xenc.EncryptAttachment(att, memKey, xmlsec.TransformAttachmentContentOnly, memOpts)
	if err != nil || string(att.Body) != "body" {
		t.Fatalf("EncryptAttachment: %v, body %q", err, att.Body)
	}
	keep = bytes.Clone(ct)
	got, err := xenc.DecryptAttachment(ed, ct, memKey, xenc.DecryptOptions{})
	if err != nil || string(got.Body) != "body" || !bytes.Equal(ct, keep) {
		t.Fatalf("DecryptAttachment: %v; ciphertext changed: %v", err, !bytes.Equal(ct, keep))
	}

	plain := []byte("octets")
	if _, _, err := xenc.EncryptOctets(plain, memKey, memOpts); err != nil || string(plain) != "octets" {
		t.Fatalf("EncryptOctets: %v, plaintext %q", err, plain)
	}
}

// memPeak runs fn and returns the most heap it held at once beyond what was
// live before it, and what it allocated in all. As peakHeap in
// internal/swa, sampled every 200µs with GOGC at 10.
func memPeak(fn func()) (peak, alloc uint64) {
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var max atomic.Uint64
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > max.Load() {
				max.Store(m.HeapAlloc)
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
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if max.Load() > before.HeapAlloc {
		peak = max.Load() - before.HeapAlloc
	}
	return peak, after.TotalAlloc - before.TotalAlloc
}

// memBench runs fn under memPeak for each size XENC_PEAK_MIB lists, comma
// separated (default 1), reporting peak-B/B and alloc-B/B against the
// input size setup returns.
//
//	XENC_PEAK_MIB=1,10 go test -run '^$' -bench Memory -benchtime 1x ./xenc
func memBench(b *testing.B, setup func(b *testing.B, n int) (size int, fn func() error)) {
	sizes := os.Getenv("XENC_PEAK_MIB")
	if sizes == "" {
		sizes = "1"
	}
	for _, mib := range strings.Split(sizes, ",") {
		var n int
		fmt.Sscan(mib, &n)
		b.Run(mib+"MiB", func(b *testing.B) {
			size, fn := setup(b, n<<20)
			for b.Loop() {
				var err error
				peak, alloc := memPeak(func() { err = fn() })
				if err != nil {
					b.Fatal(err)
				}
				b.ReportMetric(float64(peak)/float64(size), "peak-B/B")
				b.ReportMetric(float64(alloc)/float64(size), "alloc-B/B")
			}
		})
	}
}

// BenchmarkEmitMemory measures the paths that emit a rebuilt document:
// DecryptAndReplace, DecryptHeader and EncryptHeader.
func BenchmarkEmitMemory(b *testing.B) {
	b.Run("DecryptAndReplace", func(b *testing.B) {
		memBench(b, func(b *testing.B, n int) (int, func() error) {
			doc, _, _, _, payload := memDoc(b, 100, n)
			out, err := xenc.EncryptElement(doc, payload, memKey, memOpts)
			if err != nil {
				b.Fatal(err)
			}
			tree, err := xmlsec.Parse(out)
			if err != nil {
				b.Fatal(err)
			}
			ed := xmltree.DocumentElement(tree.Root).ChildElements()[1].ChildElements()[0]
			return len(out), func() error {
				_, err := xenc.DecryptAndReplace(tree.Root, ed, memKey, xenc.DecryptOptions{})
				return err
			}
		})
	})
	b.Run("DecryptHeader", func(b *testing.B) {
		memBench(b, func(b *testing.B, n int) (int, func() error) {
			doc, block, sec, _, _ := memDoc(b, n, 100)
			out, err := xenc.EncryptHeader(doc, block, sec, memKey, memOpts)
			if err != nil {
				b.Fatal(err)
			}
			tree, err := xmlsec.Parse(out)
			if err != nil {
				b.Fatal(err)
			}
			eh := xmltree.DocumentElement(tree.Root).ChildElements()[0].ChildElements()[1]
			return len(out), func() error { _, err := xenc.DecryptHeader(tree.Root, eh, memKey, xenc.DecryptOptions{}); return err }
		})
	})
	b.Run("EncryptHeader", func(b *testing.B) {
		memBench(b, func(b *testing.B, n int) (int, func() error) {
			doc, block, sec, _, _ := memDoc(b, n, 100)
			return n, func() error { _, err := xenc.EncryptHeader(doc, block, sec, memKey, memOpts); return err }
		})
	})
}

// BenchmarkEncryptElementMemory measures EncryptElement, whose plaintext
// is sealed in place and whose CipherValue is encoded once.
func BenchmarkEncryptElementMemory(b *testing.B) {
	memBench(b, func(b *testing.B, n int) (int, func() error) {
		doc, _, _, _, payload := memDoc(b, 100, n)
		return n, func() error { _, err := xenc.EncryptElement(doc, payload, memKey, memOpts); return err }
	})
}

// BenchmarkEncryptContentMemory measures EncryptContent, whose children
// are serialized into one buffer.
func BenchmarkEncryptContentMemory(b *testing.B) {
	memBench(b, func(b *testing.B, n int) (int, func() error) {
		doc, _, _, body, _ := memDoc(b, 100, n)
		return n, func() error { _, err := xenc.EncryptContent(doc, body, memKey, memOpts); return err }
	})
}

// BenchmarkDecryptDataMemory measures DecryptData of an inline
// CipherValue, decrypted into the decoded buffer.
func BenchmarkDecryptDataMemory(b *testing.B) {
	memBench(b, func(b *testing.B, n int) (int, func() error) {
		_, ed, err := xenc.EncryptOctets(make([]byte, n), memKey, memOpts)
		if err != nil {
			b.Fatal(err)
		}
		return n, func() error { _, err := xenc.DecryptData(ed, memKey, xenc.DecryptOptions{}); return err }
	})
}

// BenchmarkEncryptAttachmentMemory measures an Attachment-Complete
// encryption, its headers and body built into the buffer sealed in place.
func BenchmarkEncryptAttachmentMemory(b *testing.B) {
	memBench(b, func(b *testing.B, n int) (int, func() error) {
		att := &xmlsec.Attachment{ID: "a@x", Body: make([]byte, n), MIMEHeaders: map[string][]string{"Content-Type": {"application/octet-stream"}}}
		return n, func() error {
			_, _, err := xenc.EncryptAttachment(att, memKey, xmlsec.TransformAttachmentComplete, memOpts)
			return err
		}
	})
}
