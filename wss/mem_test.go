package wss

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
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

// A Header holds the wsse:Security element of the latest tree, not of the
// tree NewHeader made, which would keep that whole tree alive.
func TestHeaderHoldsLatestTree(t *testing.T) {
	doc := newDoc(t, env11)
	h, err := NewHeader(doc, xmlsec.NSSOAP11, "", false)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := h.AddBinarySecurityToken(testCert(t, "c"), nil, xmlsec.BSTValueTypeX509v3); err != nil {
			t.Fatal(err)
		}
		if h.el.Root() != doc.Root() {
			t.Fatal("Header holds an earlier tree")
		}
	}
}

// checkTokenOrder outside a header refuses exactly the pairs that a
// numbering of every element in document order refuses, which it once
// built, and a reference in another tree.
func TestCheckTokenOrderDocumentOrder(t *testing.T) {
	doc := parseDoc(t, `<r><a><b/><c><d/></c></a><e/><f><g/></f></r>`)
	pos := map[*xdm.Node]int{}
	var els []*xdm.Node
	xmltree.Walk(doc, func(e *xdm.Node) { pos[e] = len(pos) + 1; els = append(els, e) })
	for _, str := range els {
		for _, tok := range els {
			if got, want := checkTokenOrder(doc, str, tok) != nil, pos[str] <= pos[tok]; got != want {
				t.Fatalf("%s, %s: refused %v, want %v", str.Name().Local, tok.Name().Local, got, want)
			}
		}
	}
	other := xmltree.DocumentElement(parseDoc(t, `<r><a/></r>`))
	if checkTokenOrder(doc, other.FirstChild(), els[0]) == nil || checkTokenOrder(doc, els[1], other) == nil {
		t.Fatal("a node of another tree accepted")
	}
}

// BenchmarkCheckTokenOrderMemory reports the heap per document byte of
// checking a reference's order outside a header. WSS_PEAK_MIB sets the
// sizes.
func BenchmarkCheckTokenOrderMemory(b *testing.B) {
	for _, mib := range memSizes() {
		var s strings.Builder
		s.WriteString("<r><t/>")
		for s.Len() < mib<<20 {
			s.WriteString("<i/>")
		}
		s.WriteString("<s/></r>")
		tree, err := xmlsec.Parse([]byte(s.String()))
		if err != nil {
			b.Fatal(err)
		}
		r := xmltree.DocumentElement(tree.Root)
		tok, str := r.FirstChild(), r.LastChild()
		b.Run(fmt.Sprintf("%dMiB", mib), func(b *testing.B) {
			for b.Loop() {
				peak := peakHeap(func() { _ = checkTokenOrder(tree.Root, str, tok) })
				b.ReportMetric(float64(peak)/float64(s.Len()), "peak-B/B")
			}
		})
	}
}

// BenchmarkIDForMemory reports the heap per document byte of checking a
// new ID against a document where every element has one. WSS_PEAK_MIB sets
// the sizes.
func BenchmarkIDForMemory(b *testing.B) {
	for _, mib := range memSizes() {
		var s strings.Builder
		s.WriteString(`<r xmlns:wsu="` + xmlsec.NSWSU + `">`)
		for i := 0; s.Len() < mib<<20; i++ {
			fmt.Fprintf(&s, `<i wsu:Id="id-%d"/>`, i)
		}
		s.WriteString("</r>")
		tree, err := xmlsec.Parse([]byte(s.String()))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("%dMiB", mib), func(b *testing.B) {
			for b.Loop() {
				peak := peakHeap(func() { _, _ = idFor(tree.Root, "fresh") })
				b.ReportMetric(float64(peak)/float64(s.Len()), "peak-B/B")
			}
		})
	}
}

// mustParse parses s for a benchmark.
func mustParse(tb testing.TB, s string) *xdm.Node {
	tree, err := xmlsec.Parse([]byte(s))
	if err != nil {
		tb.Fatal(err)
	}
	return tree.Root
}

// wideShapes returns, for a document of about size bytes, receive-side
// calls on an element with very many element children.
func wideShapes(tb testing.TB, size int) map[string]func() {
	fill := strings.Repeat("<x/>", size/4)
	env := `<soap:Envelope xmlns:soap="` + xmlsec.NSSOAP11 + `" xmlns:wsse="` + xmlsec.NSWSSE + `" xmlns:wsu="` + xmlsec.NSWSU +
		`" xmlns:wsse11="` + xmlsec.NSWSSE11 + `" xmlns:ds="` + xmlsec.NSDSig + `">`
	envDoc := mustParse(tb, env+`<soap:Header>`+fill+`<wsse:Security/></soap:Header><soap:Body/></soap:Envelope>`)
	secDoc := mustParse(tb, env+`<soap:Header><wsse:Security><wsse:BinarySecurityToken wsu:Id="t" ValueType="`+xmlsec.BSTValueTypeX509v3+`">AA==</wsse:BinarySecurityToken>`+fill+
		`<ds:Signature><ds:SignedInfo/><ds:SignatureValue>AA==</ds:SignatureValue><ds:KeyInfo><wsse:SecurityTokenReference><wsse:Reference URI="#t" ValueType="`+xmlsec.BSTValueTypeX509v3+
		`"/></wsse:SecurityTokenReference></ds:KeyInfo></ds:Signature><wsse11:SignatureConfirmation wsu:Id="c" Value="AA=="/></wsse:Security></soap:Header><soap:Body/></soap:Envelope>`)
	sec, err := FindHeader(secDoc, xmlsec.NSSOAP11, "")
	if err != nil {
		tb.Fatal(err)
	}
	ref := sec.LastChild().PrevSibling().LastChild().FirstChild()
	ts := xmltree.DocumentElement(mustParse(tb, `<wsu:Timestamp xmlns:wsu="`+xmlsec.NSWSU+`">`+fill+`</wsu:Timestamp>`))
	str := xmltree.DocumentElement(mustParse(tb, `<wsse:SecurityTokenReference xmlns:wsse="`+xmlsec.NSWSSE+`">`+fill+`</wsse:SecurityTokenReference>`))
	cert := &x509.Certificate{SerialNumber: big.NewInt(1)}
	return map[string]func(){
		"FindHeader":                  func() { _, _ = FindHeader(envDoc, xmlsec.NSSOAP11, "") },
		"FindTimestamp":               func() { _, _ = FindTimestamp(sec) },
		"SignatureValues":             func() { _, _ = SignatureValues(sec) },
		"CheckSignatureConfirmations": func() { _ = CheckSignatureConfirmations(sec, [][]byte{{0}}) },
		"ResolveStrict":               func() { _, _ = ResolveSecurityTokenReferenceStrict(secDoc, ref) },
		"ParseTimestamp":              func() { _, _ = ParseTimestamp(ts) },
		"CheckSTR":                    func() { _ = CheckSecurityTokenReference(str) },
		"MatchSTR":                    func() { _ = MatchSecurityTokenReference(str, cert) },
	}
}

// Each receive-side check of an element with very many element children
// reads only the children it needs, and holds no slice of them.
func TestWideElementHeap(t *testing.T) {
	const size = 4 << 20
	for name, f := range wideShapes(t, size) {
		if peak := peakHeap(f); peak > size/4 {
			t.Errorf("%s: peak heap %d for a %d-byte element", name, peak, size)
		}
	}
}

// BenchmarkWideElementMemory reports the peak heap per document byte of
// each receive-side check of an element with very many element children.
// WSS_PEAK_MIB sets the sizes.
func BenchmarkWideElementMemory(b *testing.B) {
	for _, mib := range memSizes() {
		for name, f := range wideShapes(b, mib<<20) {
			b.Run(fmt.Sprintf("%s/%dMiB", name, mib), func(b *testing.B) {
				for b.Loop() {
					b.ReportMetric(float64(peakHeap(f))/float64(mib<<20), "peak-B/B")
				}
			})
		}
	}
}

// longValueShapes returns the errors for received values of about size
// bytes that an error message quotes.
func longValueShapes(tb testing.TB, size int) map[string]func() error {
	long := strings.Repeat("\u0085", size/2)
	ts := xmltree.DocumentElement(mustParse(tb, `<wsu:Timestamp xmlns:wsu="`+xmlsec.NSWSU+`"><wsu:Created>`+long+`</wsu:Created></wsu:Timestamp>`))
	tok := xmltree.DocumentElement(mustParse(tb, bst(`ValueType="`+long+`"`, "AA==")))
	strDoc := mustParse(tb, `<wsse:SecurityTokenReference xmlns:wsse="`+xmlsec.NSWSSE+`"><wsse:Reference URI="#`+long+`"/></wsse:SecurityTokenReference>`)
	ki := xmltree.DocumentElement(mustParse(tb, `<wsse:SecurityTokenReference xmlns:wsse="`+xmlsec.NSWSSE+`"><wsse:KeyIdentifier ValueType="`+long+`"/></wsse:SecurityTokenReference>`))
	return map[string]func() error{
		"ParseTimestamp":     func() error { _, err := ParseTimestamp(ts); return err },
		"BSTValueType":       func() error { _, err := ParseBinarySecurityToken(tok); return err },
		"ReferencedToken":    func() error { _, err := ReferencedToken(strDoc, xmltree.DocumentElement(strDoc)); return err },
		"KeyIdentifierCheck": func() error { return CheckSecurityTokenReference(ki) },
	}
}

// An error about a long received value quotes 64 bytes of it, not all.
func TestLongValueError(t *testing.T) {
	for name, f := range longValueShapes(t, 1<<16) {
		if err := f(); err == nil || len(err.Error()) > 512 || !strings.Contains(err.Error(), `\u0085"...`) {
			t.Errorf("%s: %d-byte error %.200v", name, len(err.Error()), err)
		}
	}
}

// BenchmarkLongValueErrorMemory reports the peak heap per value byte of
// refusing a long received value an error message quotes. WSS_PEAK_MIB
// sets the sizes.
func BenchmarkLongValueErrorMemory(b *testing.B) {
	for _, mib := range memSizes() {
		for name, f := range longValueShapes(b, mib<<20) {
			b.Run(fmt.Sprintf("%s/%dMiB", name, mib), func(b *testing.B) {
				for b.Loop() {
					b.ReportMetric(float64(peakHeap(func() { _ = f() }))/float64(mib<<20), "peak-B/B")
				}
			})
		}
	}
}

// BenchmarkIssuerNameMemory reports the peak heap per name byte of matching
// a long X509IssuerName. WSS_PEAK_MIB sets the sizes.
func BenchmarkIssuerNameMemory(b *testing.B) {
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), RawIssuer: []byte{0x30, 0}}
	for _, mib := range memSizes() {
		str := xmltree.DocumentElement(mustParse(b, `<wsse:SecurityTokenReference xmlns:wsse="`+xmlsec.NSWSSE+`" xmlns:ds="`+xmlsec.NSDSig+
			`"><ds:X509Data><ds:X509IssuerSerial><ds:X509IssuerName>CN=`+strings.Repeat("a b ", mib<<18)+
			`</ds:X509IssuerName><ds:X509SerialNumber>1</ds:X509SerialNumber></ds:X509IssuerSerial></ds:X509Data></wsse:SecurityTokenReference>`))
		b.Run(fmt.Sprintf("%dMiB", mib), func(b *testing.B) {
			for b.Loop() {
				b.ReportMetric(float64(peakHeap(func() { _ = MatchSecurityTokenReference(str, cert) }))/float64(mib<<20), "peak-B/B")
			}
		})
	}
}

// BenchmarkCheckUniqueIDsMemory reports the peak heap per document byte of
// checking a document where every element has an ID. WSS_PEAK_MIB sets the
// sizes.
func BenchmarkCheckUniqueIDsMemory(b *testing.B) {
	for _, mib := range memSizes() {
		var s strings.Builder
		s.WriteString(`<r xmlns:wsu="` + xmlsec.NSWSU + `">`)
		for i := 0; s.Len() < mib<<20; i++ {
			fmt.Fprintf(&s, `<i wsu:Id="i%d"/>`, i)
		}
		s.WriteString("</r>")
		doc := mustParse(b, s.String())
		b.Run(fmt.Sprintf("%dMiB", mib), func(b *testing.B) {
			for b.Loop() {
				b.ReportMetric(float64(peakHeap(func() { _ = CheckUniqueIDs(doc) }))/float64(s.Len()), "peak-B/B")
			}
		})
	}
}
