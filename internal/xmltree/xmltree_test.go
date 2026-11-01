package xmltree

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/knroy/go-xml/v2/xdm"
)

func TestClone(t *testing.T) {
	e := Element(nil, "p", "urn:p", "e")
	e.AddNamespace("p", "urn:p")
	SetAttr(e, "", "", "a", "1")
	Text(Element(e, "p", "urn:p", "k"), "v")
	c := Clone(e)
	SetAttr(e, "", "", "a", "2")
	e.FirstChild().FirstChild().SetValue("w")
	if c.Parent() != nil || AttrValue(c, "", "a") != "1" || c.AttrAt(0).Parent() != c ||
		c.NamespaceDeclAt(0).Value() != "urn:p" || c.FirstChild().Parent() != c || c.FirstChild().StringValue() != "v" {
		t.Fatalf("clone %+v", c)
	}
}

func TestSetAttrAndAttrValue(t *testing.T) {
	e := Element(nil, "p", "urn:p", "e")
	if got := AttrValue(e, "", "a"); got != "" {
		t.Fatalf("absent attribute: %q", got)
	}
	SetAttr(e, "", "", "a", "1")
	SetAttr(e, "", "", "a", "2")
	if e.NumAttrs() != 1 || AttrValue(e, "", "a") != "2" {
		t.Fatalf("replace: %d attrs, value %q", e.NumAttrs(), AttrValue(e, "", "a"))
	}
}

func TestDeclare(t *testing.T) {
	cases := []struct {
		name    string
		bound   string // URI already bound to "p" on the parent, "" for none
		uri     string
		wantErr bool
		wantNew bool
	}{
		{"unbound", "", "urn:a", false, true},
		{"same binding in scope", "urn:a", "urn:a", false, false},
		{"conflicting binding", "urn:a", "urn:b", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parent := Element(nil, "", "", "parent")
			if c.bound != "" {
				parent.AddNamespace("p", c.bound)
			}
			e := Element(parent, "", "", "e")
			err := Declare(e, "p", c.uri)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v", err)
			}
			if got := e.NumNamespaceDecls() == 1; got != c.wantNew {
				t.Fatalf("declared on e: %v", got)
			}
		})
	}
}

func TestDocumentElement(t *testing.T) {
	root := Element(nil, "", "", "root")
	child := Element(root, "", "", "child")
	if got := DocumentElement(child); got != root {
		t.Fatal("detached element tree: want its root element")
	}

	doc := xdm.NewNode(xdm.KindDocument, xdm.QName{}, "")
	Text(doc, "stray")
	el := Element(doc, "", "", "el")
	if got := DocumentElement(el); got != el {
		t.Fatal("document: want its element child")
	}

	empty := xdm.NewNode(xdm.KindDocument, xdm.QName{}, "")
	Text(empty, "only text")
	if got := DocumentElement(empty); got != nil {
		t.Fatal("document without element: want nil")
	}
}

func TestBase64(t *testing.T) {
	cases := []struct {
		in      string
		want    []byte
		wantErr bool
	}{
		{"aGVs\r\n bG8=\t", []byte("hello"), false},
		{"", []byte{}, false},
		{"not base64!", nil, true},
	}
	for _, c := range cases {
		e := Element(nil, "", "", "e")
		Text(e, c.in)
		got, err := Base64(e)
		if (err != nil) != c.wantErr || !c.wantErr && !bytes.Equal(got, c.want) {
			t.Errorf("%q: %q, %v", c.in, got, err)
		}
	}
}

func TestWalk(t *testing.T) {
	root := Element(nil, "", "", "a")
	Text(root, "t")
	Element(Element(root, "", "", "b"), "", "", "c")
	var names []string
	Walk(root, func(n *xdm.Node) { names = append(names, n.Name().Local) })
	if len(names) != 3 || names[0] != "a" || names[1] != "b" || names[2] != "c" {
		t.Fatalf("walk order %v", names)
	}
}

func TestDocumentElementNil(t *testing.T) {
	if DocumentElement(nil) != nil {
		t.Fatal("non-nil")
	}
}

// oldBase64 is Base64 as it was before it decoded in chunks.
func oldBase64(e *xdm.Node) ([]byte, error) {
	s := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, e.StringValue())
	return base64.StdEncoding.DecodeString(s)
}

// TestBase64MatchesOld checks Base64 against the whole-text version for
// valid and invalid input of every shape, across chunk boundaries.
func TestBase64MatchesOld(t *testing.T) {
	check := func(s string) {
		t.Helper()
		e := Element(nil, "", "", "e")
		Text(e, s)
		got, err := Base64(e)
		want, werr := oldBase64(e)
		if !bytes.Equal(got, want) || fmt.Sprint(err) != fmt.Sprint(werr) || (got == nil) != (want == nil) {
			t.Fatalf("%q: got %x, %v; want %x, %v", s, got, err, want, werr)
		}
	}
	long := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("0123456789"), 1000))
	wrapped := regexp.MustCompile(`.{1,76}`).ReplaceAllString(long, "$0\r\n")
	for _, s := range []string{
		"", " \t\r\n", "AAAA", "AA==", "AAA=", "A", "AA", "AAA", "A===", "AA=", "=", "====", "AA==AA==", "AA== ", "AA==\nAAAA",
		"AA AA", "\tAAAA\r\n", "AA\vAA", "AA\fAA", "AA AA", "AA　AA", "AAA\xff", "\xffAAA", "AA�AA", "AA!A", "é",
		long, wrapped, wrapped + "!", wrapped + "=", "!" + wrapped,
		long[:4096] + "AA==", long[:4092] + "AA==" + long[:4], long[:4092] + "AAA=" + long[:4], long[:4094] + "==", long[:4095] + "=",
		long[:4092] + "AA==\n", long[:4096] + "!", long[:4095] + "\xff", long[:4094] + "é" + long[:8], long[:4093] + "\xff",
	} {
		check(s)
	}
	r := rand.New(rand.NewPCG(1, 2))
	alphabet := []string{"A", "b", "9", "+", "/", "=", " ", "\t", "\r", "\n", "!", "\xff", "é", "\v"}
	for range 3000 {
		var b strings.Builder
		n := r.IntN(64)
		if r.IntN(4) == 0 {
			b.WriteString(long[:4096-r.IntN(8)])
		}
		for range n {
			if r.IntN(8) == 0 {
				b.WriteString(alphabet[r.IntN(len(alphabet))])
			} else {
				b.WriteString(alphabet[r.IntN(5)])
			}
		}
		check(b.String())
	}
}

// BenchmarkBase64Memory reports what Base64 allocates per octet of
// base64 text, wrapped at 76 characters with CRLF as xmlsec1, WSS4J and
// Santuario write it. XMLTREE_B64_MIB sets the decoded sizes,
// comma-separated (default 1).
//
//	XMLTREE_B64_MIB=1,10 go test -run '^$' -bench Base64Memory -benchtime 1x ./internal/xmltree
func BenchmarkBase64Memory(b *testing.B) {
	sizes := os.Getenv("XMLTREE_B64_MIB")
	if sizes == "" {
		sizes = "1"
	}
	for _, mib := range strings.Split(sizes, ",") {
		var n int
		fmt.Sscan(mib, &n)
		b.Run(mib+"MiB", func(b *testing.B) {
			enc := base64.StdEncoding.EncodeToString(make([]byte, n<<20))
			var w strings.Builder
			for len(enc) > 76 {
				w.WriteString(enc[:76] + "\r\n")
				enc = enc[76:]
			}
			w.WriteString(enc)
			e := Element(nil, "", "", "e")
			Text(e, w.String())
			size := float64(w.Len())
			for b.Loop() {
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				if _, err := Base64(e); err != nil {
					b.Fatal(err)
				}
				runtime.ReadMemStats(&after)
				b.ReportMetric(float64(after.TotalAlloc-before.TotalAlloc)/size, "alloc-B/B")
			}
		})
	}
}
