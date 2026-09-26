package security

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// listener counts every request made to it. A fetch is the failure, whatever
// the parse or verification result: an error after the request has been
// sent has already leaked.
func listener(t *testing.T) (url string, hits *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits = new(atomic.Int64)
	srv := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) })}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "http://" + ln.Addr().String(), hits
}

// secret writes a file a successful XXE would disclose, and returns its
// file: URI and content.
func secret(t *testing.T) (uri, content string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret.txt")
	content = "SECRET-7f3a"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return "file://" + filepath.ToSlash(p), content
}

func utf16le(s string) string {
	b := []byte{0xFF, 0xFE}
	for _, r := range utf16.Encode([]rune(s)) {
		b = append(b, byte(r), byte(r>>8))
	}
	return string(b)
}

func billionLaughs() string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa">`)
	prev := "a"
	for _, e := range []string{"b", "c", "d", "e", "f", "g", "h", "i"} {
		b.WriteString(`<!ENTITY ` + e + ` "` + strings.Repeat("&"+prev+";", 10) + `">`)
		prev = e
	}
	b.WriteString(`]><r>&i;</r>`)
	return b.String()
}

// Every DOCTYPE is refused, however it is dressed, and nothing is read.
func TestParseRefusesXXE(t *testing.T) {
	url, hits := listener(t)
	file, content := secret(t)
	xxe := `<!DOCTYPE r [<!ENTITY x SYSTEM "` + file + `">]><r>&x;</r>`
	for name, doc := range map[string]string{
		"file entity":                  xxe,
		"http entity":                  `<!DOCTYPE r [<!ENTITY x SYSTEM "` + url + `/x">]><r>&x;</r>`,
		"parameter entity":             `<!DOCTYPE r [<!ENTITY % p SYSTEM "` + url + `/p.dtd"> %p;]><r/>`,
		"external subset":              `<!DOCTYPE r SYSTEM "` + url + `/d.dtd"><r/>`,
		"PUBLIC external subset":       `<!DOCTYPE r PUBLIC "-//X//Y" "` + url + `/d.dtd"><r/>`,
		"billion laughs":               billionLaughs(),
		"after a comment and a PI":     `<?xml version="1.0"?><!-- c --><?pi x?>` + xxe,
		"behind a UTF-8 BOM":           "\xEF\xBB\xBF" + xxe,
		"UTF-16":                       utf16le(`<?xml version="1.0" encoding="UTF-16"?>` + xxe),
		"undeclared entity":            `<r>&x;</r>`,
		"undeclared entity in an attr": `<r a="&x;"/>`,
	} {
		t.Run(name, func(t *testing.T) {
			tree, err := xmlsec.Parse([]byte(doc))
			if err == nil {
				t.Fatalf("accepted; content %q", tree.Root.StringValue())
			}
			if strings.Contains(err.Error(), content) {
				t.Fatalf("error discloses the file: %v", err)
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("%d network fetches", n)
	}
}

// Documents that merely name an external resource parse, and nothing is
// fetched or expanded: no XInclude processing, no stylesheet, no schema.
func TestParseFetchesNothing(t *testing.T) {
	url, hits := listener(t)
	file, content := secret(t)
	for name, doc := range map[string]string{
		"XInclude":           `<r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="` + url + `/i" parse="text"/><xi:include href="` + file + `" parse="text"/></r>`,
		"xml-stylesheet":     `<?xml-stylesheet type="text/xsl" href="` + url + `/s.xsl"?><r/>`,
		"xsi:schemaLocation": `<r xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:x ` + url + `/s.xsd"/>`,
		"xml:base":           `<r xml:base="` + url + `/"><c/></r>`,
	} {
		t.Run(name, func(t *testing.T) {
			tree, err := xmlsec.Parse([]byte(doc))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(tree.Root.StringValue(), content) {
				t.Fatal("file content was included")
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("%d network fetches", n)
	}
}

// With an authentic signature, verification reaches reference resolution.
// Only "", "#id" and cid: resolve; every other URI is refused unread.
func TestVerifyDereferencesNothingExternal(t *testing.T) {
	url, hits := listener(t)
	file, _ := secret(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "k"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	for _, uri := range []string{
		url + "/verify",
		file,
		"cid:" + url,
		"#xpointer(document('" + url + "/xp'))",
	} {
		t.Run(uri, func(t *testing.T) {
			tree, err := xmlsec.Parse([]byte(`<r><a>x</a></r>`))
			if err != nil {
				t.Fatal(err)
			}
			signed, err := dsig.SignEnveloped(tree.Root, xmlsec.KeyProvider{Signer: key, Certificate: cert}, dsig.SignOptions{
				SignatureAlgorithm:        xmlsec.SigRSASHA256,
				CanonicalizationAlgorithm: string(c14n.Exclusive10),
				References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
					{Algorithm: xmlsec.TransformEnvelopedSignature}, {Algorithm: string(c14n.Exclusive10)}}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			doc, err := xmlsec.Parse(signed)
			if err != nil {
				t.Fatal(err)
			}
			sig, si, ref, value := elements(doc.Root)
			ref.Attr("", "URI").Value = uri

			// Re-sign the altered SignedInfo with the real key, so the
			// signature is authentic and verification goes on to resolve
			// the reference.
			h := sha256.New()
			if _, err := c14n.Digest(h, si, c14n.Options{Algorithm: c14n.Exclusive10}); err != nil {
				t.Fatal(err)
			}
			v, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h.Sum(nil))
			if err != nil {
				t.Fatal(err)
			}
			value.Children[0].Value = base64.StdEncoding.EncodeToString(v)

			if _, err := dsig.Verify(doc.Root, sig, dsig.VerifyOptions{Certificate: cert}); err == nil {
				t.Fatal("verified")
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("%d network fetches", n)
	}
}

func elements(root *xdm.Node) (sig, si, ref, value *xdm.Node) {
	xmltree.Walk(root, func(e *xdm.Node) {
		if e.Name.URI != dsig.NSDSig {
			return
		}
		switch e.Name.Local {
		case "Signature":
			sig = e
		case "SignedInfo":
			si = e
		case "Reference":
			ref = e
		case "SignatureValue":
			value = e
		}
	})
	return
}
