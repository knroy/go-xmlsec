package wss_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/dsig"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
	"github.com/knroy/go-xmlsec/v2/wss"
)

// flowEnvelope returns a SOAP 1.1 envelope of about size bytes whose body
// is many small elements, the shape that costs most per byte.
func flowEnvelope(size int) []byte {
	var b strings.Builder
	b.WriteString(`<soap:Envelope xmlns:soap="` + xmlsec.NSSOAP11 + `"><soap:Body><p:Payload xmlns:p="urn:p">`)
	for i := 0; b.Len() < size; i++ {
		fmt.Fprintf(&b, `<p:i n="%d">v%d</p:i>`, i, i)
	}
	b.WriteString(`</p:Payload></soap:Body></soap:Envelope>`)
	return []byte(b.String())
}

func flowKey(tb testing.TB) xmlsec.KeyProvider {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "flow"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		tb.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	return xmlsec.KeyProvider{Signer: k, Certificate: cert}
}

// sendFlow signs the body of msg into a new WS-Security header with a
// timestamp and a binary security token, as a sender does, and returns the
// Document.
func sendFlow(tb testing.TB, msg []byte, key xmlsec.KeyProvider) *xmlsec.Document {
	tree, err := xmlsec.Parse(msg)
	if err != nil {
		tb.Fatal(err)
	}
	doc := xmlsec.NewDocument(tree.Root)
	body := xmltree.DocumentElement(tree.Root).FirstChild()
	bodyID, err := wss.AssignID(doc, body)
	if err != nil {
		tb.Fatal(err)
	}
	h, err := wss.NewHeader(doc, xmlsec.NSSOAP11, "", true)
	if err != nil {
		tb.Fatal(err)
	}
	tsID, err := h.AddTimestamp(time.Now(), time.Minute)
	if err != nil {
		tb.Fatal(err)
	}
	tokID, err := h.AddBinarySecurityToken(key.Certificate, nil, xmlsec.BSTValueTypeX509v3)
	if err != nil {
		tb.Fatal(err)
	}
	exc := []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}
	sig, err := dsig.Sign(doc, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigECDSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{
			{URI: "#" + tsID, Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "#" + bodyID, Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
		},
		KeyInfo:         dsig.KeyInfoSecurityTokenReference,
		SecurityTokenID: tokID,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if err := h.Prepend(sig); err != nil {
		tb.Fatal(err)
	}
	return doc
}

// BenchmarkSendFlowMemory reports the peak heap of the WS-Security send
// flow, and what the Document still holds after it, per message byte: each
// change makes a new tree, and the Document must not keep the old ones.
// WSS_PEAK_MIB sets the sizes.
//
//	WSS_PEAK_MIB=1,10 go test -run '^$' -bench SendFlowMemory -benchtime 1x ./wss
func BenchmarkSendFlowMemory(b *testing.B) {
	key := flowKey(b)
	for _, mib := range wss.MemSizes() {
		msg := flowEnvelope(mib << 20)
		size := float64(len(msg))
		b.Run(fmt.Sprintf("%dMiB", mib), func(b *testing.B) {
			for b.Loop() {
				var base, after runtime.MemStats
				runtime.GC()
				runtime.ReadMemStats(&base)
				var doc *xmlsec.Document
				peak := wss.PeakHeap(func() { doc = sendFlow(b, msg, key) })
				runtime.GC()
				runtime.ReadMemStats(&after)
				runtime.KeepAlive(doc)
				b.ReportMetric(float64(peak)/size, "peak-B/B")
				b.ReportMetric((float64(after.HeapAlloc)-float64(base.HeapAlloc))/size, "retained-B/B")
			}
		})
	}
}
