package xenc_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

var recipientKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

func recipient(t *testing.T) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "r"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &recipientKey.PublicKey, recipientKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func as4Opts(t *testing.T) xenc.EncryptOptions {
	return xenc.EncryptOptions{
		DataAlgorithm:         xmlsec.EncAES128GCM,
		KeyTransportAlgorithm: xmlsec.KeyTransportRSAOAEP,
		MGFAlgorithm:          xmlsec.MGF1SHA256,
		DigestAlgorithm:       xmlsec.DigestSHA256,
		Recipient:             recipient(t),
	}
}

// reparse round-trips an element through canonical octets, as the wire does.
func reparse(t *testing.T, el *xdm.Node) *xdm.Node {
	t.Helper()
	b, err := c14n.Bytes(el, c14n.Options{Algorithm: c14n.Exclusive10})
	if err != nil {
		t.Fatal(err)
	}
	tree, err := xmlsec.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return xmltree.DocumentElement(tree.Root)
}

func TestConformance_AP_06_AES128GCM(t *testing.T) {
	opts := as4Opts(t)
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	att := &xmlsec.Attachment{ID: "a@x", Body: []byte("compressed payload"),
		MIMEHeaders: map[string][]string{"content-type": {"application/gzip"}}}
	ct, ed, err := xenc.EncryptAttachment(att, ek.SessionKey, xmlsec.TransformAttachmentContentOnly, opts)
	if err != nil {
		t.Fatal(err)
	}
	ed = reparse(t, ed)
	if ed.AttrValue("MimeType") != "application/gzip" || ed.AttrValue("Type") != xmlsec.TransformAttachmentContentOnly {
		t.Fatalf("attributes %v %v", ed.AttrValue("MimeType"), ed.AttrValue("Type"))
	}

	key, err := xenc.DecryptEncryptedKey(reparse(t, ek.Element), recipientKey,
		[]string{xmlsec.KeyTransportRSAOAEP}, []string{xmlsec.MGF1SHA256}, []string{xmlsec.DigestSHA256})
	if err != nil {
		t.Fatal(err)
	}
	got, err := xenc.DecryptAttachment(ed, ct, key, []string{xmlsec.EncAES128GCM})
	if err != nil || !bytes.Equal(got.Body, att.Body) || got.ID != att.ID ||
		len(got.MIMEHeaders) != 1 || got.MIMEHeaders["Content-Type"][0] != "application/gzip" {
		t.Fatalf("decrypt: %+v, %v", got, err)
	}

	ct[len(ct)-1] ^= 1
	if _, err := xenc.DecryptAttachment(ed, ct, key, nil); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err := xenc.DecryptAttachment(ed, ct, key, []string{xmlsec.EncAES256GCM}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("allow-list: %v", err)
	}
}

func TestConformance_AP_07_RSAOAEPExplicitMGF(t *testing.T) {
	ek, err := xenc.GenerateEncryptedKey(as4Opts(t))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Exclusive10})
	if !strings.Contains(string(b), `<xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Algorithm="`+xmlsec.MGF1SHA256+`">`) {
		t.Fatalf("no explicit MGF:\n%s", b)
	}

	// Without the MGF element the specification default is SHA-1.
	implicit := strings.Replace(string(b), `<xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Algorithm="`+xmlsec.MGF1SHA256+`"></xenc11:MGF>`, "", 1)
	tree, err := xmlsec.Parse([]byte(implicit))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xenc.DecryptEncryptedKey(xmltree.DocumentElement(tree.Root), recipientKey, nil, nil, nil); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("implicit SHA-1 MGF: %v", err)
	}
	if _, err := xenc.DecryptEncryptedKey(reparse(t, ek.Element), recipientKey, nil, []string{xmlsec.MGF1SHA512}, nil); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("MGF allow-list: %v", err)
	}
}

// Every permitted data, MGF and digest algorithm round-trips.
func TestAlgorithmCombinations(t *testing.T) {
	for _, data := range []string{xmlsec.EncAES128GCM, xmlsec.EncAES192GCM, xmlsec.EncAES256GCM} {
		for _, mgf := range []string{xmlsec.MGF1SHA256, xmlsec.MGF1SHA384, xmlsec.MGF1SHA512} {
			for _, digest := range []string{xmlsec.DigestSHA256, xmlsec.DigestSHA384, xmlsec.DigestSHA512} {
				opts := as4Opts(t)
				opts.DataAlgorithm, opts.MGFAlgorithm, opts.DigestAlgorithm = data, mgf, digest
				opts.OAEPParams = []byte("label")
				ek, err := xenc.GenerateEncryptedKey(opts)
				if err != nil {
					t.Fatal(err)
				}
				key, err := xenc.DecryptEncryptedKey(reparse(t, ek.Element), recipientKey,
					[]string{xmlsec.KeyTransportRSAOAEP}, []string{mgf}, []string{digest})
				if err != nil || !bytes.Equal(key, ek.SessionKey) {
					t.Fatalf("%s %s %s: %v", data, mgf, digest, err)
				}
			}
		}
	}
}

func TestEncryptElement(t *testing.T) {
	src := `<S:Envelope xmlns:S="urn:s" xmlns:q="urn:q"><S:Body><p:Payload xmlns:p="urn:p" q:attr="1">hi</p:Payload></S:Body></S:Envelope>`
	tree, err := xmlsec.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	doc := tree.Root
	target := xmltree.DocumentElement(doc).ChildElements()[0].ChildElements()[0]
	opts := as4Opts(t)
	key := bytes.Repeat([]byte{7}, 16)

	out, err := xenc.EncryptElement(doc, target, key, opts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), ">hi<") || !strings.Contains(string(out), xenc.TypeElement) {
		t.Fatalf("not encrypted:\n%s", out)
	}
	if again, _ := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10}); string(again) != src {
		t.Fatalf("doc modified:\n%s", again)
	}

	enc, err := xmlsec.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	ed := xmltree.DocumentElement(enc.Root).ChildElements()[0].ChildElements()[0]
	pt, err := xenc.DecryptData(ed, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The plaintext parses on its own: every in-scope namespace is declared.
	if _, err := xmlsec.Parse(pt); err != nil || !strings.Contains(string(pt), `xmlns:q="urn:q"`) {
		t.Fatalf("plaintext %s: %v", pt, err)
	}
	if _, err := xenc.DecryptData(ed, bytes.Repeat([]byte{8}, 16), nil); err == nil {
		t.Fatal("wrong key accepted")
	}
}
