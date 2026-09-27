package xenc_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

// BSP R5624: with no DataID, EncryptHeader gives the EncryptedData a
// random Id, a different one each time.
func TestEncryptHeaderGeneratesID(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	doc := covParse(t, `<S:Envelope xmlns:S="`+soap12+`"><S:Header><wsse:Security xmlns:wsse="`+xmlsec.NSWSSE+`"/><b>v</b></S:Header><S:Body/></S:Envelope>`)
	hdr := doc.ChildElements()[0]
	id := regexp.MustCompile(`<xenc:EncryptedData xmlns:xenc="[^"]+" Id="(id-[0-9a-f]{32})"`)
	var seen []string
	for range 2 {
		out, err := xenc.EncryptHeader(doc, hdr.ChildElements()[1], hdr.ChildElements()[0], key, as4Opts(t))
		m := id.FindStringSubmatch(string(out))
		if err != nil || m == nil {
			t.Fatalf("%v\n%s", err, out)
		}
		seen = append(seen, m[1])
	}
	if seen[0] == seen[1] {
		t.Fatal("same Id twice")
	}
}

// SOAP Message Security 1.1.1 section 9.4.4: DecryptHeader puts the header
// block back where the EncryptedHeader was, and the document is what it
// was before EncryptHeader.
func TestDecryptHeader(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	for _, ns := range []string{soap11, soap12} {
		src := `<S:Envelope xmlns:S="` + ns + `" xmlns:q="urn:q"><S:Header><wsse:Security xmlns:wsse="` + xmlsec.NSWSSE + `" S:mustUnderstand="1"></wsse:Security>` +
			`<m:Block xmlns:m="urn:m" q:a="1">v<!--c--></m:Block><n></n></S:Header><S:Body></S:Body></S:Envelope>`
		doc := covParse(t, src)
		hdr := doc.ChildElements()[0]
		out, err := xenc.EncryptHeader(doc, hdr.ChildElements()[1], hdr.ChildElements()[0], key, as4Opts(t))
		if err != nil {
			t.Fatal(err)
		}
		enc := covParse(t, string(out))
		eh := firstNamed(enc, "EncryptedHeader")
		got, err := xenc.DecryptHeader(enc, eh, key, xenc.DecryptOptions{})
		// The EncryptedHeader's own wsse11 binding was in scope for the
		// plaintext, so the block keeps it.
		want := strings.Replace(src, `<m:Block xmlns:m="urn:m"`, `<m:Block xmlns:m="urn:m" xmlns:wsse11="`+xmlsec.NSWSSE11+`"`, 1)
		if err != nil || string(got) != want {
			t.Fatalf("%v\n%s\nwant\n%s", err, got, src)
		}
		if again, _ := c14n.Bytes(enc.Root(), c14n.Options{Algorithm: c14n.Inclusive10WithComments}); string(again) != string(out) {
			t.Fatal("doc modified")
		}
	}
}

// ehDoc is an envelope whose header holds an EncryptedHeader, declaring
// ehNS, around content.
func ehDoc(ehNS, content string) string {
	return `<S:Envelope xmlns:S="` + soap12 + `" xmlns="urn:default"><S:Header>` +
		`<wsse11:EncryptedHeader xmlns:wsse11="` + xmlsec.NSWSSE11 + `" ` + ehNS + `>` + content + `</wsse11:EncryptedHeader>` +
		`</S:Header><S:Body/></S:Envelope>`
}

// ehED is an EncryptedData of the given Type holding pt under key.
func ehED(key []byte, typ, pt string) string {
	return covED(`Type="`+typ+`"`, covEM(xmlsec.EncAES128GCM)+
		`<xenc:CipherData><xenc:CipherValue>`+base64.StdEncoding.EncodeToString(sealGCM(key, pt))+`</xenc:CipherValue></xenc:CipherData>`)
}

// XML Encryption 1.1 section 4.5.4: the plaintext is parsed in the
// EncryptedHeader's context, whose namespaces the block keeps.
func TestDecryptHeaderContext(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	doc := covParse(t, ehDoc(`xmlns:x="urn:x"`, " "+ehED(key, xenc.TypeElement, `<x:B><c/></x:B>`)+"\n"))
	out, err := xenc.DecryptHeader(doc, firstNamed(doc, "EncryptedHeader"), key, xenc.DecryptOptions{})
	if err != nil || !strings.Contains(string(out), `<S:Header><x:B xmlns:wsse11="`+xmlsec.NSWSSE11+`" xmlns:x="urn:x"><c></c></x:B></S:Header>`) {
		t.Fatalf("%v\n%s", err, out)
	}
	if b := firstNamed(covParse(t, string(out)), "c"); b.Name.URI != "urn:default" {
		t.Fatalf("default namespace %q", b.Name.URI)
	}
}

func TestDecryptHeaderErrors(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	good := ehED(key, xenc.TypeElement, `<b/>`)
	for _, c := range []struct {
		name, doc string
		key       []byte
		want      error
	}{
		{"two EncryptedData", ehDoc(``, good+good), key, xmlsec.ErrMalformed},
		{"other element", ehDoc(``, good+`<x/>`), key, xmlsec.ErrMalformed},
		{"text", ehDoc(``, good+`x`), key, xmlsec.ErrMalformed},
		{"comment", ehDoc(``, `<!--c-->`+good), key, xmlsec.ErrMalformed},
		{"empty", ehDoc(``, ``), key, xmlsec.ErrMalformed},
		{"Type Content", ehDoc(``, ehED(key, xenc.TypeContent, `<b/>`)), key, xmlsec.ErrMalformed},
		{"wrong key", ehDoc(``, good), bytes.Repeat([]byte{8}, 16), xmlsec.ErrDecryptionFailed},
		{"two elements", ehDoc(``, ehED(key, xenc.TypeElement, `<b/><c/>`)), key, xmlsec.ErrDecryptionFailed},
		{"text only", ehDoc(``, ehED(key, xenc.TypeElement, `b`)), key, xmlsec.ErrDecryptionFailed},
		{"not XML", ehDoc(``, ehED(key, xenc.TypeElement, `<b>`)), key, xmlsec.ErrDecryptionFailed},
		{"DOCTYPE", ehDoc(``, ehED(key, xenc.TypeElement, `<!DOCTYPE b><b/>`)), key, xmlsec.ErrDecryptionFailed},
	} {
		t.Run(c.name, func(t *testing.T) {
			doc := covParse(t, c.doc)
			out, err := xenc.DecryptHeader(doc, firstNamed(doc, "EncryptedHeader"), c.key, xenc.DecryptOptions{})
			if !errors.Is(err, c.want) || out != nil {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if c.want == xmlsec.ErrDecryptionFailed && err.Error() != "xenc: decryption failed" {
				t.Fatalf("detail leaked: %v", err)
			}
		})
	}
	// Not an EncryptedHeader block, or not in the document.
	doc := covParse(t, `<S:Envelope xmlns:S="`+soap12+`"><S:Header><b/></S:Header><S:Body>`+
		`<wsse11:EncryptedHeader xmlns:wsse11="`+xmlsec.NSWSSE11+`">`+good+`</wsse11:EncryptedHeader></S:Body></S:Envelope>`)
	for name, eh := range map[string]*xdm.Node{
		"plain header block":        firstNamed(doc, "b"),
		"EncryptedHeader in a Body": firstNamed(doc, "EncryptedHeader"),
	} {
		if _, err := xenc.DecryptHeader(doc, eh, key, xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrMalformed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := xenc.DecryptHeader(nil, firstNamed(doc, "b"), key, xenc.DecryptOptions{}); err == nil {
		t.Fatal("nil doc accepted")
	}
}

// WS-Security 1.1.1 section 9.4.3: the block becomes a
// wsse11:EncryptedHeader holding the EncryptedData, carrying the
// referencing Security header's mustUnderstand and actor or role.
func TestEncryptHeader(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	for _, c := range []struct {
		name, ns, secAttrs, want string
	}{
		{"SOAP 1.1", soap11, `S:mustUnderstand="1" S:actor="urn:next"`, `<wsse11:EncryptedHeader xmlns:wsse11="` + xmlsec.NSWSSE11 + `" S:actor="urn:next" S:mustUnderstand="1">`},
		{"SOAP 1.2", soap12, `S:mustUnderstand="true" S:role="urn:r" S:relay="true" other="x"`, `<wsse11:EncryptedHeader xmlns:wsse11="` + xmlsec.NSWSSE11 + `" S:mustUnderstand="true" S:relay="true" S:role="urn:r">`},
		{"prefix declared on Security", soap12, `xmlns:e="` + soap12 + `" e:mustUnderstand="true"`, `<wsse11:EncryptedHeader xmlns:e="` + soap12 + `" xmlns:wsse11="` + xmlsec.NSWSSE11 + `" e:mustUnderstand="true">`},
		{"no attributes", soap12, ``, `<wsse11:EncryptedHeader xmlns:wsse11="` + xmlsec.NSWSSE11 + `">`},
	} {
		t.Run(c.name, func(t *testing.T) {
			doc := covParse(t, `<S:Envelope xmlns:S="`+c.ns+`"><S:Header>`+
				`<wsse:Security xmlns:wsse="`+xmlsec.NSWSSE+`" `+c.secAttrs+`></wsse:Security>`+
				`<m:Block xmlns:m="urn:m" S:mustUnderstand="1" secret="s">v</m:Block></S:Header><S:Body/></S:Envelope>`)
			hdr := doc.ChildElements()[0]
			sec, block := hdr.ChildElements()[0], hdr.ChildElements()[1]
			opts := as4Opts(t)
			opts.DataID = "ED-h"
			out, err := xenc.EncryptHeader(doc, block, sec, key, opts)
			if err != nil {
				t.Fatal(err)
			}
			s := string(out)
			if !strings.Contains(s, c.want+`<xenc:EncryptedData xmlns:xenc="`+xmlsec.NSXEnc+`" Id="ED-h" Type="`+xenc.TypeElement+`">`) ||
				strings.Contains(s, "secret") || strings.Contains(s, "Block") {
				t.Fatalf("encrypted:\n%s", s)
			}
			if pt := decryptIn(t, out, key); !strings.HasPrefix(pt, `<m:Block xmlns:S="`+c.ns+`" xmlns:m="urn:m" secret="s" S:mustUnderstand="1">`) {
				t.Fatalf("plaintext %s", pt)
			}
			if len(hdr.ChildElements()) != 2 || hdr.ChildElements()[1] != block {
				t.Fatal("doc modified")
			}
		})
	}
}

func TestEncryptHeaderErrors(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	doc := covParse(t, `<S:Envelope xmlns:S="`+soap12+`" xmlns:x="urn:x"><S:Header>`+
		`<wsse:Security xmlns:wsse="`+xmlsec.NSWSSE+`"/>`+
		`<wsse:Security xmlns:wsse="`+xmlsec.NSWSSE+`" xmlns:x="`+soap12+`" x:mustUnderstand="true"/>`+
		`<b>v</b></S:Header><S:Body><c/></S:Body></S:Envelope>`)
	hdr := doc.ChildElements()[0]
	sec, clash, block := hdr.ChildElements()[0], hdr.ChildElements()[1], hdr.ChildElements()[2]
	other := covParse(t, `<wsse:Security xmlns:wsse="`+xmlsec.NSWSSE+`"/>`)
	for name, c := range map[string]struct {
		block, sec *xdm.Node
		dataAlg    string
	}{
		"not a header block":       {doc.ChildElements()[1].ChildElements()[0], sec, ""},
		"not in doc":               {other, sec, ""},
		"no Security":              {block, nil, ""},
		"Security is not Security": {block, doc.ChildElements()[1], ""},
		"Security is the block":    {sec, sec, ""},
		"Security in another doc":  {block, other, ""},
		"prefix bound elsewhere":   {block, clash, ""},
		"unknown data algorithm":   {block, sec, "urn:x"},
	} {
		t.Run(name, func(t *testing.T) {
			opts := as4Opts(t)
			if c.dataAlg != "" {
				opts.DataAlgorithm = c.dataAlg
			}
			if out, err := xenc.EncryptHeader(doc, c.block, c.sec, key, opts); err == nil || out != nil {
				t.Fatalf("got %v", err)
			}
		})
	}
}
