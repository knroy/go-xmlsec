package xenc_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
	"github.com/knroy/go-xmlsec/xenc"
)

const strNS = `xmlns:wsse="` + xmlsec.NSWSSE + `"`

// strRef is a SecurityTokenReference with one wsse:Reference to uri.
func strRef(uri string) string {
	return `<wsse:SecurityTokenReference ` + strNS + `><wsse:Reference URI="` + uri + `"/></wsse:SecurityTokenReference>`
}

// SOAP Message Security 1.1.1 section 7.7: an EncryptedData's ds:KeyInfo
// names the EncryptedKey by a SecurityTokenReference with a direct
// reference to its Id, the symmetric binding's shape.
func TestFindEncryptedKeySTR(t *testing.T) {
	for _, c := range []struct{ name, doc string }{
		{"by Id", `<r ` + resolveNS + `>` + resolveEK(`Id="ek" Recipient="want"`, ``) + resolveED(``, strRef("#ek")) + `</r>`},
		{"by wsu:Id", `<r ` + resolveNS + `>` + resolveEK(`wsu:Id="ek" Recipient="want"`, ``) + resolveED(``, strRef("#ek")) + `</r>`},
	} {
		t.Run(c.name, func(t *testing.T) {
			ek, err := xenc.FindEncryptedKey(firstNamed(covParse(t, c.doc), "EncryptedData"))
			if err != nil || ek.AttrValue("Recipient") != "want" {
				t.Fatalf("found %v, %v", ek, err)
			}
		})
	}
}

func TestFindEncryptedKeySTRErrors(t *testing.T) {
	ek := resolveEK(`Id="ek"`, ``)
	for _, c := range []struct {
		name, doc string
		want      error
	}{
		{"two references", `<r ` + resolveNS + `>` + ek + resolveED(``, `<wsse:SecurityTokenReference `+strNS+`><wsse:Reference URI="#ek"/><wsse:Reference URI="#ek"/></wsse:SecurityTokenReference>`) + `</r>`, xmlsec.ErrUnsupportedKeyInfo},
		{"key identifier", `<r ` + resolveNS + `>` + ek + resolveED(``, `<wsse:SecurityTokenReference `+strNS+`><wsse:KeyIdentifier>AA==</wsse:KeyIdentifier></wsse:SecurityTokenReference>`) + `</r>`, xmlsec.ErrUnsupportedKeyInfo},
		{"external URI", `<r ` + resolveNS + `>` + ek + resolveED(``, strRef("http://example.com/ek")) + `</r>`, xmlsec.ErrUnsupportedKeyInfo},
		{"empty fragment", `<r ` + resolveNS + `>` + ek + resolveED(``, strRef("#")) + `</r>`, xmlsec.ErrUnsupportedKeyInfo},
		{"missing", `<r ` + resolveNS + `>` + resolveED(``, strRef("#ek")) + `</r>`, xmlsec.ErrIDNotFound},
		{"duplicate ID", `<r ` + resolveNS + `>` + ek + resolveEK(`wsu:Id="ek"`, ``) + resolveED(``, strRef("#ek")) + `</r>`, xmlsec.ErrAmbiguousID},
		{"not an EncryptedKey", `<r ` + resolveNS + `><x wsu:Id="ek"/>` + resolveED(``, strRef("#ek")) + `</r>`, xmlsec.ErrMalformed},
	} {
		t.Run(c.name, func(t *testing.T) {
			ek, err := xenc.FindEncryptedKey(firstNamed(covParse(t, c.doc), "EncryptedData"))
			if !errors.Is(err, c.want) || ek != nil {
				t.Fatalf("got %v, %v; want %v", ek, err, c.want)
			}
		})
	}
}

// The WSS4J symmetric-binding shape end to end: an RSA-OAEP EncryptedKey in
// the header with no ReferenceList, a header ReferenceList naming the
// EncryptedData of the Body content and of an EncryptedHeader, and each
// EncryptedData naming the EncryptedKey by a SecurityTokenReference. The
// receiver walks it with ReferencedData, FindEncryptedKey, and
// DecryptData or DecryptHeader, all under StrictBSP.
func TestSymmetricBinding(t *testing.T) {
	const src = `<S:Envelope xmlns:S="` + soap12 + `"><S:Header><h:H xmlns:h="urn:h">secret header</h:H></S:Header>` +
		`<S:Body><p:P xmlns:p="urn:p">secret body</p:P></S:Body></S:Envelope>`
	doc := covParse(t, src)
	hdr, err := wss.NewHeader(doc, xmlsec.NSSOAP12, "", true)
	if err != nil {
		t.Fatal(err)
	}
	opts := as4Opts(t)
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	ekID, err := wss.AssignID(doc, ek.Element)
	if err != nil {
		t.Fatal(err)
	}
	recip, err := wss.NewIssuerSerialReference(opts.Recipient)
	if err != nil {
		t.Fatal(err)
	}
	if err := ek.SetKeyInfo(recip); err != nil {
		t.Fatal(err)
	}
	if opts.DataKeyInfo, err = wss.NewSecurityTokenReference(doc, ekID, encryptedKeyToken); err != nil {
		t.Fatal(err)
	}
	list, err := wss.NewReferenceList("ED-body", "ED-header")
	if err != nil {
		t.Fatal(err)
	}
	if err := hdr.Prepend(list); err != nil {
		t.Fatal(err)
	}
	if err := hdr.Prepend(ek.Element); err != nil {
		t.Fatal(err)
	}
	opts.DataID = "ED-body"
	out, err := xenc.EncryptContent(doc, doc.ChildElements()[1], ek.SessionKey, opts)
	if err != nil {
		t.Fatal(err)
	}
	doc = covParse(t, string(out))
	h := doc.ChildElements()[0]
	opts.DataID = "ED-header"
	if out, err = xenc.EncryptHeader(doc, h.ChildElements()[0], h.ChildElements()[1], ek.SessionKey, opts); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "secret") {
		t.Fatalf("not encrypted:\n%s", out)
	}

	// Receive.
	doc = covParse(t, string(out))
	sec := doc.ChildElements()[0].ChildElements()[1]
	if k := sec.ChildElements(); len(k) != 2 || k[0].Name.Local != "EncryptedKey" || k[1].Name.Local != "ReferenceList" {
		t.Fatalf("header order:\n%s", out)
	}
	eds, err := xenc.ReferencedData(sec.ChildElements()[1])
	if err != nil || len(eds) != 2 {
		t.Fatal(err)
	}
	strictOpts := xenc.DecryptOptions{StrictBSP: true}
	var body string
	for _, ed := range eds {
		ekEl, err := xenc.FindEncryptedKey(ed)
		if err != nil {
			t.Fatal(err)
		}
		key, err := xenc.DecryptEncryptedKey(ekEl, recipientKey, strictOpts)
		if err != nil {
			t.Fatal(err)
		}
		if ed.Parent.IsElement(xmlsec.NSWSSE11, "EncryptedHeader") {
			if out, err = xenc.DecryptHeader(doc, ed.Parent, key, strictOpts); err != nil || !strings.Contains(string(out), `<S:Header><h:H xmlns:h="urn:h"`) || !strings.Contains(string(out), `>secret header</h:H><wsse:Security`) {
				t.Fatalf("header: %v\n%s", err, out)
			}
			continue
		}
		pt, err := xenc.DecryptData(ed, key, strictOpts)
		if err != nil {
			t.Fatal(err)
		}
		body = string(pt)
	}
	if !strings.HasPrefix(body, `<p:P `) || !strings.HasSuffix(body, `>secret body</p:P>`) {
		t.Fatalf("body %s", body)
	}
}

// encryptedKeyToken is the token type of an EncryptedKey (SOAP Message
// Security 1.1.1 section 7.7), the ValueType WSS4J puts on the reference.
const encryptedKeyToken = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey"

// EncryptOptions.DataKeyInfo puts a ds:KeyInfo after the EncryptionMethod
// of every EncryptedData, for each Encrypt function, from a copy: the same
// options encrypt twice. FindEncryptedKey follows it back.
func TestDataKeyInfo(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	str := covParse(t, strRef("#EK-1"))
	str.Parent = nil
	opts := as4Opts(t)
	opts.DataKeyInfo = str
	const want = `<xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128GCM + `"></xenc:EncryptionMethod><ds:KeyInfo xmlns:ds="` + xmlsec.NSDSig + `"><wsse:SecurityTokenReference ` + strNS + `><wsse:Reference URI="#EK-1"></wsse:Reference></wsse:SecurityTokenReference></ds:KeyInfo><xenc:CipherData>`
	src := `<S:Envelope xmlns:S="` + soap12 + `"><S:Header><wsse:Security ` + strNS + `>` + resolveEK(`xmlns:xenc="`+xmlsec.NSXEnc+`" Id="EK-1"`, ``) +
		`</wsse:Security><h:H xmlns:h="urn:h">x</h:H></S:Header><S:Body><p>a</p></S:Body></S:Envelope>`
	doc := covParse(t, src)
	body := doc.ChildElements()[1]
	hdr := doc.ChildElements()[0]
	for name, enc := range map[string]func() ([]byte, error){
		"element": func() ([]byte, error) { return xenc.EncryptElement(doc, body.ChildElements()[0], key, opts) },
		"content": func() ([]byte, error) { return xenc.EncryptContent(doc, body, key, opts) },
		"header": func() ([]byte, error) {
			return xenc.EncryptHeader(doc, hdr.ChildElements()[1], hdr.ChildElements()[0], key, opts)
		},
	} {
		out, err := enc()
		if err != nil || !strings.Contains(string(out), want) {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		ed := firstNamed(covParse(t, string(out)), "EncryptedData")
		if ek, err := xenc.FindEncryptedKey(ed); err != nil || ek.AttrValue("Id") != "EK-1" {
			t.Fatalf("%s: FindEncryptedKey %v", name, err)
		}
	}
	_, ed, err := xenc.EncryptAttachment(&xmlsec.Attachment{ID: "a", Body: []byte("b")}, key, xmlsec.TransformAttachmentContentOnly, opts)
	if err != nil || !ed.ChildElements()[1].IsElement(xmlsec.NSDSig, "KeyInfo") {
		t.Fatalf("attachment: %v", err)
	}
	if str.Parent != nil {
		t.Fatal("DataKeyInfo was linked, not copied")
	}

	// Its own ds:KeyInfo is taken by what conveys a derived or agreed key.
	opts.MasterKey = bytes.Repeat([]byte{1}, 16)
	if _, err := xenc.EncryptElement(doc, body.ChildElements()[0], nil, opts); err == nil || !strings.Contains(err.Error(), "DataKeyInfo") {
		t.Fatalf("DataKeyInfo with MasterKey: %v", err)
	}
	opts.MasterKey = nil

	for name, k := range map[string]*xdm.Node{
		"attached": covParse(t, `<a><b/></a>`).ChildElements()[0],
		"KeyInfo":  xmltree.Element(nil, "ds", xmlsec.NSDSig, "KeyInfo"),
		"text":     {Kind: xdm.KindText, Value: "x"},
	} {
		opts.DataKeyInfo = k
		if _, err := xenc.EncryptElement(doc, body.ChildElements()[0], key, opts); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
