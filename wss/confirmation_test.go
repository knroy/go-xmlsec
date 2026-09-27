package wss

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// A responder confirms each signature of the request (SOAP Message Security
// 1.1.1 section 8.5.1), and the initiator's check accepts exactly the
// confirmations section 8.5.2 describes.
func TestSignatureConfirmationRoundTrip(t *testing.T) {
	request := parseDoc(t, `<wsse:Security xmlns:wsse="`+xmlsec.NSWSSE+`" xmlns:ds="`+xmlsec.NSDSig+`">`+
		`<ds:Signature><ds:SignedInfo/><ds:SignatureValue>AQID</ds:SignatureValue></ds:Signature><x/>`+
		`<ds:Signature><ds:SignedInfo/><ds:SignatureValue>BA U=</ds:SignatureValue></ds:Signature></wsse:Security>`)
	sent, err := SignatureValues(xmltree.DocumentElement(request))
	if err != nil || len(sent) != 2 || string(sent[0]) != "\x01\x02\x03" || string(sent[1]) != "\x04\x05" {
		t.Fatalf("SignatureValues: %q, %v", sent, err)
	}

	respond := func(values ...[]byte) *xdm.Node {
		doc := parseDoc(t, env11)
		h, err := NewHeader(doc, xmlsec.NSSOAP11, "", false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.AddTimestamp(time.Unix(0, 0), 0); err != nil {
			t.Fatal(err)
		}
		for _, v := range values {
			id, err := h.AddSignatureConfirmation(v)
			if err != nil || id == "" {
				t.Fatalf("AddSignatureConfirmation: %q, %v", id, err)
			}
		}
		// The confirmations follow the timestamp.
		if kids := h.Element().ChildElements(); !kids[0].IsElement(xmlsec.NSWSU, "Timestamp") {
			t.Fatalf("header order: %v", kids[0].Name)
		}
		return h.Element()
	}

	for name, c := range map[string]struct {
		sec  *xdm.Node
		sent [][]byte
		want error
	}{
		"both confirmed":           {respond(sent[1], sent[0]), sent, nil},
		"unsigned request":         {respond(nil), nil, nil},
		"no confirmation":          {respond(), sent, xmlsec.ErrSignatureInvalid},
		"one unconfirmed":          {respond(sent[0]), sent, xmlsec.ErrSignatureInvalid},
		"one confirmed twice":      {respond(sent[0], sent[0]), sent, xmlsec.ErrSignatureInvalid},
		"wrong value":              {respond(sent[0], []byte("x")), sent, xmlsec.ErrSignatureInvalid},
		"no Value, signed request": {respond(nil, sent[0]), sent, xmlsec.ErrSignatureInvalid},
		"Value, unsigned request":  {respond(sent[0]), nil, xmlsec.ErrSignatureInvalid},
		"two, unsigned request":    {respond(nil, nil), nil, xmlsec.ErrSignatureInvalid},
	} {
		if err := CheckSignatureConfirmations(c.sec, c.sent); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The Value is the base64 of the octets, and wsu:Id is always there.
	sec := respond(sent[0])
	sc := sec.ChildElements()[1]
	if sc.AttrValue("Value") != base64.StdEncoding.EncodeToString(sent[0]) || sc.Attr(xmlsec.NSWSU, "Id") == nil {
		t.Fatalf("SignatureConfirmation %+v", sc.Attrs)
	}
	if respond(nil).ChildElements()[1].Attr("", "Value") != nil {
		t.Fatal("Value written for an unsigned request")
	}
}

func TestSignatureConfirmationErrors(t *testing.T) {
	sec := func(inner string) *xdm.Node {
		return xmltree.DocumentElement(parseDoc(t, `<wsse:Security xmlns:wsse="`+xmlsec.NSWSSE+`" xmlns:wsse11="`+xmlsec.NSWSSE11+
			`" xmlns:wsu="`+xmlsec.NSWSU+`" xmlns:ds="`+xmlsec.NSDSig+`">`+inner+`</wsse:Security>`))
	}
	sent := [][]byte{{1, 2, 3}}
	for name, c := range map[string]struct {
		inner string
		want  error
	}{
		"R5441 no wsu:Id":   {`<wsse11:SignatureConfirmation Value="AQID"/>`, xmlsec.ErrMalformed},
		"empty Value":       {`<wsse11:SignatureConfirmation wsu:Id="a" Value=""/>`, xmlsec.ErrMalformed},
		"Value not base64":  {`<wsse11:SignatureConfirmation wsu:Id="a" Value="!!"/>`, xmlsec.ErrMalformed},
		"confirmed":         {`<wsse11:SignatureConfirmation wsu:Id="a" Value="AQID"/>`, nil},
		"not wsse:Security": {``, xmlsec.ErrMalformed},
	} {
		s := sec(c.inner)
		if name == "not wsse:Security" {
			s = nil
		}
		if err := CheckSignatureConfirmations(s, sent); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}

	for name, inner := range map[string]string{
		"no SignatureValue":         `<ds:Signature><ds:SignedInfo/></ds:Signature>`,
		"SignatureValue not base64": `<ds:Signature><ds:SignedInfo/><ds:SignatureValue>!!</ds:SignatureValue></ds:Signature>`,
		"empty SignatureValue":      `<ds:Signature><ds:SignedInfo/><ds:SignatureValue/></ds:Signature>`,
	} {
		if _, err := SignatureValues(sec(inner)); !errors.Is(err, xmlsec.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := SignatureValues(nil); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Errorf("nil: %v", err)
	}

	h, err := NewHeader(parseDoc(t, env11), xmlsec.NSSOAP11, "", false)
	if err != nil {
		t.Fatal(err)
	}
	SetRandReader(t, strings.NewReader(""))
	if _, err := h.AddSignatureConfirmation(nil); err == nil {
		t.Fatal("randomness failure not reported")
	}
}
