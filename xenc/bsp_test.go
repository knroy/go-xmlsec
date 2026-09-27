package xenc_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

var strict = xenc.DecryptOptions{StrictBSP: true}

// keyUnwrappers calls each EncryptedKey function with no key at all: a
// StrictBSP refusal must come before any key is needed.
var keyUnwrappers = map[string]func(*xdm.Node, xenc.DecryptOptions) error{
	"DecryptEncryptedKey": func(el *xdm.Node, o xenc.DecryptOptions) error {
		_, err := xenc.DecryptEncryptedKey(el, nil, o)
		return err
	},
	"UnwrapEncryptedKey": func(el *xdm.Node, o xenc.DecryptOptions) error {
		_, err := xenc.UnwrapEncryptedKey(el, nil, o)
		return err
	},
	"DecryptAgreedKey": func(el *xdm.Node, o xenc.DecryptOptions) error {
		_, err := xenc.DecryptAgreedKey(el, nil, o)
		return err
	},
	"DecryptAgreedKeyDH": func(el *xdm.Node, o xenc.DecryptOptions) error {
		_, err := xenc.DecryptAgreedKeyDH(el, nil, o)
		return err
	},
	"UnwrapEncryptedKeyPassword": func(el *xdm.Node, o xenc.DecryptOptions) error {
		_, err := xenc.UnwrapEncryptedKeyPassword(el, nil, o)
		return err
	},
	"DecryptEncryptedKeyPKCS1v15": func(el *xdm.Node, o xenc.DecryptOptions) error {
		_, err := xenc.DecryptEncryptedKeyPKCS1v15(el, nil, nil, o)
		return err
	},
}

// BSP R3209, R5622, R5623, R5602, R5424, R5426 on an EncryptedKey, under
// StrictBSP only.
func TestStrictBSPEncryptedKey(t *testing.T) {
	for name, c := range map[string]struct {
		attrs, rest string
		refused     bool
	}{
		"Type":          {`Type="` + xenc.TypeElement + `"`, ``, true},
		"MimeType":      {`MimeType="text/xml"`, ``, true},
		"Encoding":      {`Encoding="urn:e"`, ``, true},
		"Recipient":     {`Recipient="Bert"`, ``, true},
		"KeyName":       {``, `<ds:KeyInfo><ds:KeyName>k</ds:KeyName></ds:KeyInfo>`, true},
		"two STRs":      {``, `<ds:KeyInfo>` + strRef("#t") + strRef("#t") + `</ds:KeyInfo>`, true},
		"empty KeyInfo": {``, `<ds:KeyInfo/>`, true},
		"STR":           {``, `<ds:KeyInfo>` + strRef("#t") + `</ds:KeyInfo>`, false},
		"no KeyInfo":    {``, ``, false},
		"Id":            {`Id="x"`, ``, false},
	} {
		doc := `<xenc:EncryptedKey ` + resolveNS + ` ` + c.attrs + `>` + covEM(xmlsec.KeyWrapAES128) + c.rest +
			`<xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>`
		for fn, call := range keyUnwrappers {
			// Some other error, never ErrMalformed, when accepted.
			err := call(covParse(t, doc), strict)
			if refused := errors.Is(err, xmlsec.ErrMalformed); refused != c.refused || err == nil {
				t.Errorf("%s %s: %v", name, fn, err)
			}
			if err := call(covParse(t, doc), xenc.DecryptOptions{}); errors.Is(err, xmlsec.ErrMalformed) && c.rest == `` {
				t.Errorf("%s %s, lax: %v", name, fn, err)
			}
		}
	}
	// Not an EncryptedKey: the function's own check answers.
	for fn, call := range keyUnwrappers {
		if err := call(nil, strict); !errors.Is(err, xmlsec.ErrMalformed) {
			t.Errorf("%s nil: %v", fn, err)
		}
		if err := call(covParse(t, resolveED(resolveNS, `-`)), strict); !errors.Is(err, xmlsec.ErrMalformed) {
			t.Errorf("%s EncryptedData: %v", fn, err)
		}
	}
}

// BSP R3228, R5629, R5424, R5426 on an EncryptedData, under StrictBSP only;
// each refusal before the key is used, so a wrong key is never reported.
func TestStrictBSPEncryptedData(t *testing.T) {
	ct := base64.StdEncoding.EncodeToString(make([]byte, 32))
	ed := func(attrs, keyInfo string) string {
		return `<xenc:EncryptedData ` + attrs + `>` + covEM(xmlsec.EncAES128GCM) + keyInfo +
			`<xenc:CipherData><xenc:CipherValue>` + ct + `</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>`
	}
	ek := resolveEK(``, `<xenc:ReferenceList><xenc:DataReference URI="#ed"/></xenc:ReferenceList>`)
	for name, c := range map[string]struct {
		doc     string
		refused bool
	}{
		"in a SOAP Header":       {`<S:Envelope xmlns:S="` + soap12 + `" ` + resolveNS + `><S:Header>` + ed(`Id="ed"`, `<ds:KeyInfo>`+strRef("#k")+`</ds:KeyInfo>`) + `</S:Header></S:Envelope>`, true},
		"no KeyInfo, no key":     {`<r ` + resolveNS + `>` + ed(`Id="ed"`, ``) + `</r>`, true},
		"no KeyInfo, no Id":      {`<r ` + resolveNS + `>` + ek + ed(``, ``) + `</r>`, true},
		"KeyName":                {`<r ` + resolveNS + `>` + ed(``, `<ds:KeyInfo><ds:KeyName>k</ds:KeyName></ds:KeyInfo>`) + `</r>`, true},
		"inline EncryptedKey":    {`<r ` + resolveNS + `>` + ed(``, `<ds:KeyInfo>`+resolveEK(``, ``)+`</ds:KeyInfo>`) + `</r>`, true},
		"STR":                    {`<r ` + resolveNS + `>` + ed(``, `<ds:KeyInfo>`+strRef("#k")+`</ds:KeyInfo>`) + `</r>`, false},
		"named by EncryptedKey":  {`<r ` + resolveNS + `>` + ek + ed(`Id="ed"`, ``) + `</r>`, false},
		"in a Body, with an STR": {`<S:Envelope xmlns:S="` + soap12 + `" ` + resolveNS + `><S:Body>` + ed(``, `<ds:KeyInfo>`+strRef("#k")+`</ds:KeyInfo>`) + `</S:Body></S:Envelope>`, false},
	} {
		el := firstNamed(covParse(t, c.doc), "EncryptedData")
		_, err := xenc.DecryptData(el, bytes.Repeat([]byte{1}, 16), strict)
		if c.refused != errors.Is(err, xmlsec.ErrMalformed) || !c.refused && !errors.Is(err, xmlsec.ErrDecryptionFailed) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := xenc.DecryptData(el, bytes.Repeat([]byte{1}, 16), xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrDecryptionFailed) {
			t.Errorf("%s, lax: %v", name, err)
		}
	}
	if _, err := xenc.DecryptData(covParse(t, resolveEK(resolveNS, ``)), nil, strict); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatal(err)
	}
}

// A detached EncryptedData from EncryptAttachment, with DataKeyInfo, is
// what StrictBSP accepts; without a KeyInfo it is refused.
func TestStrictBSPAttachment(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	att := &xmlsec.Attachment{ID: "a", Body: []byte("body")}
	opts := as4Opts(t)
	opts.DataKeyInfo = covParse(t, strRef("#k"))
	opts.DataKeyInfo.Parent = nil
	ct, ed, err := xenc.EncryptAttachment(att, key, xmlsec.TransformAttachmentContentOnly, opts)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := xenc.DecryptAttachment(ed, ct, key, strict); err != nil || string(got.Body) != "body" {
		t.Fatalf("%v", err)
	}
	opts.DataKeyInfo = nil
	ct, ed, err = xenc.EncryptAttachment(att, key, xmlsec.TransformAttachmentContentOnly, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xenc.DecryptAttachment(ed, ct, key, strict); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("%v", err)
	}
}

// The agreed and derived entry points take the same checks: an
// AgreementMethod or DerivedKey in an EncryptedData's ds:KeyInfo is no
// SecurityTokenReference (R5426), and DeriveKey applies the EncryptedKey
// rules to an EncryptedKey target.
func TestStrictBSPAgreedAndDerived(t *testing.T) {
	edWith := func(ki string) *xdm.Node {
		return covParse(t, resolveED(resolveNS, `<ds:KeyInfo>`+ki+`</ds:KeyInfo>`))
	}
	agreed := edWith(`<xenc:AgreementMethod Algorithm="` + xmlsec.KeyAgreementECDHES + `"/>`)
	derived := edWith(`<xenc11:DerivedKey xmlns:xenc11="` + xmlsec.NSXEnc11 + `"/>`)
	ek := covParse(t, resolveEK(resolveNS+` Recipient="Bert"`, ``))
	for name, call := range map[string]func() error{
		"DecryptAgreedDataKey":   func() error { _, err := xenc.DecryptAgreedDataKey(agreed, nil, strict); return err },
		"DecryptAgreedDataKeyDH": func() error { _, err := xenc.DecryptAgreedDataKeyDH(agreed, nil, strict); return err },
		"DeriveKey, data":        func() error { _, err := xenc.DeriveKey(nil, derived, nil, strict); return err },
		"DeriveKey, key":         func() error { _, err := xenc.DeriveKey(nil, ek, nil, strict); return err },
	} {
		if err := call(); !errors.Is(err, xmlsec.ErrMalformed) || !strings.Contains(err.Error(), "BSP") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
