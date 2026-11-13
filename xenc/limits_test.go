package xenc_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
	"github.com/knroy/go-xmlsec/v2/xenc"
)

// allNamed returns every element named local in n's document.
func allNamed(n *xdm.Node, local string) []*xdm.Node {
	var out []*xdm.Node
	xmltree.Walk(n.Root(), func(e *xdm.Node) {
		if e.Name().Local == local {
			out = append(out, e)
		}
	})
	return out
}

// partsED is an EncryptedData of Type Element, Id e<i>, holding pt under key
// inline.
func partsED(i int, key []byte, pt string) string {
	return covED(fmt.Sprintf(`Id="e%d" Type="%s"`, i, xenc.TypeElement), covEM(xmlsec.EncAES128GCM)+
		`<xenc:CipherData><xenc:CipherValue>`+base64.StdEncoding.EncodeToString(sealGCM(key, pt))+`</xenc:CipherValue></xenc:CipherData>`)
}

// N EncryptedData sharing one same-document CipherReference source, by
// "#id" or by URI="" (section 3.3.1 allows both), each decode the whole
// source: more than DefaultMaxEncryptedParts of them are refused by the
// first DecryptData, whatever the key, before any of that work.
func TestMaxEncryptedPartsSharedCipherReference(t *testing.T) {
	key := bytes.Repeat([]byte{5}, 16)
	src := base64.StdEncoding.EncodeToString(sealGCM(key, strings.Repeat("x", 4096)))
	doc := func(n int, uri string) []*xdm.Node {
		var b strings.Builder
		b.WriteString(`<r xmlns:xenc="` + xmlsec.NSXEnc + `" xmlns:ds="` + xmlsec.NSDSig + `"><t Id="src">` + src + `</t>`)
		for range n {
			b.WriteString(`<xenc:EncryptedData>` + covEM(xmlsec.EncAES128GCM) + `<xenc:CipherData><xenc:CipherReference URI="` + uri +
				`"><xenc:Transforms><ds:Transform Algorithm="` + xmlsec.TransformBase64 + `"/></xenc:Transforms></xenc:CipherReference></xenc:CipherData></xenc:EncryptedData>`)
		}
		b.WriteString(`</r>`)
		return allNamed(covParse(t, b.String()), "EncryptedData")
	}
	for _, uri := range []string{"#src", ""} {
		for _, ed := range doc(xenc.DefaultMaxEncryptedParts, uri) {
			if pt, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{}); err != nil || len(pt) != 4096 {
				t.Fatalf("URI %q: %d octets, %v", uri, len(pt), err)
			}
		}
		eds := doc(xenc.DefaultMaxEncryptedParts+1, uri)
		for _, c := range []struct {
			key  []byte
			opts xenc.DecryptOptions
		}{
			{key, xenc.DecryptOptions{}},
			{make([]byte, 16), xenc.DecryptOptions{}},
			{key, xenc.DecryptOptions{MaxEncryptedParts: -1}},
		} {
			if _, err := xenc.DecryptData(eds[0], c.key, c.opts); !errors.Is(err, xmlsec.ErrLimitExceeded) || errors.Is(err, xmlsec.ErrDecryptionFailed) {
				t.Fatalf("URI %q: %v", uri, err)
			}
		}
		if _, err := xenc.DecryptData(eds[0], key, xenc.DecryptOptions{MaxEncryptedParts: len(eds)}); err != nil {
			t.Fatalf("URI %q, MaxEncryptedParts raised: %v", uri, err)
		}
	}
}

// DecryptAndReplace and DecryptHeader emit the whole document per part, so
// they are bounded the same way.
func TestMaxEncryptedPartsReplace(t *testing.T) {
	key := bytes.Repeat([]byte{6}, 16)
	body := func(n int) *xdm.Node {
		var b strings.Builder
		b.WriteString(`<r>`)
		for i := range n {
			b.WriteString(partsED(i, key, `<p/>`))
		}
		b.WriteString(`</r>`)
		return covParse(t, b.String())
	}
	header := func(n int) *xdm.Node {
		var b strings.Builder
		b.WriteString(`<S:Envelope xmlns:S="` + soap12 + `"><S:Header>`)
		for range n {
			b.WriteString(`<wsse11:EncryptedHeader xmlns:wsse11="` + xmlsec.NSWSSE11 + `">` + ehED(key, xenc.TypeElement, `<b/>`) + `</wsse11:EncryptedHeader>`)
		}
		b.WriteString(`</S:Header><S:Body/></S:Envelope>`)
		return covParse(t, b.String())
	}
	replace := func(doc, ed *xdm.Node, opts xenc.DecryptOptions) error {
		_, err := xenc.DecryptAndReplace(doc, ed, key, opts)
		return err
	}
	decryptHeader := func(doc, ed *xdm.Node, opts xenc.DecryptOptions) error {
		_, err := xenc.DecryptHeader(doc, ed.Parent(), key, opts)
		return err
	}
	for name, c := range map[string]struct {
		build   func(int) *xdm.Node
		decrypt func(doc, ed *xdm.Node, opts xenc.DecryptOptions) error
	}{
		"DecryptAndReplace": {body, replace},
		"DecryptHeader":     {header, decryptHeader},
	} {
		t.Run(name, func(t *testing.T) {
			doc := c.build(xenc.DefaultMaxEncryptedParts)
			for _, ed := range allNamed(doc, "EncryptedData") {
				if err := c.decrypt(doc, ed, xenc.DecryptOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			doc = c.build(xenc.DefaultMaxEncryptedParts + 1)
			ed := allNamed(doc, "EncryptedData")[0]
			if err := c.decrypt(doc, ed, xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrLimitExceeded) {
				t.Fatalf("%d parts: %v", xenc.DefaultMaxEncryptedParts+1, err)
			}
			if err := c.decrypt(doc, ed, xenc.DecryptOptions{MaxEncryptedParts: 100}); err != nil {
				t.Fatalf("MaxEncryptedParts raised: %v", err)
			}
		})
	}
}

// The receive loop of docs/usage.md calls FindEncryptedKey per part, each a
// walk of the document. FindEncryptedKey has no cap of its own: the first
// decryption of a message with too many parts fails instead, so the loop
// never does more than DefaultMaxEncryptedParts walks.
func TestMaxEncryptedPartsReceiveLoop(t *testing.T) {
	kek := bytes.Repeat([]byte{8}, 16)
	message := func(n int) *xdm.Node {
		ek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM,
			KeyTransportAlgorithm: xmlsec.KeyWrapAES128, KeyEncryptionKey: kek})
		if err != nil {
			t.Fatal(err)
		}
		var eds strings.Builder
		for i := range n {
			if err := ek.AddDataReference(fmt.Sprintf("e%d", i)); err != nil {
				t.Fatal(err)
			}
			eds.WriteString(partsED(i, ek.SessionKey, `<p/>`))
		}
		ekXML, err := c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Inclusive10})
		if err != nil {
			t.Fatal(err)
		}
		return covParse(t, `<r>`+string(ekXML)+eds.String()+`</r>`)
	}
	receive := func(doc *xdm.Node) (int, error) {
		eds, err := xenc.ReferencedData(firstNamed(doc, "ReferenceList"))
		if err != nil {
			t.Fatal(err)
		}
		for i, ed := range eds {
			ekEl, err := xenc.FindEncryptedKey(ed)
			if err != nil {
				t.Fatal(err)
			}
			key, err := xenc.UnwrapEncryptedKey(ekEl, kek, xenc.DecryptOptions{})
			if err != nil {
				return i, err
			}
			if _, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{}); err != nil {
				return i, err
			}
		}
		return len(eds), nil
	}
	// One EncryptedKey and 63 EncryptedData: 64 parts.
	if n, err := receive(message(xenc.DefaultMaxEncryptedParts - 1)); err != nil || n != xenc.DefaultMaxEncryptedParts-1 {
		t.Fatalf("%d parts decrypted, %v", n, err)
	}
	if n, err := receive(message(xenc.DefaultMaxEncryptedParts)); n != 0 || !errors.Is(err, xmlsec.ErrLimitExceeded) {
		t.Fatalf("%d parts decrypted, %v", n, err)
	}
}

// Every Decrypt, Unwrap and Derive function counts EncryptedData,
// EncryptedKey and DerivedKey together, and refuses a document with more
// than the limit before anything else; at the limit, the refusal is
// something else.
func TestMaxEncryptedPartsEveryFunction(t *testing.T) {
	doc := func(n int) (ek, ed, dk *xdm.Node) {
		var b strings.Builder
		b.WriteString(`<r xmlns:xenc="` + xmlsec.NSXEnc + `" xmlns:xenc11="` + xmlsec.NSXEnc11 + `">`)
		for i := range n {
			b.WriteString([]string{`<xenc:EncryptedKey/>`, `<xenc:EncryptedData/>`, `<xenc11:DerivedKey/>`}[i%3])
		}
		b.WriteString(`<other/></r>`)
		root := covParse(t, b.String())
		return firstNamed(root, "EncryptedKey"), firstNamed(root, "EncryptedData"), firstNamed(root, "DerivedKey")
	}
	calls := map[string]func(ek, ed, dk *xdm.Node) error{
		"DecryptData": func(_, ed, _ *xdm.Node) error {
			_, err := xenc.DecryptData(ed, nil, xenc.DecryptOptions{})
			return err
		},
		"DecryptAttachment": func(_, ed, _ *xdm.Node) error {
			_, err := xenc.DecryptAttachment(ed, nil, nil, xenc.DecryptOptions{})
			return err
		},
		"DecryptEncryptedKey": func(ek, _, _ *xdm.Node) error {
			_, err := xenc.DecryptEncryptedKey(ek, nil, xenc.DecryptOptions{})
			return err
		},
		"DecryptEncryptedKeyPKCS1v15": func(ek, ed, _ *xdm.Node) error {
			_, err := xenc.DecryptEncryptedKeyPKCS1v15(ek, ed, nil, xenc.DecryptOptions{})
			return err
		},
		"UnwrapEncryptedKey": func(ek, _, _ *xdm.Node) error {
			_, err := xenc.UnwrapEncryptedKey(ek, nil, xenc.DecryptOptions{})
			return err
		},
		"UnwrapEncryptedKeyPassword": func(ek, _, _ *xdm.Node) error {
			_, err := xenc.UnwrapEncryptedKeyPassword(ek, nil, xenc.DecryptOptions{})
			return err
		},
		"DeriveKey": func(_, ed, dk *xdm.Node) error {
			_, err := xenc.DeriveKey(dk, ed, nil, xenc.DecryptOptions{})
			return err
		},
		"DecryptAgreedKey": func(ek, _, _ *xdm.Node) error {
			_, err := xenc.DecryptAgreedKey(ek, nil, xenc.DecryptOptions{})
			return err
		},
		"DecryptAgreedDataKey": func(_, ed, _ *xdm.Node) error {
			_, err := xenc.DecryptAgreedDataKey(ed, nil, xenc.DecryptOptions{})
			return err
		},
		"DecryptAgreedKeyDH": func(ek, _, _ *xdm.Node) error {
			_, err := xenc.DecryptAgreedKeyDH(ek, nil, xenc.DecryptOptions{})
			return err
		},
		"DecryptAgreedDataKeyDH": func(_, ed, _ *xdm.Node) error {
			_, err := xenc.DecryptAgreedDataKeyDH(ed, nil, xenc.DecryptOptions{})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			if err := call(doc(xenc.DefaultMaxEncryptedParts)); err == nil || errors.Is(err, xmlsec.ErrLimitExceeded) {
				t.Fatalf("at the limit: %v", err)
			}
			if err := call(doc(xenc.DefaultMaxEncryptedParts + 1)); !errors.Is(err, xmlsec.ErrLimitExceeded) {
				t.Fatalf("over the limit: %v", err)
			}
		})
	}
}

// Section 3.5.1 lets several ds:RetrievalMethod elements name one
// EncryptedKey. Each distinct URI is looked up once, so K of them cost a
// constant number of document walks, not K: the time grows with K, not K².
func TestRetrievalMethodsLookedUpOnce(t *testing.T) {
	const rm = `<ds:RetrievalMethod URI="#ek" Type="` + xenc.TypeEncryptedKey + `"/>`
	find := func(k int) (time.Duration, error) {
		ed := firstNamed(covParse(t, `<r `+resolveNS+`>`+resolveEK(`Id="ek"`, ``)+resolveED(``, strings.Repeat(rm, k))+`</r>`), "EncryptedData")
		best := time.Duration(1 << 62)
		for range 5 {
			start := time.Now()
			got, err := xenc.FindEncryptedKey(ed)
			if err != nil {
				return 0, err
			}
			if got.AttrValue("Id") != "ek" {
				return 0, errors.New("wrong EncryptedKey")
			}
			best = min(best, time.Since(start))
		}
		return best, nil
	}
	if _, err := find(10_000); err != nil {
		t.Fatal(err)
	}
	small, err := find(1000)
	if err != nil {
		t.Fatal(err)
	}
	large, err := find(8000)
	if err != nil {
		t.Fatal(err)
	}
	// Linear is a ratio near 8, one walk per child near 64.
	if ratio := float64(large) / float64(max(small, time.Microsecond)); ratio > 32 {
		t.Fatalf("K=1000 took %v, K=8000 %v: ratio %.1f", small, large, ratio)
	}

	// Every child is still checked, repeated or not, and distinct URIs
	// must still name one element.
	typ := `Type="` + xenc.TypeEncryptedKey + `"`
	for _, c := range []struct {
		name, keyInfo string
		want          error
	}{
		{"Id and wsu:Id of one element", strings.Repeat(rm+`<ds:RetrievalMethod URI="#wek" `+typ+`/>`, 3), nil},
		{"repeated, then another Type", rm + rm + `<ds:RetrievalMethod URI="#ek" Type="urn:other"/>`, xmlsec.ErrUnsupportedKeyInfo},
		{"repeated, then a transform", rm + rm + `<ds:RetrievalMethod URI="#ek" ` + typ + `><ds:Transforms/></ds:RetrievalMethod>`, xmlsec.ErrUnsupportedKeyInfo},
		{"repeated, then another element", rm + rm + `<ds:RetrievalMethod URI="#other" ` + typ + `/>`, xmlsec.ErrAmbiguousID},
	} {
		t.Run(c.name, func(t *testing.T) {
			ed := firstNamed(covParse(t, `<r `+resolveNS+`>`+resolveEK(`Id="ek" wsu:Id="wek"`, ``)+resolveEK(`Id="other"`, ``)+
				resolveED(``, c.keyInfo)+`</r>`), "EncryptedData")
			ek, err := xenc.FindEncryptedKey(ed)
			if c.want == nil && (err != nil || ek.AttrValue("Id") != "ek") || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("%v, %v", ek, err)
			}
		})
	}
}
