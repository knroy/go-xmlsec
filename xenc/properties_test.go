package xenc_test

import (
	"bytes"
	"crypto/elliptic"
	"strings"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

func childNames(el *xdm.Node) string {
	var names []string
	for _, k := range el.ChildElements() {
		names = append(names, k.Name.Local)
	}
	return strings.Join(names, ",")
}

// property is an xenc:EncryptionProperty whose content is in a namespace
// declared on an ancestor, so the copy must declare it itself.
func property(t *testing.T) *xdm.Node {
	doc := covParse(t, `<r xmlns:xenc="`+xmlsec.NSXEnc+`" xmlns:p="urn:p"><xenc:EncryptionProperty Target="#ED"><p:When>2026-09-26</p:When></xenc:EncryptionProperty></r>`)
	return doc.ChildElements()[0]
}

// Section 3.7: EncryptionProperties follow CipherData, and MimeType and
// Encoding are carried on element and content encryption too.
func TestEncryptionProperties(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	prop := property(t)
	opts := xenc.EncryptOptions{
		DataAlgorithm:        xmlsec.EncAES128GCM,
		DataID:               "ED",
		MimeType:             "text/xml",
		Encoding:             "http://example.org/utf-8",
		EncryptionProperties: []*xdm.Node{prop, prop},
	}
	for name, encrypt := range map[string]func(doc *xdm.Node) ([]byte, error){
		"element": func(doc *xdm.Node) ([]byte, error) {
			o := opts
			o.Type = xenc.TypeElement
			return xenc.EncryptElement(doc, doc.ChildElements()[0], key, o)
		},
		"content": func(doc *xdm.Node) ([]byte, error) { return xenc.EncryptContent(doc, doc, key, opts) },
	} {
		t.Run(name, func(t *testing.T) {
			// Twice with the same options: the properties are copied, never moved.
			for range 2 {
				out, err := encrypt(covParse(t, `<r><a>x</a></r>`))
				if err != nil {
					t.Fatal(err)
				}
				ed := firstNamed(covParse(t, string(out)), "EncryptedData")
				if got := childNames(ed); got != "EncryptionMethod,CipherData,EncryptionProperties" {
					t.Fatalf("children %s", got)
				}
				if ed.AttrValue("MimeType") != "text/xml" || ed.AttrValue("Encoding") != opts.Encoding {
					t.Fatal("MimeType or Encoding missing")
				}
				props := ed.ChildElements()[2].ChildElements()
				if len(props) != 2 || !firstNamed(props[1], "When").IsElement("urn:p", "When") {
					t.Fatal("properties not copied with their namespaces")
				}
				if _, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	if prop.Parent == nil || prop.Parent.Name.Local != "r" {
		t.Fatal("the caller's property was moved")
	}

	// An attachment gets them too, but its MimeType is the Content-Type.
	att := &xmlsec.Attachment{ID: "a", Body: []byte("b")}
	if _, ed, err := xenc.EncryptAttachment(att, key, xmlsec.TransformAttachmentContentOnly, xenc.EncryptOptions{
		DataAlgorithm: xmlsec.EncAES128GCM, EncryptionProperties: []*xdm.Node{prop},
	}); err != nil || childNames(ed) != "EncryptionMethod,CipherData,EncryptionProperties" {
		t.Fatalf("attachment: %v", err)
	}
}

func TestEncryptionPropertiesRefused(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	deep := xmltree.Element(nil, "xenc", xmlsec.NSXEnc, "EncryptionProperty")
	deep.AddNamespace("xenc", xmlsec.NSXEnc)
	for n, i := deep, 0; i < xmlsec.MaxC14NDepth+1; i++ {
		n = xmltree.Element(n, "", "", "d")
	}
	undeclared := xmltree.Element(nil, "xenc", xmlsec.NSXEnc, "EncryptionProperty")
	xmltree.Element(undeclared, "u", "urn:u", "x")

	base := xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM}
	with := func(f func(*xenc.EncryptOptions)) xenc.EncryptOptions { o := base; f(&o); return o }
	for name, opts := range map[string]xenc.EncryptOptions{
		"nil property":       with(func(o *xenc.EncryptOptions) { o.EncryptionProperties = []*xdm.Node{nil} }),
		"other element":      with(func(o *xenc.EncryptOptions) { o.EncryptionProperties = []*xdm.Node{covParse(t, `<p/>`)} }),
		"too deep":           with(func(o *xenc.EncryptOptions) { o.EncryptionProperties = []*xdm.Node{deep} }),
		"undeclared prefix":  with(func(o *xenc.EncryptOptions) { o.EncryptionProperties = []*xdm.Node{undeclared} }),
		"other Type":         with(func(o *xenc.EncryptOptions) { o.Type = xenc.TypeContent }),
		"CipherReferenceURI": with(func(o *xenc.EncryptOptions) { o.CipherReferenceURI = "http://example.com/ct" }),
	} {
		t.Run(name, func(t *testing.T) {
			doc := covParse(t, `<r><a>x</a></r>`)
			if _, err := xenc.EncryptElement(doc, doc.ChildElements()[0], key, opts); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	att := &xmlsec.Attachment{ID: "a", Body: []byte("b")}
	if _, _, err := xenc.EncryptAttachment(att, key, xmlsec.TransformAttachmentContentOnly, with(func(o *xenc.EncryptOptions) { o.MimeType = "text/plain" })); err == nil {
		t.Fatal("attachment MimeType accepted")
	}
}

// Children are placed by name in schema order, whatever order they are
// added in (sections 3.4, 3.5.1).
func TestEncryptedKeySchemaOrder(t *testing.T) {
	opts := as4Opts(t)
	opts.CarriedKeyName = "k"
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := ek.AddDataReference("ED-1"); err != nil {
		t.Fatal(err)
	}
	name := xmltree.Element(nil, "ds", xmlsec.NSDSig, "KeyName")
	if err := ek.SetKeyInfo(name); err != nil {
		t.Fatal(err)
	}
	if err := ek.AddDataReference("ED-2"); err != nil {
		t.Fatal(err)
	}
	if got := childNames(ek.Element); got != "EncryptionMethod,KeyInfo,CipherData,ReferenceList,CarriedKeyName" {
		t.Fatalf("children %s", got)
	}
}

// Section 3.1: with EncryptionProperties, a ds:KeyInfo the EncryptedData's
// own key adds still goes before CipherData, so the key is found again.
func TestEncryptionPropertiesWithKeyInfo(t *testing.T) {
	master, pw := bytes.Repeat([]byte{9}, 32), []byte("pw")
	r := newECRecipient(t, elliptic.P256(), "")
	r.opts.DirectKeyAgreement = true
	for name, c := range map[string]struct {
		opts   xenc.EncryptOptions
		derive func(ed *xdm.Node) ([]byte, error)
	}{
		"MasterKey": {xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, DigestAlgorithm: xmlsec.DigestSHA256, MasterKey: master},
			func(ed *xdm.Node) ([]byte, error) {
				dk, err := xenc.FindDerivedKey(ed)
				if err != nil {
					return nil, err
				}
				return xenc.DeriveKey(dk, ed, master, xenc.DecryptOptions{})
			}},
		"Password": {xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, Password: pw, PBKDF2Iterations: xenc.MinPBKDF2Iterations},
			func(ed *xdm.Node) ([]byte, error) {
				dk, err := xenc.FindDerivedKey(ed)
				if err != nil {
					return nil, err
				}
				return xenc.DeriveKey(dk, ed, pw, xenc.DecryptOptions{AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2}})
			}},
		"DirectKeyAgreement": {r.opts, func(ed *xdm.Node) ([]byte, error) {
			return xenc.DecryptAgreedDataKey(ed, r.priv, xenc.DecryptOptions{})
		}},
	} {
		t.Run(name, func(t *testing.T) {
			c.opts.EncryptionProperties = []*xdm.Node{property(t)}
			ed := dkEncrypt(t, c.opts)
			if got := childNames(ed); got != "EncryptionMethod,KeyInfo,CipherData,EncryptionProperties" {
				t.Fatalf("children %s", got)
			}
			key, err := c.derive(ed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
