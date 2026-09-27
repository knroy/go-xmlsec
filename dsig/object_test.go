package dsig_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// content returns the children of the document element of s.
func content(t *testing.T, s string) []*xdm.Node {
	t.Helper()
	return xmltree.DocumentElement(parse(t, []byte(s))).Children
}

// enveloping signs with no document and returns the signature serialized
// as the document element.
func enveloping(t *testing.T, opts dsig.SignOptions) ([]byte, error) {
	t.Helper()
	sig, err := dsig.Sign(nil, newKey(t, rsaKey), opts)
	if err != nil {
		return nil, err
	}
	doc := &xdm.Node{Kind: xdm.KindDocument}
	doc.AppendChild(sig)
	return serialize(t, doc), nil
}

func ref(uri string) dsig.Reference {
	return dsig.Reference{URI: uri, DigestAlgorithm: xmlsec.DigestSHA256, Transforms: excC14N}
}

// XML-DSig 4.6 and 5.2: an enveloping signature over its ds:Object, its
// ds:SignatureProperty and its ds:KeyInfo, each named by the Id Sign gave
// it, verifies without IDAttrDSig, and covers what it names.
func TestEnvelopingSignature(t *testing.T) {
	opts := dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		KeyInfo:                   dsig.KeyInfoX509Data,
		SignatureID:               "sig",
		SignedInfoID:              "si",
		SignatureValueID:          "sv",
		KeyInfoID:                 "ki",
		References:                []dsig.Reference{ref("#obj"), ref("#prop"), ref("#ki")},
		Objects: []dsig.Object{
			{ID: "obj", MimeType: "text/xml", Encoding: "urn:enc",
				Content: content(t, `<r xmlns:p="urn:p">text<p:data a="1">hello</p:data><!--c--><?pi x?></r>`)},
			{Content: content(t, `<r>unsigned</r>`)},
		},
		Properties: []dsig.SignatureProperty{
			{ID: "prop", Content: content(t, `<r xmlns:t="urn:t"><t:time>2026-09-26</t:time></r>`)},
			{Target: "#other", Content: content(t, `<r xmlns:t="urn:t"> <t:x/></r>`)},
		},
	}
	signed, err := enveloping(t, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`<ds:Signature xmlns:ds="` + xmlsec.NSDSig + `" Id="sig"><ds:SignedInfo Id="si">`,
		`<ds:SignatureValue Id="sv">`, `<ds:KeyInfo Id="ki">`,
		`<ds:Object Encoding="urn:enc" Id="obj" MimeType="text/xml">text<p:data xmlns:p="urn:p" a="1">hello</p:data><!--c--><?pi x?></ds:Object>`,
		`<ds:Object><ds:SignatureProperties><ds:SignatureProperty Id="prop" Target="#sig"><t:time xmlns:t="urn:t">`,
		`<ds:SignatureProperty Target="#other">`,
	} {
		if !strings.Contains(string(signed), want) {
			t.Fatalf("missing %s in\n%s", want, signed)
		}
	}
	doc := parse(t, signed)
	// With IDAttrDSig as well, each Id is still counted once.
	if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{IDAttributes: []xdm.QName{dsig.IDAttrDSig}}); err != nil {
		t.Fatal(err)
	}
	cov, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cov.SignedElementIDs, []string{"obj", "prop", "ki"}) || cov.SignedElements[0].Name.Local != "Object" {
		t.Fatalf("coverage %v", cov.SignedElementIDs)
	}

	for _, tamper := range []string{"hello", "2026-09-26", `<ds:KeyInfo Id="ki">`} {
		doc := parse(t, []byte(strings.Replace(string(signed), tamper, tamper+" ", 1)))
		if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{}); !errors.Is(err, xmlsec.ErrDigestMismatch) {
			t.Fatalf("tampered %s: %v", tamper, err)
		}
	}
}

// A detached signature placed in the document signs its own ds:Object and
// a document element, and a same-document Id elsewhere that repeats an
// Object's Id makes the reference ambiguous.
func TestObjectInDetachedSignature(t *testing.T) {
	doc := parse(t, []byte(`<r><a xml:id="a">x</a></r>`))
	opts := dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References:                []dsig.Reference{ref("#a"), ref("#obj")},
		Objects:                   []dsig.Object{{ID: "obj", Content: content(t, `<r>data</r>`)}},
	}
	sig, err := dsig.Sign(doc, newKey(t, rsaKey), opts)
	if err != nil {
		t.Fatal(err)
	}
	xmltree.DocumentElement(doc).AppendChild(sig)
	signed := serialize(t, doc)
	got := parse(t, signed)
	if _, err := dsig.Verify(got, findSignature(got), dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey}); err != nil {
		t.Fatal(err)
	}
	dup := parse(t, []byte(strings.Replace(string(signed), `<r>`, `<r><b xml:id="obj"/>`, 1)))
	if _, err := dsig.Verify(dup, findSignature(dup), dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey}); !errors.Is(err, xmlsec.ErrAmbiguousID) {
		t.Fatalf("duplicated Object Id: %v", err)
	}

	// A second signature computed in place whose Object repeats the first's
	// Id is ambiguous.
	opts.IDAttributes = []xdm.QName{dsig.IDAttrDSig}
	opts.Parent = xmltree.DocumentElement(doc)
	if _, err := dsig.Sign(doc, newKey(t, rsaKey), opts); !errors.Is(err, xmlsec.ErrAmbiguousID) {
		t.Fatalf("the first signature's Object still stands: %v", err)
	}
}

// Only the Ids the signature schema gives its own elements count, and only
// where Sign puts them: a ds:Object nested in content, or another
// signature's, is not the signature's own.
func TestOwnIDs(t *testing.T) {
	nested := content(t, `<r xmlns:ds="`+xmlsec.NSDSig+`"><ds:Object Id="inner"/><x><ds:Manifest Id="m"/></x>`+
		`<ds:SignatureProperty Id="sp"/><ds:KeyInfo Id="k"/><ds:Reference Id="rf"/><x Id="plain"/></r>`)
	for _, id := range []string{"inner", "m", "sp", "k", "rf", "plain"} {
		_, err := enveloping(t, dsig.SignOptions{
			SignatureAlgorithm:        xmlsec.SigRSASHA256,
			CanonicalizationAlgorithm: string(c14n.Exclusive10),
			References:                []dsig.Reference{ref("#" + id)},
			Objects:                   []dsig.Object{{Content: nested}},
		})
		if !errors.Is(err, xmlsec.ErrIDNotFound) {
			t.Fatalf("%s: %v", id, err)
		}
	}
}

func TestObjectRefusals(t *testing.T) {
	attr := &xdm.Node{Kind: xdm.KindAttribute, Name: xdm.QName{Local: "a"}}
	el := content(t, `<r xmlns:t="urn:t"><t:x/></r>`)
	cases := []struct {
		name string
		mod  func(*dsig.SignOptions)
		want error
	}{
		{"Object ID", func(o *dsig.SignOptions) { o.Objects = []dsig.Object{{ID: "1x"}} }, xmlsec.ErrMalformed},
		{"Object Encoding", func(o *dsig.SignOptions) { o.Objects = []dsig.Object{{Encoding: "a b"}} }, xmlsec.ErrMalformed},
		{"nil content", func(o *dsig.SignOptions) { o.Objects = []dsig.Object{{Content: []*xdm.Node{nil}}} }, xmlsec.ErrMalformed},
		{"attribute content", func(o *dsig.SignOptions) { o.Objects = []dsig.Object{{Content: []*xdm.Node{attr}}} }, xmlsec.ErrMalformed},
		{"document content", func(o *dsig.SignOptions) {
			o.Objects = []dsig.Object{{Content: []*xdm.Node{{Kind: xdm.KindDocument}}}}
		}, xmlsec.ErrMalformed},
		{"property ID", func(o *dsig.SignOptions) { o.Properties = []dsig.SignatureProperty{{ID: "a:b", Content: el}} }, xmlsec.ErrMalformed},
		{"property without Target or SignatureID", func(o *dsig.SignOptions) {
			o.SignatureID = ""
			o.Properties = []dsig.SignatureProperty{{Content: el}}
		}, xmlsec.ErrMalformed},
		{"property Target", func(o *dsig.SignOptions) { o.Properties = []dsig.SignatureProperty{{Target: "# x", Content: el}} }, xmlsec.ErrMalformed},
		{"property content kind", func(o *dsig.SignOptions) {
			o.Properties = []dsig.SignatureProperty{{Content: []*xdm.Node{attr}}}
		}, xmlsec.ErrMalformed},
		{"property content in ds", func(o *dsig.SignOptions) {
			o.Properties = []dsig.SignatureProperty{{Content: content(t, `<r xmlns:ds="`+xmlsec.NSDSig+`"><ds:X/></r>`)}}
		}, xmlsec.ErrMalformed},
		{"property content in no namespace", func(o *dsig.SignOptions) {
			o.Properties = []dsig.SignatureProperty{{Content: content(t, `<r><x/></r>`)}}
		}, xmlsec.ErrMalformed},
		{"property content without an element", func(o *dsig.SignOptions) {
			o.Properties = []dsig.SignatureProperty{{Content: content(t, `<r>text</r>`)}}
		}, xmlsec.ErrMalformed},
		{"SignedInfoID", func(o *dsig.SignOptions) { o.SignedInfoID = "a b" }, xmlsec.ErrMalformed},
		{"KeyInfoID without KeyInfo", func(o *dsig.SignOptions) { o.KeyInfoID = "ki" }, xmlsec.ErrMalformed},
		{"repeated Id", func(o *dsig.SignOptions) {
			o.Objects = []dsig.Object{{ID: "sig"}}
		}, xmlsec.ErrMalformed},
		{"repeated Reference Id", func(o *dsig.SignOptions) {
			o.References[0].ID = "p"
			o.Properties = []dsig.SignatureProperty{{ID: "p", Content: el}}
		}, xmlsec.ErrMalformed},
		{"whole document without a document", func(o *dsig.SignOptions) {
			o.References = []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256,
				Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformEnvelopedSignature}, excC14N[0]}}}
		}, xmlsec.ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := dsig.SignOptions{
				SignatureAlgorithm:        xmlsec.SigRSASHA256,
				CanonicalizationAlgorithm: string(c14n.Exclusive10),
				SignatureID:               "sig",
				References:                []dsig.Reference{ref("#sig-obj")},
				Objects:                   []dsig.Object{{ID: "sig-obj"}},
			}
			c.mod(&opts)
			if _, err := enveloping(t, opts); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}
