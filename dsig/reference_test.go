package dsig_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

// Transform chains that end in octets: base64 over an attachment's SwA
// canonical form; a canonicalization of canonical octets, which parses them
// again (XML-DSig 4.4.3.2); and #WithComments canonicalization, which
// renders as its plain form.
func TestTransformChains(t *testing.T) {
	key := newKey(t, rsaKey)
	atts := attachments(t, "aGVs\r\nbG8=")
	signed := covSignAndPlace(t, key, dsig.KeyInfoX509Data, atts, func(id string) []dsig.Reference {
		return []dsig.Reference{
			{URI: "#" + id, DigestAlgorithm: xmlsec.DigestSHA384,
				Transforms: []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10WithComments)}}},
			{URI: "cid:att-1@example.com", DigestAlgorithm: xmlsec.DigestSHA512,
				Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformAttachmentContentSignature}, {Algorithm: xmlsec.TransformBase64}}},
			{URI: "#" + id, DigestAlgorithm: xmlsec.DigestSHA256,
				Transforms: []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}, {Algorithm: string(c14n.Inclusive10)}}},
		}
	})
	doc := parse(t, signed)
	cov, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{Attachments: atts})
	if err != nil {
		t.Fatal(err)
	}
	if len(cov.SignedElementIDs) != 2 || !cov.CoversAttachments("att-1@example.com") {
		t.Fatalf("coverage %+v", cov)
	}

	// The base64 transform digests the decoded octets, so a change in
	// whitespace alone does not alter it; a change in content does.
	if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{Attachments: attachments(t, "aGVsbG8=")}); err != nil {
		t.Fatalf("whitespace change: %v", err)
	}
	if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{Attachments: attachments(t, "aGVsbG9v")}); !errors.Is(err, xmlsec.ErrDigestMismatch) {
		t.Fatalf("content change: %v", err)
	}
	if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{}); !errors.Is(err, xmlsec.ErrAttachmentNotFound) {
		t.Fatalf("no attachments: %v", err)
	}
}

// Every #WithComments transform digests as its plain form, since a bare
// dereference has already dropped comments.
func TestWithCommentsTransforms(t *testing.T) {
	key := newKey(t, rsaKey)
	for _, alg := range []c14n.Algorithm{c14n.Inclusive10WithComments, c14n.Inclusive11WithComments, c14n.Exclusive10WithComments} {
		t.Run(string(alg), func(t *testing.T) {
			signed, err := dsig.SignEnveloped(parse(t, []byte(metadata)), key, dsig.SignOptions{
				SignatureAlgorithm:        xmlsec.SigRSASHA256,
				CanonicalizationAlgorithm: string(c14n.Inclusive10),
				References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
					{Algorithm: xmlsec.TransformEnvelopedSignature}, {Algorithm: string(alg)},
				}}},
				KeyInfo: dsig.KeyInfoX509Data,
			})
			if err != nil {
				t.Fatal(err)
			}
			doc := parse(t, signed)
			if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{}); err != nil {
				t.Fatal(err)
			}
			// Comments are outside the digest.
			doc = parse(t, []byte(strings.Replace(string(signed), "<!-- comment -->", "<!-- other -->", 1)))
			if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{}); err != nil {
				t.Fatalf("comment change: %v", err)
			}
		})
	}
}

// The SwA signature transforms digest the canonical form of the attachment
// (SwA profile 5.4): a change canonicalization absorbs verifies, a change it
// does not is a digest mismatch, and only Attachment-Complete covers the
// headers.
func TestSwASignatureTransforms(t *testing.T) {
	key := newKey(t, rsaKey)
	set := func(desc, body string) xmlsec.AttachmentSet {
		s, err := xmlsec.NewAttachmentSet(&xmlsec.Attachment{ID: "att-1@example.com", Body: []byte(body),
			MIMEHeaders: map[string][]string{
				"Content-ID":          {"<att-1@example.com>"},
				"Content-Type":        {"application/xml; charset=UTF-8"},
				"Content-Description": {desc},
			}})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	ref := func(alg string) dsig.Reference {
		return dsig.Reference{URI: "cid:att-1@example.com", DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms: []dsig.TransformSpec{{Algorithm: alg}}}
	}
	for _, alg := range []string{xmlsec.TransformAttachmentContentSignature, xmlsec.TransformAttachmentCompleteSignature} {
		t.Run(alg, func(t *testing.T) {
			signed := covSignAndPlace(t, key, dsig.KeyInfoX509Data, set("invoice", `<a b="1"><c/></a>`), func(string) []dsig.Reference {
				return []dsig.Reference{ref(alg)}
			})
			verify := func(atts xmlsec.AttachmentSet) error {
				doc := parse(t, signed)
				cov, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{Attachments: atts})
				if err == nil && !cov.CoversAttachments("att-1@example.com") {
					t.Fatalf("coverage %+v", cov)
				}
				return err
			}
			if err := verify(set("invoice", "<?xml version='1.0'?>\n<a  b='1'><c></c><!-- x --></a>\n")); err != nil {
				t.Fatalf("canonically equal body: %v", err)
			}
			if err := verify(set("invoice", `<a b="2"><c/></a>`)); !errors.Is(err, xmlsec.ErrDigestMismatch) {
				t.Fatalf("changed body: %v", err)
			}
			err := verify(set("receipt", `<a b="1"><c/></a>`))
			if complete := alg == xmlsec.TransformAttachmentCompleteSignature; complete != errors.Is(err, xmlsec.ErrDigestMismatch) || !complete && err != nil {
				t.Fatalf("changed Content-Description: %v", err)
			}
		})
	}
}

// XML-DSig 6.6.2: base64 over a node set decodes the concatenated text
// nodes, in document order, skipping comments and markup. Such a chain ends
// in octets, so it does not rely on implicit canonicalization.
func TestBase64OfNodeSet(t *testing.T) {
	key := newKey(t, rsaKey)
	doc := parse(t, []byte(`<r xmlns:wsu="`+wss.NSWSU+`"><d wsu:Id="d">aGVs<!-- c -->bG8<i>h</i></d></r>`))
	sig, err := dsig.Sign(doc, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{{URI: "#d", DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformBase64}}}},
		Parent: xmltree.DocumentElement(doc),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("hello!"))
	if got := sig.ChildElements()[0].ChildElements()[2].ChildElements()[2].StringValue(); got != base64.StdEncoding.EncodeToString(want[:]) {
		t.Fatalf("DigestValue %s, want the digest of %q", got, "hello!")
	}
	cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{
		Certificate:                       key.Certificate,
		RequireExplicitCanonicalization:   true,
		AllowedCanonicalizationAlgorithms: []string{string(c14n.Exclusive10)},
	})
	if err != nil || !cov.Covers("d") {
		t.Fatalf("verify: %v", err)
	}
}

// #xpointer(/) and #xpointer(id('ID')) keep comments (XML-DSig 4.4.3.3), so
// a #WithComments canonicalization covers them; "" and "#id" do not.
func TestXPointerReferences(t *testing.T) {
	key := newKey(t, rsaKey)
	const src = `<r xmlns:wsu="` + wss.NSWSU + `"><!-- top --><d wsu:Id="d" ID="s">x<!-- inner --></d></r>`
	incWC := string(c14n.Inclusive10WithComments)

	signIn := func(t *testing.T, uri, alg string, ids ...xdm.QName) *xdm.Node {
		t.Helper()
		doc := parse(t, []byte(src))
		var ts []dsig.TransformSpec
		if uri == "" || uri == "#xpointer(/)" {
			ts = append(ts, dsig.TransformSpec{Algorithm: xmlsec.TransformEnvelopedSignature})
		}
		if _, err := dsig.Sign(doc, key, dsig.SignOptions{
			SignatureAlgorithm:        xmlsec.SigRSASHA256,
			CanonicalizationAlgorithm: string(c14n.Inclusive10),
			References: []dsig.Reference{{URI: uri, DigestAlgorithm: xmlsec.DigestSHA256,
				Transforms: append(ts, dsig.TransformSpec{Algorithm: alg})}},
			Parent:       xmltree.DocumentElement(doc),
			IDAttributes: ids,
		}); err != nil {
			t.Fatal(err)
		}
		return parse(t, serialize(t, doc))
	}
	verify := func(doc *xdm.Node, ids ...xdm.QName) (*dsig.Coverage, error) {
		return dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{Certificate: key.Certificate, IDAttributes: ids})
	}
	edit := func(t *testing.T, doc *xdm.Node, old, new string) *xdm.Node {
		t.Helper()
		return parse(t, []byte(strings.Replace(string(serialize(t, doc)), old, new, 1)))
	}

	cases := []struct {
		name, uri, alg string
		ids            []xdm.QName
		wantID         string // "": the whole document
		comment        string
		covered        bool // the comment is in the digest
	}{
		{"#xpointer(/) with comments", "#xpointer(/)", incWC, nil, "", "top", true},
		{"#xpointer(/) without comments", "#xpointer(/)", string(c14n.Inclusive10), nil, "", "top", false},
		{"empty URI with comments", "", incWC, nil, "", "top", false},
		{"#xpointer(id('d')) with comments", "#xpointer(id('d'))", incWC, nil, "d", "inner", true},
		{`#xpointer(id("d")) with comments`, `#xpointer(id("d"))`, incWC, nil, "d", "inner", true},
		{"#xpointer(id('s')) by IDAttributes", "#xpointer(id('s'))", incWC, []xdm.QName{dsig.IDAttrSAML}, "s", "inner", true},
		{"#d with comments", "#d", incWC, nil, "d", "inner", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := signIn(t, c.uri, c.alg, c.ids...)
			cov, err := verify(doc, c.ids...)
			if err != nil {
				t.Fatal(err)
			}
			if c.wantID == "" && !cov.WholeDocumentSigned ||
				c.wantID != "" && (!cov.Covers(c.wantID) || len(cov.SignedElements) != 1 || cov.SignedElements[0].Name.Local != "d") {
				t.Fatalf("coverage %+v", cov)
			}
			_, err = verify(edit(t, doc, "<!-- "+c.comment+" -->", "<!-- changed -->"), c.ids...)
			if c.covered != errors.Is(err, xmlsec.ErrDigestMismatch) || !c.covered && err != nil {
				t.Fatalf("comment changed: %v", err)
			}
		})
	}

	// Duplicate IDs are refused through an XPointer as through "#id".
	doc := signIn(t, "#xpointer(id('d'))", incWC)
	if _, err := verify(edit(t, doc, "<!-- top -->", `<e xmlns:wsu="`+wss.NSWSU+`" wsu:Id="d"/>`)); !errors.Is(err, xmlsec.ErrAmbiguousID) {
		t.Fatalf("duplicate wsu:Id: %v", err)
	}
	if _, err := verify(edit(t, doc, "<!-- top -->", `<e ID="d"/>`), dsig.IDAttrSAML); !errors.Is(err, xmlsec.ErrAmbiguousID) {
		t.Fatalf("duplicate across wsu:Id and ID: %v", err)
	}
	// Any other XPointer is refused when verifying too.
	sig := findSignature(doc)
	sig.ChildElements()[0].ChildElements()[2].Attr("", "URI").Value = "#xpointer(id('d')/..)"
	resignSI(t, sig, c14n.Inclusive10)
	if _, err := verify(doc); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("XPointer expression: %v", err)
	}
}
