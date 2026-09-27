package dsig_test

import (
	"crypto/sha256"
	"encoding/base64"
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

// Transform chains that end in octets: an attachment's SwA canonical form;
// a canonicalization of canonical octets, which parses them again (XML-DSig
// 4.4.3.2); and #WithComments canonicalization, which renders as its plain
// form. Base64 over an attachment is refused by Sign (SwA profile 5.4.4).
func TestTransformChains(t *testing.T) {
	key := newKey(t, rsaKey)
	atts := attachments(t, "aGVs\r\nbG8=")
	signed := covSignAndPlace(t, key, dsig.KeyInfoX509Data, atts, func(id string) []dsig.Reference {
		return []dsig.Reference{
			{URI: "#" + id, DigestAlgorithm: xmlsec.DigestSHA384,
				Transforms: []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10WithComments)}}},
			{URI: "cid:att-1@example.com", DigestAlgorithm: xmlsec.DigestSHA512,
				Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformAttachmentContentSignature}}},
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
	doc := parse(t, []byte(`<r xmlns:wsu="`+xmlsec.NSWSU+`"><d wsu:Id="d">aGVs<!-- c -->bG8<i>h</i></d></r>`))
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
	const src = `<r xmlns:wsu="` + xmlsec.NSWSU + `"><!-- top --><d wsu:Id="d" ID="s">x<!-- inner --></d></r>`
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
	if _, err := verify(edit(t, doc, "<!-- top -->", `<e xmlns:wsu="`+xmlsec.NSWSU+`" wsu:Id="d"/>`)); !errors.Is(err, xmlsec.ErrAmbiguousID) {
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

// External references: an absolute URI other than cid: is dereferenced
// only through the caller's resolver, as an octet stream, and reported in
// Coverage.ExternalURIs.
func TestExternalReferences(t *testing.T) {
	const (
		plain = "http://example.invalid/plain.bin"
		xml   = "http://example.invalid/doc.xml"
	)
	resources := map[string][]byte{plain: []byte("hello!"), xml: []byte(`<a  b='1'></a>`)}
	var calls []string
	resolve := func(uri string) ([]byte, error) {
		calls = append(calls, uri)
		b, ok := resources[uri]
		if !ok {
			return nil, errors.New("not served")
		}
		return b, nil
	}
	key := newKey(t, rsaKey)
	sign := func(refs []dsig.Reference, r xmlsec.URIResolver) ([]byte, error) {
		doc := parse(t, []byte(`<r/>`))
		_, err := dsig.Sign(doc, key, dsig.SignOptions{
			SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c14n.Exclusive10),
			References: refs, KeyInfo: dsig.KeyInfoX509Data, ResolveURI: r, Parent: xmltree.DocumentElement(doc),
		})
		if err != nil {
			return nil, err
		}
		return serialize(t, doc), nil
	}
	signed, err := sign([]dsig.Reference{
		{URI: plain, DigestAlgorithm: xmlsec.DigestSHA256},
		{URI: xml, DigestAlgorithm: xmlsec.DigestSHA256, Transforms: excC14N},
	}, resolve)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(r xmlsec.URIResolver) (*dsig.Coverage, error) {
		doc := parse(t, signed)
		return dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{Certificate: key.Certificate, ResolveURI: r})
	}

	calls = nil
	cov, err := verify(resolve)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cov.ExternalURIs, []string{plain, xml}) || !slices.Equal(calls, []string{plain, xml}) ||
		cov.WholeDocumentSigned || len(cov.SignedElementIDs) != 0 || len(cov.References) != 2 {
		t.Fatalf("coverage %+v, resolver calls %v", cov, calls)
	}

	// The canonicalization parses the octets, so another serialization of
	// the same XML verifies; other octets do not.
	resources[xml] = []byte(`<a b="1"/>`)
	if _, err := verify(resolve); err != nil {
		t.Fatalf("reserialized: %v", err)
	}
	resources[plain] = []byte("hello?")
	if _, err := verify(resolve); !errors.Is(err, xmlsec.ErrDigestMismatch) {
		t.Fatalf("other octets: %v", err)
	}
	resources[plain] = []byte("hello!")
	resources[xml] = []byte(`<!DOCTYPE a><a/>`)
	if _, err := verify(resolve); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("octets with a DOCTYPE: %v", err)
	}

	errGone := errors.New("gone")
	if _, err := verify(func(string) ([]byte, error) { return nil, errGone }); !errors.Is(err, xmlsec.ErrDereference) || !errors.Is(err, errGone) {
		t.Fatalf("resolver error: %v", err)
	}
	if _, err := verify(nil); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("no resolver: %v", err)
	}

	// Refused when signing: no resolver, a failing one, a relative URI and
	// a URI that does not parse; only the failing one is ever called.
	for _, c := range []struct {
		uri  string
		r    xmlsec.URIResolver
		want error
	}{
		{plain, nil, xmlsec.ErrMalformed},
		{"http://example.invalid/missing", resolve, xmlsec.ErrDereference},
		{"data/plain.bin", resolve, xmlsec.ErrMalformed},
		{"http://[::1", resolve, xmlsec.ErrMalformed},
	} {
		calls = nil
		_, err := sign([]dsig.Reference{{URI: c.uri, DigestAlgorithm: xmlsec.DigestSHA256}}, c.r)
		if !errors.Is(err, c.want) {
			t.Fatalf("sign %q: got %v, want %v", c.uri, err, c.want)
		}
		if c.want == xmlsec.ErrMalformed && len(calls) != 0 {
			t.Fatalf("sign %q called the resolver", c.uri)
		}
	}
}

// XML-DSig 4.4.3.1: with BaseURI, a relative reference is resolved against
// it, never against xml:base, and the resolver and Coverage see the
// absolute URI; without it a relative URI is refused, and a relative
// BaseURI is refused.
func TestBaseURI(t *testing.T) {
	const base = "http://example.invalid/dir/"
	var calls []string
	resolve := func(uri string) ([]byte, error) { calls = append(calls, uri); return []byte("octets"), nil }
	key := newKey(t, rsaKey)
	opts := dsig.SignOptions{
		SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{{URI: "data.bin", DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "../up.bin", DigestAlgorithm: xmlsec.DigestSHA256}, ref("#a")},
		ResolveURI: resolve, BaseURI: base,
	}
	doc := parse(t, []byte(`<r xml:base="http://evil.invalid/"><a xml:id="a"/></r>`))
	sig, err := dsig.Sign(doc, key, opts)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{base + "data.bin", "http://example.invalid/up.bin"}
	if !slices.Equal(calls, want) {
		t.Fatalf("resolver called with %v", calls)
	}
	xmltree.DocumentElement(doc).AppendChild(sig)
	signed := serialize(t, doc)
	if !strings.Contains(string(signed), `URI="data.bin"`) {
		t.Fatalf("the relative URI is not kept:\n%s", signed)
	}
	verify := func(base string) (*dsig.Coverage, error) {
		doc := parse(t, signed)
		return dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey, ResolveURI: resolve, BaseURI: base})
	}
	cov, err := verify(base)
	if err != nil || !slices.Equal(cov.ExternalURIs, want) || cov.References[0].URI != "data.bin" {
		t.Fatalf("coverage %+v: %v", cov, err)
	}
	for _, b := range []string{"", "dir/"} {
		if _, err := verify(b); !errors.Is(err, xmlsec.ErrMalformed) {
			t.Fatalf("verify with BaseURI %q: %v", b, err)
		}
	}
	for _, c := range []struct{ base, uri string }{{"dir/", "data.bin"}, {base, "%zz"}} {
		opts.BaseURI, opts.References = c.base, []dsig.Reference{{URI: c.uri, DigestAlgorithm: xmlsec.DigestSHA256}}
		if _, err := dsig.Sign(parse(t, []byte(`<r/>`)), key, opts); !errors.Is(err, xmlsec.ErrMalformed) {
			t.Fatalf("sign %q against %q: %v", c.uri, c.base, err)
		}
	}
}

// XML-DSig 6.6.4: the enveloped-signature transform applies only to a node
// set from the original document, never to one parsed from octets.
func TestEnvelopedOnReparsedOctets(t *testing.T) {
	_, err := dsig.Sign(parse(t, []byte(`<r/>`)), newKey(t, rsaKey), dsig.SignOptions{
		SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{{URI: "http://example.invalid/doc.xml", DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformXPath, XPath: "true()"},
				{Algorithm: xmlsec.TransformEnvelopedSignature}, excC14N[0]}}},
		ResolveURI: func(string) ([]byte, error) { return []byte(`<a/>`), nil },
	})
	if !errors.Is(err, xmlsec.ErrMalformed) || !strings.Contains(err.Error(), "parsed from octets") {
		t.Fatalf("got %v", err)
	}
}
