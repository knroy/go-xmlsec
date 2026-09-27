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

const manifestDoc = `<r><a xml:id="a">signed through the manifest</a><b xml:id="b">x</b></r>`

var envelopedExc = []dsig.TransformSpec{{Algorithm: xmlsec.TransformEnvelopedSignature}, excC14N[0]}

func findManifest(doc *xdm.Node) *xdm.Node {
	var m *xdm.Node
	xmltree.Walk(doc, func(e *xdm.Node) {
		if m == nil && e.IsElement(xmlsec.NSDSig, "Manifest") {
			m = e
		}
	})
	return m
}

// signManifest builds a Manifest over refs, signs it in place inside doc's
// element (through the Manifest's Id, or the Object's when viaObject), and
// returns the serialized document.
func signManifest(t *testing.T, refs []dsig.Reference, opts dsig.SignOptions, viaObject bool) []byte {
	t.Helper()
	doc := parse(t, []byte(manifestDoc))
	opts.ManifestID = "m"
	m, err := dsig.BuildManifest(doc, refs, opts)
	if err != nil {
		t.Fatal(err)
	}
	r := ref("#m")
	r.Type = xmlsec.TypeManifest
	if viaObject {
		r = ref("#o")
	}
	if _, err := dsig.Sign(doc, newKey(t, rsaKey), dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References:                []dsig.Reference{r},
		Objects:                   []dsig.Object{{ID: "o", Content: []*xdm.Node{m}}},
		Parent:                    xmltree.DocumentElement(doc),
	}); err != nil {
		t.Fatal(err)
	}
	return serialize(t, doc)
}

// XML-DSig 5.1: a signed ds:Manifest's references are the application's to
// check. The signature verifies whatever they now name; VerifyManifest
// reports what they cover, or which one fails.
func TestManifest(t *testing.T) {
	ext := func(uri string) ([]byte, error) { return []byte("external " + uri), nil }
	refs := []dsig.Reference{ref("#a"), {URI: "data.txt", DigestAlgorithm: xmlsec.DigestSHA256},
		{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: envelopedExc},
		{OmitURI: true, DigestAlgorithm: xmlsec.DigestSHA256}}
	sopts := dsig.SignOptions{ResolveURI: ext, BaseURI: "http://example.com/dir/", OmittedURIData: []byte("known")}
	vopts := dsig.VerifyOptions{ResolveURI: ext, BaseURI: "http://example.com/dir/",
		ResolveOmittedURI: func() ([]byte, error) { return []byte("known"), nil }}
	for _, viaObject := range []bool{false, true} {
		signed := signManifest(t, refs, sopts, viaObject)
		if !strings.Contains(string(signed), `<ds:Object Id="o"><ds:Manifest Id="m">`) {
			t.Fatalf("no Manifest in\n%s", signed)
		}
		doc := parse(t, signed)
		cov, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		mcov, err := dsig.VerifyManifest(doc, findManifest(doc), cov, vopts)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(mcov.SignedElementIDs, []string{"a"}) || !slices.Equal(mcov.ExternalURIs, []string{"http://example.com/dir/data.txt"}) ||
			!mcov.WholeDocumentSigned || !mcov.OmittedURISigned || mcov.PublicKey == nil || len(mcov.References) != 4 ||
			!strings.HasPrefix(string(mcov.References[0].Raw), `<ds:Reference xmlns:ds=`) {
			t.Fatalf("manifest coverage %+v", mcov)
		}

		// A changed target leaves the signature valid and fails the Manifest.
		doc = parse(t, []byte(strings.Replace(string(signed), "signed through", "changed after", 1)))
		if cov, err = dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey}); err != nil {
			t.Fatal(err)
		}
		if _, err := dsig.VerifyManifest(doc, findManifest(doc), cov, vopts); !errors.Is(err, xmlsec.ErrDigestMismatch) {
			t.Fatalf("changed target: %v", err)
		}
	}
}

// Only a Manifest the signature covers is followed, and its references are
// admitted as a signature's are, before any digest.
func TestVerifyManifestRefusals(t *testing.T) {
	signed := signManifest(t, []dsig.Reference{ref("#a")}, dsig.SignOptions{}, false)
	doc := parse(t, signed)
	cov, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	m := findManifest(doc)
	other := parse(t, signed)

	// A Manifest standing alone, as a caller-built Coverage names it: its
	// enveloped-signature transform removes only the Manifest.
	loose := func(inner string) (*xdm.Node, *xdm.Node, *dsig.Coverage) {
		d := parse(t, []byte(`<r><ds:Manifest xmlns:ds="`+xmlsec.NSDSig+`">`+inner+`</ds:Manifest></r>`))
		lm := findManifest(d)
		return d, lm, &dsig.Coverage{SignedElements: []*xdm.Node{lm}}
	}
	refXML := func(attrs string) string {
		return `<ds:Reference ` + attrs + `>` + covTr + covDigest + `</ds:Reference>`
	}
	cases := []struct {
		name string
		args func() (*xdm.Node, *xdm.Node, *dsig.Coverage)
		opts dsig.VerifyOptions
		want error
	}{
		{"nil document", func() (*xdm.Node, *xdm.Node, *dsig.Coverage) { return nil, m, cov }, dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"not a Manifest", func() (*xdm.Node, *xdm.Node, *dsig.Coverage) { return doc, findSignature(doc), cov }, dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"Manifest of another document", func() (*xdm.Node, *xdm.Node, *dsig.Coverage) { return other, m, cov }, dsig.VerifyOptions{}, nil},
		{"no Coverage", func() (*xdm.Node, *xdm.Node, *dsig.Coverage) { return doc, m, nil }, dsig.VerifyOptions{}, xmlsec.ErrSignatureInvalid},
		{"not signed", func() (*xdm.Node, *xdm.Node, *dsig.Coverage) { return doc, m, &dsig.Coverage{} }, dsig.VerifyOptions{}, xmlsec.ErrSignatureInvalid},
		{"another document's Coverage", func() (*xdm.Node, *xdm.Node, *dsig.Coverage) { return other, findManifest(other), cov }, dsig.VerifyOptions{}, xmlsec.ErrSignatureInvalid},
		{"relative BaseURI", func() (*xdm.Node, *xdm.Node, *dsig.Coverage) { return doc, m, cov }, dsig.VerifyOptions{BaseURI: "dir/"}, xmlsec.ErrMalformed},
		{"digest not allowed", func() (*xdm.Node, *xdm.Node, *dsig.Coverage) { return doc, m, cov },
			dsig.VerifyOptions{AllowedDigestAlgorithms: []string{xmlsec.DigestSHA512}}, xmlsec.ErrAlgorithmNotAllowed},
		{"too many references", func() (*xdm.Node, *xdm.Node, *dsig.Coverage) { return loose(refXML(`URI="#a"`) + refXML(`URI="#a"`)) },
			dsig.VerifyOptions{MaxReferences: 1}, xmlsec.ErrLimitExceeded},
		{"empty", func() (*xdm.Node, *xdm.Node, *dsig.Coverage) { return loose("") }, dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"not a Reference", func() (*xdm.Node, *xdm.Node, *dsig.Coverage) { return loose(`<ds:Object/>`) }, dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"no canonical form", func() (*xdm.Node, *xdm.Node, *dsig.Coverage) {
			return loose(refXML(`xmlns:rel="relative" rel:x="1" URI="#a"`))
		}, dsig.VerifyOptions{}, xmlsec.ErrUnverifiable},
		{"two omitted URIs", func() (*xdm.Node, *xdm.Node, *dsig.Coverage) { return loose(refXML(``) + refXML(``)) },
			dsig.VerifyOptions{ResolveOmittedURI: func() ([]byte, error) { return nil, nil }}, xmlsec.ErrMalformed},
		{"enveloped removes only the Manifest", func() (*xdm.Node, *xdm.Node, *dsig.Coverage) {
			return loose(`<ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="` + xmlsec.TransformEnvelopedSignature +
				`"/><ds:Transform Algorithm="` + covExc + `"/></ds:Transforms>` + covDigest + `</ds:Reference>`)
		}, dsig.VerifyOptions{}, xmlsec.ErrDigestMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, man, cv := c.args()
			if _, err := dsig.VerifyManifest(d, man, cv, c.opts); err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestBuildManifestRefusals(t *testing.T) {
	doc := parse(t, []byte(manifestDoc))
	cases := []struct {
		name string
		doc  *xdm.Node
		refs []dsig.Reference
		opts dsig.SignOptions
		want error
	}{
		{"no document", nil, []dsig.Reference{ref("#a")}, dsig.SignOptions{}, xmlsec.ErrMalformed},
		{"no references", doc, nil, dsig.SignOptions{}, nil},
		{"bad reference", doc, []dsig.Reference{{URI: "#a", DigestAlgorithm: xmlsec.DigestSHA1}}, dsig.SignOptions{}, xmlsec.ErrUnsupportedAlgorithm},
		{"ManifestID", doc, []dsig.Reference{ref("#a")}, dsig.SignOptions{ManifestID: "1"}, xmlsec.ErrMalformed},
		{"repeated Id", doc, []dsig.Reference{{URI: "#a", ID: "m", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: excC14N}},
			dsig.SignOptions{ManifestID: "m"}, xmlsec.ErrMalformed},
		{"the Manifest's own Id", doc, []dsig.Reference{ref("#m")}, dsig.SignOptions{ManifestID: "m"}, xmlsec.ErrIDNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := dsig.BuildManifest(c.doc, c.refs, c.opts)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}
