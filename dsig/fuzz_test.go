package dsig_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

// must panics on err. It is for fuzz setup only: the helpers in
// dsig_test.go take a *testing.T, which fuzz setup does not have.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func fuzzKey() xmlsec.KeyProvider {
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fuzz"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0)}
	der := must(x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaKey.PublicKey, rsaKey))
	return xmlsec.KeyProvider{Signer: rsaKey, Certificate: must(x509.ParseCertificate(der))}
}

// fuzzSigned returns a WS-Security detached signature, as signAS4 builds,
// and an enveloped one, as signEnveloped builds.
func fuzzSigned(key xmlsec.KeyProvider) (detached, enveloped []byte) {
	doc := must(xmlsec.Parse([]byte(envelope))).Root
	env := xmltree.DocumentElement(doc)
	msgID := must(wss.AssignID(doc, env.ChildElements()[0].ChildElements()[0]))
	bodyID := must(wss.AssignID(doc, env.ChildElements()[1]))
	hdr := must(wss.NewHeader(doc, wss.NSSOAP12, "", true))
	tok := must(hdr.AddBinarySecurityToken(key.Certificate, nil, xmlsec.BSTValueTypeX509v3))
	atts := must(xmlsec.NewAttachmentSet(&xmlsec.Attachment{ID: "att-1@example.com", Body: []byte("payload")}))
	sig := must(dsig.Sign(doc, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{
			{URI: "#" + msgID, Transforms: excC14N, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "#" + bodyID, Transforms: excC14N, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "cid:att-1@example.com", DigestAlgorithm: xmlsec.DigestSHA256,
				Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformAttachmentContentOnly}}},
		},
		KeyInfo:         dsig.KeyInfoSecurityTokenReference,
		SecurityTokenID: tok,
		Attachments:     atts,
	}))
	if err := hdr.Append(sig); err != nil {
		panic(err)
	}
	detached = must(c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10WithComments}))

	enveloped = must(dsig.SignEnveloped(must(xmlsec.Parse([]byte(metadata))).Root, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Inclusive10),
		References: []dsig.Reference{{
			DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms: []dsig.TransformSpec{
				{Algorithm: xmlsec.TransformEnvelopedSignature},
				{Algorithm: string(c14n.Inclusive10)},
			},
		}},
		KeyInfo: dsig.KeyInfoX509Data,
	}))
	return detached, enveloped
}

// resign recomputes ds:SignatureValue over sig's SignedInfo as it stands, so
// that a mutated document still passes the signature check and the fuzzer
// reaches reference dereferencing and transforms. It reports whether it
// could.
func resign(sig *xdm.Node) bool {
	kids := sig.ChildElements()
	if len(kids) < 2 || !kids[0].IsElement(dsig.NSDSig, "SignedInfo") {
		return false
	}
	si := kids[0].ChildElements()
	if len(si) < 2 {
		return false
	}
	opts := c14n.Options{Algorithm: c14n.Algorithm(si[0].AttrValue("Algorithm"))}
	if in := si[0].ChildElements(); len(in) == 1 {
		opts.InclusiveNamespacePrefixes = c14n.ParsePrefixList(in[0].AttrValue("PrefixList"))
	}
	h, ok := xmlsec.SignatureHash(si[1].AttrValue("Algorithm"))
	if !ok || !strings.Contains(si[1].AttrValue("Algorithm"), "#rsa-") {
		return false
	}
	w := h.New()
	if _, err := c14n.DigestNodeSet(w, c14n.Subtree(kids[0]), opts); err != nil {
		return false
	}
	v, err := rsa.SignPKCS1v15(nil, rsaKey, crypto.Hash(h), w.Sum(nil))
	if err != nil {
		return false
	}
	kids[1].Children = nil
	xmltree.Text(kids[1], base64.StdEncoding.EncodeToString(v))
	return true
}

const fuzzSigOpen = `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`

func fuzzSignedInfo(refs string) string {
	return fuzzSigOpen + `<ds:SignedInfo>` +
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
		`<ds:SignatureMethod Algorithm="` + xmlsec.SigRSASHA256 + `"/>` + refs +
		`</ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>`
}

func fuzzReference(uri, transforms, digest string) string {
	return `<ds:Reference URI="` + uri + `"><ds:Transforms>` + transforms + `</ds:Transforms>` +
		`<ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"/><ds:DigestValue>` + digest + `</ds:DigestValue></ds:Reference>`
}

const fuzzExc = `<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`

func FuzzVerify(f *testing.F) {
	key := fuzzKey()
	detached, enveloped := fuzzSigned(key)
	good := "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	f.Add(detached, []byte("payload"))
	f.Add(enveloped, []byte(nil))
	f.Add([]byte(fuzzSigOpen+`</ds:Signature>`), []byte(nil))
	f.Add([]byte(fuzzSignedInfo(strings.Repeat(fuzzReference("", fuzzExc, good), 100))), []byte(nil))
	f.Add([]byte(fuzzSignedInfo(fuzzReference("", `<ds:Transform Algorithm="`+xmlsec.TransformXSLT+`">`+
		`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"/></ds:Transform>`, good))), []byte(nil))
	f.Add([]byte(fuzzSignedInfo(fuzzReference("#x", fuzzExc, "!!not=base64")+fuzzReference("cid:a", "", "QUJD="))), []byte("QUJD"))
	// A reference to the signature itself, and one to its own SignedInfo.
	cyclic := fuzzSignedInfo(fuzzReference("#s", `<ds:Transform Algorithm="`+xmlsec.TransformEnvelopedSignature+`"/>`+fuzzExc, good) +
		fuzzReference("#si", fuzzExc, good))
	cyclic = strings.NewReplacer(fuzzSigOpen, fuzzSigOpen[:len(fuzzSigOpen)-1]+` xml:id="s">`,
		`<ds:SignedInfo>`, `<ds:SignedInfo xml:id="si">`).Replace(cyclic)
	f.Add([]byte(cyclic), []byte(nil))
	var nested strings.Builder
	for i := range 200 {
		nested.WriteString(`<e xmlns="urn:n` + string(rune('a'+i%26)) + `" xmlns:p` + string(rune('a'+i%26)) + `="urn:p">`)
	}
	nested.WriteString(fuzzSignedInfo(fuzzReference("", `<ds:Transform Algorithm="`+xmlsec.TransformEnvelopedSignature+`"/>`+
		`<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>`, good)))
	for range 200 {
		nested.WriteString(`</e>`)
	}
	f.Add([]byte(nested.String()), []byte(nil))

	f.Fuzz(func(t *testing.T, doc, body []byte) {
		tree, err := xmlsec.Parse(doc)
		if err != nil {
			t.Skip()
		}
		sig := findSignature(tree.Root)
		if sig == nil {
			t.Skip()
		}
		atts, err := xmlsec.NewAttachmentSet(&xmlsec.Attachment{ID: "att-1@example.com", Body: body})
		if err != nil {
			t.Fatal(err)
		}
		verify := func(opts dsig.VerifyOptions) {
			cov, err := dsig.Verify(tree.Root, sig, opts)
			if err == nil && (cov == nil || len(cov.References) == 0) {
				t.Fatalf("verified with coverage %+v", cov)
			}
		}
		verify(dsig.VerifyOptions{})
		verify(dsig.VerifyOptions{Attachments: atts})
		verify(dsig.VerifyOptions{Certificate: key.Certificate, Attachments: atts})
		if resign(sig) {
			verify(dsig.VerifyOptions{Certificate: key.Certificate, Attachments: atts})
		}
	})
}
