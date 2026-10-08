package security

import (
	"crypto"
	"crypto/x509"
	"errors"
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

const soapEnvelope = `<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope">` +
	`<S:Header></S:Header><S:Body><p:Payload xmlns:p="urn:p">pay 100</p:Payload></S:Body></S:Envelope>`

// signedWSS signs soapEnvelope's Body and, through the STR Dereference
// Transform, the token of a direct reference, as a WS-Security sender
// does. The header also holds decoys an attacker may point that reference
// at: a second reference, a wsse:Embedded and a ds:KeyInfo, each with an
// ID. It returns the message, the token's ID and the decoys' IDs.
func signedWSS(t *testing.T, kp xmlsec.KeyProvider) (msg, tokID string, decoys []string) {
	t.Helper()
	tree, err := xmlsec.Parse([]byte(soapEnvelope))
	if err != nil {
		t.Fatal(err)
	}
	doc := tree.Root
	body := xmltree.DocumentElement(doc).ChildElements()[1]
	bodyID, err := wss.AssignID(doc, body)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := wss.NewHeader(doc, xmlsec.NSSOAP12, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if tokID, err = hdr.AddBinarySecurityToken(kp.Certificate, nil, xmlsec.BSTValueTypeX509v3); err != nil {
		t.Fatal(err)
	}
	str, err := wss.NewSecurityTokenReference(doc, tokID, "")
	if err != nil {
		t.Fatal(err)
	}
	decoy, _ := wss.NewSecurityTokenReference(doc, tokID, "")
	emb := xmltree.Element(nil, "wsse", xmlsec.NSWSSE, "SecurityTokenReference")
	emb.AddNamespace("wsse", xmlsec.NSWSSE)
	xmltree.Element(xmltree.Element(emb, "wsse", xmlsec.NSWSSE, "Embedded"), "t", "urn:t", "Token").AddNamespace("t", "urn:t")
	ki := xmltree.Element(nil, "ds", xmlsec.NSDSig, "KeyInfo")
	ki.AddNamespace("ds", xmlsec.NSDSig)
	ki.AddNamespace("wsu", xmlsec.NSWSU)
	xmltree.SetAttr(ki, "wsu", xmlsec.NSWSU, "Id", "ki-1")
	for _, el := range []*xdm.Node{str, decoy, emb, ki} {
		if err := hdr.Append(el); err != nil {
			t.Fatal(err)
		}
	}
	strID, _ := wss.AssignID(doc, str)
	for _, el := range []*xdm.Node{decoy, emb.ChildElements()[0]} {
		id, err := wss.AssignID(doc, el)
		if err != nil {
			t.Fatal(err)
		}
		decoys = append(decoys, id)
	}
	// AssignID would give ds:KeyInfo the unqualified Id its schema defines.
	decoys = append(decoys, "ki-1")
	exc := []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}
	sig, err := dsig.Sign(doc, kp, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{
			{URI: "#" + bodyID, Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "#" + strID, Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformSTR}}, DigestAlgorithm: xmlsec.DigestSHA256},
		},
		KeyInfo:         dsig.KeyInfoSecurityTokenReference,
		SecurityTokenID: tokID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := hdr.Prepend(sig); err != nil {
		t.Fatal(err)
	}
	b, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10})
	if err != nil {
		t.Fatal(err)
	}
	return string(b), tokID, decoys
}

func verifyWSS(t *testing.T, msg string, opts dsig.VerifyOptions) (*dsig.Coverage, error) {
	t.Helper()
	tree, err := xmlsec.Parse([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	var sig *xdm.Node
	xmltree.Walk(tree.Root, func(e *xdm.Node) {
		if sig == nil && e.IsElement(xmlsec.NSDSig, "Signature") {
			sig = e
		}
	})
	return dsig.Verify(tree.Root, sig, opts)
}

// The STR Dereference Transform covers the token, not the reference, so the
// reference itself is not signed. An attacker who retargets it at another
// reference, at a wsse:Embedded or at a ds:KeyInfo (Basic Security Profile
// R3057, R3064, R3211) gets a refusal, never a digest over whatever element
// the reference now names.
func TestSTRTransformRetargetRefused(t *testing.T) {
	kp := keyPair(t, rsaKey(t))
	msg, tokID, decoys := signedWSS(t, kp)
	if cov, err := verifyWSS(t, msg, dsig.VerifyOptions{Certificate: kp.Certificate}); err != nil || len(cov.SignedTokens) != 1 {
		t.Fatalf("authentic message: %v", err)
	}
	for i, rule := range []string{"R3057 reference", "R3064 Embedded", "R3211 KeyInfo"} {
		// The first reference to the token is the signed one's, after the
		// signature's own ds:KeyInfo reference.
		n := strings.Index(msg, `<wsse:Reference URI="#`+tokID+`"`)
		n += strings.Index(msg[n+1:], `<wsse:Reference URI="#`+tokID+`"`) + 1
		attacked := msg[:n] + strings.Replace(msg[n:], `URI="#`+tokID+`"`, `URI="#`+decoys[i]+`"`, 1)
		if _, err := verifyWSS(t, attacked, dsig.VerifyOptions{Certificate: kp.Certificate}); !errors.Is(err, xmlsec.ErrMalformed) {
			t.Errorf("%s: %v", rule, err)
		}
	}
}

// A second element with a signed element's ID is signature wrapping's
// first step. CheckUniqueIDs refuses the whole message before anything is
// resolved (BSP R3204), across wsu:Id and xml:id.
func TestDuplicateIDsRefused(t *testing.T) {
	kp := keyPair(t, rsaKey(t))
	msg, _, _ := signedWSS(t, kp)
	bodyID := msg[strings.Index(msg, `<S:Body `):]
	bodyID = bodyID[strings.Index(bodyID, `wsu:Id="`)+8:]
	bodyID = bodyID[:strings.IndexByte(bodyID, '"')]
	for name, planted := range map[string]string{
		"wsu:Id": `<w xmlns:wsu="` + xmlsec.NSWSU + `" wsu:Id="` + bodyID + `"></w>`,
		"xml:id": `<w xml:id="` + bodyID + `"></w>`,
	} {
		attacked := strings.Replace(msg, `</S:Header>`, planted+`</S:Header>`, 1)
		tree, err := xmlsec.Parse([]byte(attacked))
		if err != nil {
			t.Fatal(err)
		}
		if err := wss.CheckUniqueIDs(tree.Root); !errors.Is(err, xmlsec.ErrAmbiguousID) {
			t.Errorf("%s: CheckUniqueIDs %v", name, err)
		}
		if _, err := verifyWSS(t, attacked, dsig.VerifyOptions{Certificate: kp.Certificate}); !errors.Is(err, xmlsec.ErrAmbiguousID) {
			t.Errorf("%s: Verify %v", name, err)
		}
	}
}

// A response confirming a signature other than the request's, such as one
// replayed from an earlier exchange, is refused (SOAP Message Security
// 1.1.1 section 8.5.2), and so is one that drops a confirmation.
func TestSignatureConfirmationMismatch(t *testing.T) {
	kp := keyPair(t, rsaKey(t))
	values := func(msg string) [][]byte {
		tree, err := xmlsec.Parse([]byte(msg))
		if err != nil {
			t.Fatal(err)
		}
		sec, err := wss.FindHeader(tree.Root, xmlsec.NSSOAP12, "")
		if err != nil {
			t.Fatal(err)
		}
		v, err := wss.SignatureValues(sec)
		if err != nil || len(v) != 1 {
			t.Fatalf("SignatureValues: %v, %v", v, err)
		}
		return v
	}
	request, _, _ := signedWSS(t, kp)
	earlier, _, _ := signedWSS(t, kp)
	sent, replayed := values(request), values(earlier)

	respond := func(confirm ...[]byte) *xdm.Node {
		tree, err := xmlsec.Parse([]byte(soapEnvelope))
		if err != nil {
			t.Fatal(err)
		}
		hdr, err := wss.NewHeader(tree.Root, xmlsec.NSSOAP12, "", true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := hdr.AddTimestamp(time.Now(), time.Minute); err != nil {
			t.Fatal(err)
		}
		for _, v := range confirm {
			if _, err := hdr.AddSignatureConfirmation(v); err != nil {
				t.Fatal(err)
			}
		}
		return hdr.Element()
	}
	if err := wss.CheckSignatureConfirmations(respond(sent[0]), sent); err != nil {
		t.Fatalf("authentic response: %v", err)
	}
	for name, sec := range map[string]*xdm.Node{
		"replayed confirmation":   respond(replayed[0]),
		"no confirmation":         respond(),
		"unsigned-request answer": respond(nil),
	} {
		if err := wss.CheckSignatureConfirmations(sec, sent); !errors.Is(err, xmlsec.ErrSignatureInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// VerifyOptions.StrictBSP refuses a signature the Basic Security Profile
// forbids before any cryptographic work, with xmlsec.ErrMalformed: TrustKey, which runs just before
// the signature value is checked, is never called, although the
// signature's own key is not even pinned.
func TestStrictBSPRefusesBeforeCrypto(t *testing.T) {
	kp := keyPair(t, rsaKey(t))
	msg, _, _ := signedWSS(t, kp)
	// The XSLT stylesheet is allowed, so only StrictBSP can refuse it.
	const sheet = `<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"></xsl:stylesheet>`
	xslt, err := xmlsec.Parse([]byte(sheet))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	opts := dsig.VerifyOptions{StrictBSP: true, AllowedXSLTStylesheets: []*xdm.Node{xmltree.DocumentElement(xslt.Root)},
		TrustKey: func(*x509.Certificate, crypto.PublicKey) error {
			called = true
			return nil
		}}
	if _, err := verifyWSS(t, msg, opts); err != nil || !called {
		t.Fatalf("conforming message: %v", err)
	}
	exc := `Algorithm="` + string(c14n.Exclusive10) + `"`
	for name, attacked := range map[string]string{
		"inclusive SignedInfo (R5404)": strings.Replace(msg, exc, `Algorithm="`+string(c14n.Inclusive10)+`"`, 1),
		"enveloping (R3102)": strings.Replace(strings.Replace(msg, `</ds:KeyInfo>`,
			`</ds:KeyInfo><ds:Object><o xmlns:wsu="`+xmlsec.NSWSU+`" wsu:Id="o"></o></ds:Object>`, 1), `<ds:Reference URI="#`, `<ds:Reference URI="#o" x="#`, 1),
		"Manifest (R5403)": strings.Replace(msg, `</ds:KeyInfo>`, `</ds:KeyInfo><ds:Object><ds:Manifest></ds:Manifest></ds:Object>`, 1),
		"XSLT (R5423)":     strings.Replace(msg, `<ds:Transform `+exc, `<ds:Transform Algorithm="`+xmlsec.TransformXSLT+`">`+sheet+`</ds:Transform><ds:Transform `+exc, 1),
	} {
		called = false
		if _, err := verifyWSS(t, attacked, opts); !errors.Is(err, xmlsec.ErrMalformed) || called {
			t.Errorf("%s: %v, TrustKey called %v", name, err, called)
		}
	}
}
