//go:build interop

package interop

import (
	"crypto/x509"
	"encoding/base64"
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

// resolverFor is a VerifyOptions.ResolveSecurityToken that knows one
// certificate.
func resolverFor(cert *x509.Certificate) func(*xdm.Node) (*x509.Certificate, error) {
	return func(str *xdm.Node) (*x509.Certificate, error) {
		if !wss.MatchSecurityTokenReference(str, cert) {
			return nil, errors.New("unknown certificate")
		}
		return cert, nil
	}
}

// WSS4J processes a response built by this library that signs, besides the
// Body and a wsse11:SignatureConfirmation, a token through the STR
// Dereference Transform (SOAP Message Security 1.1.1 sections 8.3 and 8.5).
// With "bst" the reference is direct and ds:KeyInfo names the token; with
// "ski" no token travels: the transformed reference and ds:KeyInfo
// (SignOptions.KeyInfoElement) name the certificate by its
// SubjectKeyIdentifier, and WSS4J builds the token from its own trust store
// for the digest, as the section requires. With "keyinfo" the transformed
// reference is the signature's own ds:KeyInfo reference to the token, as
// WSS4J signs it. WSS4J enforces the Basic Security Profile throughout.
func TestWSS4JVerifiesOurSTRTransform(t *testing.T) {
	for _, keyRef := range []string{"bst", "ski", "keyinfo"} {
		t.Run(keyRef, func(t *testing.T) {
			kp := newKeypair(t, rsaKey(t))
			cert := kp.provider.Certificate
			doc := parse(t, []byte(envelope))
			body := xmltree.DocumentElement(doc).ChildElements()[1]
			bodyID, err := wss.AssignID(doc, body)
			if err != nil {
				t.Fatal(err)
			}
			hdr, err := wss.NewHeader(doc, xmlsec.NSSOAP12, "", true)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := hdr.AddTimestamp(time.Now(), 5*time.Minute); err != nil {
				t.Fatal(err)
			}
			confirmed := []byte("the request's signature value")
			scID, err := hdr.AddSignatureConfirmation(confirmed)
			if err != nil {
				t.Fatal(err)
			}
			opts := dsig.SignOptions{
				SignatureAlgorithm:        xmlsec.SigRSASHA256,
				CanonicalizationAlgorithm: string(c14n.Exclusive10),
				KeyInfo:                   dsig.KeyInfoSecurityTokenReference,
				ResolveSecurityToken:      resolverFor(cert),
			}
			var str *xdm.Node
			if keyRef == "ski" {
				if str, err = wss.NewKeyIdentifierReference(cert); err == nil {
					opts.KeyInfoElement, err = wss.NewKeyIdentifierReference(cert)
				}
			} else if opts.SecurityTokenID, err = hdr.AddBinarySecurityToken(cert, nil, xmlsec.BSTValueTypeX509v3); err == nil {
				str, err = wss.NewSecurityTokenReference(doc, opts.SecurityTokenID, "")
			}
			if err != nil {
				t.Fatal(err)
			}
			if keyRef == "keyinfo" {
				opts.KeyInfoElement = str
			} else if err := hdr.Append(str); err != nil {
				t.Fatal(err)
			}
			strID, err := wss.AssignID(doc, str)
			if err != nil {
				t.Fatal(err)
			}
			exc := []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}
			opts.References = []dsig.Reference{
				{URI: "#" + bodyID, Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
				{URI: "#" + scID, Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
				{URI: "#" + strID, Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformSTR}}, DigestAlgorithm: xmlsec.DigestSHA256},
			}
			sig, err := dsig.Sign(doc, kp.provider, opts)
			if err != nil {
				t.Fatal(err)
			}
			if err := hdr.Append(sig); err != nil {
				t.Fatal(err)
			}
			signed, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10})
			if err != nil {
				t.Fatal(err)
			}

			out, err := santuario(t, "wss4j-verify", tempFile(t, "soap.xml", signed), kp.certPEM)
			if err != nil {
				t.Fatalf("WSS4J refused the message: %v\n%s\n%s", err, out, signed)
			}
			// 2 is a signature, 128 a SignatureConfirmation.
			for _, want := range []string{"action 2\n", "action 128\n", "signed #" + bodyID + "\n", "signed #" + scID + "\n",
				"signed #" + strID + "\n", "confirmation " + base64.StdEncoding.EncodeToString(confirmed) + "\n"} {
				if !strings.Contains(string(out), want) {
					t.Errorf("WSS4J output lacks %q:\n%s", strings.TrimSpace(want), out)
				}
			}

			// The control: the token WSS4J digests is the certificate, so
			// another certificate in its place fails there too.
			if keyRef == "bst" {
				other := newKeypair(t, rsaKey(t)).provider.Certificate.Raw
				forged := strings.Replace(string(signed), base64.StdEncoding.EncodeToString(cert.Raw)+"</wsse:BinarySecurityToken>",
					base64.StdEncoding.EncodeToString(other)+"</wsse:BinarySecurityToken>", 1)
				if out, err := santuario(t, "wss4j-verify", tempFile(t, "forged.xml", []byte(forged)), kp.certPEM); err == nil {
					t.Fatalf("WSS4J accepted a replaced token:\n%s", out)
				}
			}
		})
	}
}

// WSS4J signs its ds:KeyInfo reference through the STR Dereference
// Transform ("STRTransform"), naming the key by a direct reference, a
// SubjectKeyIdentifier or an issuer serial, and this library verifies it
// under StrictBSP, reporting the token in SignedTokens: the one in the
// message, or the one section 8.3 builds from the certificate
// ResolveSecurityToken returns, byte for byte as WSS4J digested it.
func TestWeVerifyWSS4JSTRTransform(t *testing.T) {
	for _, keyRef := range []string{"bst", "ski", "issuer-serial"} {
		t.Run(keyRef, func(t *testing.T) {
			kp := newKeypair(t, rsaKey(t))
			out := tempFile(t, "out.xml", nil)
			mustSantuario(t, "wss4j-sign-str", tempFile(t, "soap.xml", []byte(envelope)), kp.keyPEM, kp.certPEM, keyRef, out)
			signed := readFile(t, out)
			if !strings.Contains(string(signed), xmlsec.TransformSTR) {
				t.Fatalf("no STR Dereference Transform:\n%s", signed)
			}
			doc := parse(t, signed)
			cov, err := dsig.Verify(doc, find(doc, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{
				Certificate:          kp.provider.Certificate,
				ResolveSecurityToken: resolverFor(kp.provider.Certificate),
				StrictBSP:            true,
			})
			if err != nil {
				t.Fatalf("%v\n%s", err, signed)
			}
			if len(cov.SignedTokens) != 1 || (keyRef == "bst") != (cov.SignedTokens[0].Parent != nil) {
				t.Fatalf("coverage %+v", cov)
			}
			// Without the resolver, a token that is not in the message
			// cannot be dereferenced.
			if keyRef != "bst" {
				_, err := dsig.Verify(doc, find(doc, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{Certificate: kp.provider.Certificate})
				if !errors.Is(err, xmlsec.ErrSecurityTokenUnavailable) {
					t.Fatalf("no resolver: %v", err)
				}
			}
		})
	}
}

// WSS4J writes the wsse11:SignatureConfirmation a responder adds, with and
// without a Value, and this library checks it against the request's
// signature values (section 8.5.2).
func TestWeCheckWSS4JSignatureConfirmation(t *testing.T) {
	sent := []byte("the request's signature value")
	for name, c := range map[string]struct {
		value string
		sent  [][]byte
	}{
		"signed request":   {base64.StdEncoding.EncodeToString(sent), [][]byte{sent}},
		"unsigned request": {"-", nil},
	} {
		t.Run(name, func(t *testing.T) {
			out := tempFile(t, "out.xml", nil)
			mustSantuario(t, "wss4j-confirm", tempFile(t, "soap.xml", []byte(envelope)), c.value, out)
			doc := parse(t, readFile(t, out))
			sec, err := wss.FindHeader(doc, xmlsec.NSSOAP12, "")
			if err != nil || sec == nil {
				t.Fatalf("FindHeader: %v", err)
			}
			if err := wss.CheckSignatureConfirmations(sec, c.sent); err != nil {
				t.Fatalf("%v\n%s", err, readFile(t, out))
			}
			if err := wss.CheckSignatureConfirmations(sec, [][]byte{[]byte("another request")}); !errors.Is(err, xmlsec.ErrSignatureInvalid) {
				t.Fatalf("another request: %v", err)
			}
		})
	}
}
