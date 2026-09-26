//go:build interop

package interop

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
	"github.com/knroy/go-xmlsec/xenc"
)

// santuario runs the Apache Santuario harness (tests/santuario/Harness.java,
// installed as `santuario` in the interop image).
func santuario(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	p := tool(t, "santuario")
	var out bytes.Buffer
	cmd := exec.Command(p, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.Bytes(), err
}

func mustSantuario(t *testing.T, args ...string) {
	t.Helper()
	if out, err := santuario(t, args...); err != nil {
		t.Fatalf("santuario %v: %v\n%s", args, err, out)
	}
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func signOurEnveloped(t *testing.T, kp keypair, sigAlg string, alg c14n.Algorithm) []byte {
	t.Helper()
	signed, err := dsig.SignEnveloped(parse(t, []byte(metadata)), kp.provider, dsig.SignOptions{
		SignatureAlgorithm:        sigAlg,
		CanonicalizationAlgorithm: string(alg),
		References: []dsig.Reference{{
			URI:             "",
			DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms: []dsig.TransformSpec{
				{Algorithm: xmlsec.TransformEnvelopedSignature},
				{Algorithm: string(alg)},
			},
		}},
		KeyInfo: dsig.KeyInfoX509Data,
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// signatureValue returns the decoded ds:SignatureValue and every
// ds:DigestValue of the first signature in doc.
func signatureValue(t *testing.T, doc []byte) (sig []byte, digests [][]byte) {
	t.Helper()
	root := parse(t, doc)
	xmltree.Walk(root, func(e *xdm.Node) {
		if e.Name.URI != dsig.NSDSig {
			return
		}
		switch e.Name.Local {
		case "SignatureValue":
			if sig == nil {
				sig = mustBase64(t, e)
			}
		case "DigestValue":
			digests = append(digests, mustBase64(t, e))
		}
	})
	return sig, digests
}

func mustBase64(t *testing.T, e *xdm.Node) []byte {
	t.Helper()
	b, err := xmltree.Base64(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Santuario accepts our enveloped signatures.
func TestSantuarioVerifiesOurEnvelopedSignature(t *testing.T) {
	for _, c := range sigCases {
		t.Run(c.name, func(t *testing.T) {
			kp := newKeypair(t, c.key(t))
			signed := signOurEnveloped(t, kp, c.sigAlg, c.c14n)
			mustSantuario(t, "verify", tempFile(t, "signed.xml", signed), kp.certPEM)

			tampered := bytes.Replace(signed, []byte("example.com"), []byte("evil.com"), 1)
			if out, err := santuario(t, "verify", tempFile(t, "tampered.xml", tampered), kp.certPEM); err == nil {
				t.Fatalf("Santuario accepted a tampered document:\n%s", out)
			}
		})
	}
}

// We accept Santuario's enveloped signatures.
func TestWeVerifySantuarioEnvelopedSignature(t *testing.T) {
	for _, c := range sigCases {
		t.Run(c.name, func(t *testing.T) {
			kp := newKeypair(t, c.key(t))
			out := filepath.Join(t.TempDir(), "out.xml")
			mustSantuario(t, "sign-enveloped", tempFile(t, "in.xml", []byte(metadata)),
				kp.keyPEM, kp.certPEM, string(c.c14n), c.sigAlg, out)
			signed := readFile(t, out)
			doc := parse(t, signed)
			cov, err := dsig.Verify(doc, find(doc, dsig.NSDSig, "Signature"), dsig.VerifyOptions{
				Certificate:                       kp.provider.Certificate,
				AllowedSignatureAlgorithms:        []string{c.sigAlg},
				AllowedCanonicalizationAlgorithms: []string{string(c.c14n)},
			})
			if err != nil {
				t.Fatalf("%v\n%s", err, signed)
			}
			if !cov.WholeDocumentSigned {
				t.Fatal("whole document not reported as signed")
			}
		})
	}
}

// RSA PKCS#1 v1.5 is deterministic, so the same document signed with the
// same key by us and by Santuario must carry byte-identical digests and
// SignatureValue. A difference is a canonicalization or serialization
// divergence that "it verifies" alone could hide.
func TestSignatureValueMatchesSantuarioEnveloped(t *testing.T) {
	for _, alg := range []c14n.Algorithm{c14n.Inclusive10, c14n.Exclusive10} {
		t.Run(string(alg), func(t *testing.T) {
			kp := newKeypair(t, rsaKey(t))
			ours := signOurEnveloped(t, kp, xmlsec.SigRSASHA256, alg)

			out := filepath.Join(t.TempDir(), "out.xml")
			mustSantuario(t, "sign-enveloped", tempFile(t, "in.xml", []byte(metadata)),
				kp.keyPEM, kp.certPEM, string(alg), xmlsec.SigRSASHA256, out)
			theirs := readFile(t, out)

			compareSignatures(t, ours, theirs)
		})
	}
}

func compareSignatures(t *testing.T, ours, theirs []byte) {
	t.Helper()
	ourSig, ourDigests := signatureValue(t, ours)
	theirSig, theirDigests := signatureValue(t, theirs)
	// Guard against a vacuous match: nil equals nil.
	if len(ourSig) < 256 || len(theirSig) < 256 || len(ourDigests) == 0 {
		t.Fatalf("missing signature values: ours %d bytes, Santuario %d, %d digests", len(ourSig), len(theirSig), len(ourDigests))
	}
	if len(ourDigests) != len(theirDigests) {
		t.Fatalf("%d digests, Santuario %d", len(ourDigests), len(theirDigests))
	}
	for i := range ourDigests {
		if !bytes.Equal(ourDigests[i], theirDigests[i]) {
			t.Fatalf("reference %d digest differs\nours:\n%s\nSantuario:\n%s", i, ours, theirs)
		}
	}
	if !bytes.Equal(ourSig, theirSig) {
		t.Fatalf("SignatureValue differs with identical digests: ds:SignedInfo canonicalizes differently\nours:\n%s\nSantuario:\n%s", ours, theirs)
	}
}

// soapWithHeader is an envelope with IDs already assigned and an empty
// wsse:Security header, so both implementations sign the same input.
const soapWithHeader = `<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="urn:example:eb" ` +
	`xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">` +
	`<S:Header><eb:Messaging wsu:Id="msg"><eb:MessageId>m1</eb:MessageId></eb:Messaging>` +
	`<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"></wsse:Security></S:Header>` +
	`<S:Body wsu:Id="body"><p:Payload xmlns:p="urn:example:p">hello</p:Payload></S:Body></S:Envelope>`

// The WS-Security detached case: the same byte-equality, plus each side
// verifying the other.
func TestSignatureValueMatchesSantuarioDetached(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))

	doc := parse(t, []byte(soapWithHeader))
	exc := []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}
	sig, err := dsig.Sign(doc, kp.provider, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{
			{URI: "#msg", Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "#body", Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
		},
		KeyInfo: dsig.KeyInfoNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	find(doc, wss.NSWSSE, "Security").AppendChild(sig)
	ours, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10})
	if err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "out.xml")
	mustSantuario(t, "sign-detached", tempFile(t, "in.xml", []byte(soapWithHeader)),
		kp.keyPEM, xmlsec.SigRSASHA256, out, "msg", "body")
	theirs := readFile(t, out)

	compareSignatures(t, ours, theirs)

	mustSantuario(t, "verify", tempFile(t, "ours.xml", ours), kp.certPEM)
	td := parse(t, theirs)
	cov, err := dsig.Verify(td, find(td, dsig.NSDSig, "Signature"), dsig.VerifyOptions{Certificate: kp.provider.Certificate})
	if err != nil {
		t.Fatalf("%v\n%s", err, theirs)
	}
	if !cov.Covers("msg", "body") {
		t.Fatalf("coverage %v", cov.SignedElementIDs)
	}
}

// Santuario decrypts our element encryption.
func TestSantuarioDecryptsOurEncryption(t *testing.T) {
	key := rsaKey(t)
	kp := newKeypair(t, key)
	withKey := encryptWithKeyInfo(t, kp)
	out := filepath.Join(t.TempDir(), "out.xml")
	mustSantuario(t, "decrypt", tempFile(t, "enc.xml", withKey), kp.keyPEM, out)
	assertDecryptedEnvelope(t, readFile(t, out))
}

// We decrypt Santuario's element encryption.
func TestWeDecryptSantuarioEncryption(t *testing.T) {
	key := rsaKey(t)
	kp := newKeypair(t, key)
	out := filepath.Join(t.TempDir(), "out.xml")
	mustSantuario(t, "encrypt", tempFile(t, "in.xml", []byte(envelope)), kp.certPEM, "Payload", out)
	encrypted := readFile(t, out)

	doc := parse(t, encrypted)
	sessionKey, err := xenc.DecryptEncryptedKey(find(doc, xenc.NSXEnc, "EncryptedKey"), key,
		[]string{xmlsec.KeyTransportRSAOAEP}, []string{xmlsec.MGF1SHA256}, []string{xmlsec.DigestSHA256})
	if err != nil {
		t.Fatalf("%v\n%s", err, encrypted)
	}
	plain, err := xenc.DecryptData(find(doc, xenc.NSXEnc, "EncryptedData"), sessionKey, []string{xmlsec.EncAES128GCM})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plain, []byte(">hello</p:Payload>")) {
		t.Fatalf("plaintext %s", plain)
	}
}
