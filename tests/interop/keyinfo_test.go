//go:build interop

package interop

import (
	"bytes"
	"crypto/ecdsa"
	"path/filepath"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

// The ds:KeyInfo forms of XML Encryption 1.1 sections 3.5 and 5.6 beyond
// an EncryptedKey in the EncryptedData: an xenc11:DerivedKey from a master
// key (ConcatKDF) or a password (PBKDF2), an xenc:AgreementMethod directly
// under the EncryptedData, and a chain of EncryptedKeys, against xmlsec1
// 1.3, both directions. Santuario 4.0.4 has none of the three: its
// DerivedKey support is only a key agreement's KDF, and it finds an
// EncryptedKey only as a KeyInfo child of the EncryptedData.

// ourPayload encrypts envelope's payload with no session key, under the
// key opts' KeyInfo conveys.
func ourPayload(t *testing.T, opts xenc.EncryptOptions) []byte {
	t.Helper()
	doc := parse(t, []byte(envelope))
	out, err := xenc.EncryptElement(doc, find(doc, "urn:example:p", "Payload"), nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// xmlsec1Encrypt encrypts envelope's payload with xmlsec1 by tmpl, an
// EncryptedData template, with the extra arguments given.
func xmlsec1Encrypt(t *testing.T, tmpl string, args ...string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out.xml")
	args = append([]string{"--encrypt"}, args...)
	run(t, append(args, "--xml-data", tempFile(t, "data.xml", []byte(envelope)),
		"--node-name", "urn:example:p:Payload", "--output", out, tempFile(t, "tmpl.xml", []byte(tmpl)))...)
	return readFile(t, out)
}

// decryptDirect decrypts the EncryptedData of b under the key keyOf
// returns for it.
func decryptDirect(t *testing.T, b []byte, keyOf func(ed *xdm.Node) ([]byte, error)) {
	t.Helper()
	ed := find(parse(t, b), xmlsec.NSXEnc, "EncryptedData")
	key, err := keyOf(ed)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	plain, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{})
	if err != nil || !bytes.Contains(plain, []byte(">hello</p:Payload>")) {
		t.Fatalf("%q, %v", plain, err)
	}
}

func dataTemplate(keyInfo string) string {
	return `<xenc:EncryptedData xmlns:xenc="` + xmlsec.NSXEnc + `" Type="` + xenc.TypeElement + `">` +
		`<xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128GCM + `"/>` +
		`<ds:KeyInfo xmlns:ds="` + xmlsec.NSDSig + `" xmlns:xenc11="` + xmlsec.NSXEnc11 + `">` + keyInfo + `</ds:KeyInfo>` +
		`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>`
}

// A data key derived by ConcatKDF from a shared master key, which xmlsec1
// finds by the DerivedKey's MasterKeyName (section 3.5.2).
func TestDerivedKeyConcatKDFBothWays(t *testing.T) {
	master, masterPath := kekFile(t, 32)
	t.Run("xmlsec1 decrypts ours", func(t *testing.T) {
		enc := ourPayload(t, xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, DigestAlgorithm: xmlsec.DigestSHA256,
			MasterKey: master, MasterKeyName: "master"})
		out := filepath.Join(t.TempDir(), "xmlsec1.xml")
		run(t, "--decrypt", "--concatkdf-key:master", masterPath, "--output", out, tempFile(t, "enc.xml", enc))
		assertDecryptedEnvelope(t, readFile(t, out))
	})
	t.Run("we decrypt xmlsec1's", func(t *testing.T) {
		enc := xmlsec1Encrypt(t, dataTemplate(`<xenc11:DerivedKey><xenc11:KeyDerivationMethod Algorithm="`+xmlsec.KeyDerivationConcatKDF+`">`+
			`<xenc11:ConcatKDFParams AlgorithmID="0001" PartyUInfo="00D8" PartyVInfo=""><ds:DigestMethod Algorithm="`+xmlsec.DigestSHA256+`"/></xenc11:ConcatKDFParams>`+
			`</xenc11:KeyDerivationMethod><xenc11:MasterKeyName>master</xenc11:MasterKeyName></xenc11:DerivedKey>`),
			"--concatkdf-key:master", masterPath)
		decryptDirect(t, enc, func(ed *xdm.Node) ([]byte, error) {
			dk, err := xenc.FindDerivedKey(ed)
			if err != nil {
				return nil, err
			}
			return xenc.DeriveKey(dk, ed, master, xenc.DecryptOptions{})
		})
	})
}

// A data key derived by PBKDF2 from a password, directly under the
// EncryptedData.
func TestDerivedKeyPBKDF2BothWays(t *testing.T) {
	password := []byte("correct horse battery staple")
	pwPath := tempFile(t, "pw.bin", password)
	allow := xenc.DecryptOptions{AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2}}
	t.Run("xmlsec1 decrypts ours", func(t *testing.T) {
		enc := ourPayload(t, xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, Password: password, PBKDF2Iterations: 2000})
		out := filepath.Join(t.TempDir(), "xmlsec1.xml")
		run(t, "--decrypt", "--pbkdf2-key", pwPath, "--output", out, tempFile(t, "enc.xml", enc))
		assertDecryptedEnvelope(t, readFile(t, out))
	})
	t.Run("we decrypt xmlsec1's", func(t *testing.T) {
		enc := xmlsec1Encrypt(t, dataTemplate(`<xenc11:DerivedKey><xenc11:KeyDerivationMethod Algorithm="`+xmlsec.KeyDerivationPBKDF2+`"><xenc11:PBKDF2-params>`+
			`<xenc11:Salt><xenc11:Specified>AAECAwQFBgcICQoLDA0ODw==</xenc11:Specified></xenc11:Salt>`+
			`<xenc11:IterationCount>2000</xenc11:IterationCount><xenc11:KeyLength>16</xenc11:KeyLength>`+
			`<xenc11:PRF Algorithm="`+xmlsec.SigHMACSHA256+`"/></xenc11:PBKDF2-params></xenc11:KeyDerivationMethod>`+
			`<xenc11:MasterKeyName>pw</xenc11:MasterKeyName></xenc11:DerivedKey>`),
			"--pbkdf2-key:pw", pwPath)
		decryptDirect(t, enc, func(ed *xdm.Node) ([]byte, error) {
			dk, err := xenc.FindDerivedKey(ed)
			if err != nil {
				return nil, err
			}
			return xenc.DeriveKey(dk, ed, password, allow)
		})
	})
}

// ECDH-ES agreeing the data key itself: the AgreementMethod directly in
// the EncryptedData's KeyInfo (section 5.6).
func TestDirectKeyAgreementBothWays(t *testing.T) {
	recipient := newKeypair(t, ecKey(t))
	priv, err := recipient.provider.Signer.(*ecdsa.PrivateKey).ECDH()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("xmlsec1 decrypts ours", func(t *testing.T) {
		enc := ourPayload(t, xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyAgreementAlgorithm: xmlsec.KeyAgreementECDHES,
			DigestAlgorithm: xmlsec.DigestSHA256, Recipient: recipient.provider.Certificate, DirectKeyAgreement: true})
		out := filepath.Join(t.TempDir(), "xmlsec1.xml")
		run(t, "--decrypt", "--enabled-key-data", xmlsec1AgreementKeyData,
			"--privkey-pem", recipient.keyPEM+","+recipient.certPEM, "--output", out, tempFile(t, "enc.xml", enc))
		assertDecryptedEnvelope(t, readFile(t, out))
	})
	t.Run("we decrypt xmlsec1's", func(t *testing.T) {
		originator := newKeypair(t, ecKey(t))
		enc := xmlsec1Encrypt(t, dataTemplate(`<xenc:AgreementMethod Algorithm="`+xmlsec.KeyAgreementECDHES+`">`+
			`<xenc11:KeyDerivationMethod Algorithm="`+xmlsec.KeyDerivationConcatKDF+`">`+
			`<xenc11:ConcatKDFParams AlgorithmID="0001" PartyUInfo="" PartyVInfo=""><ds:DigestMethod Algorithm="`+xmlsec.DigestSHA256+`"/></xenc11:ConcatKDFParams>`+
			`</xenc11:KeyDerivationMethod>`+
			`<xenc:OriginatorKeyInfo><ds:KeyName>originator</ds:KeyName><ds:KeyValue/></xenc:OriginatorKeyInfo>`+
			`<xenc:RecipientKeyInfo><ds:KeyName>recipient</ds:KeyName></xenc:RecipientKeyInfo></xenc:AgreementMethod>`),
			"--enabled-key-data", xmlsec1AgreementKeyData,
			"--privkey-pem:originator", originator.keyPEM, "--pubkey-cert-pem:recipient", recipient.certPEM)
		decryptDirect(t, enc, func(ed *xdm.Node) ([]byte, error) {
			return xenc.DecryptAgreedDataKey(ed, priv, xenc.DecryptOptions{})
		})
	})
}

// chainUnwrap follows the EncryptedKey chain of ed two hops with
// FindEncryptedKey and unwraps it, the second key under shared.
func chainUnwrap(shared []byte) func(ed *xdm.Node) ([]byte, error) {
	return func(ed *xdm.Node) ([]byte, error) {
		ek1, err := xenc.FindEncryptedKey(ed)
		if err != nil {
			return nil, err
		}
		ek2, err := xenc.FindEncryptedKey(ek1)
		if err != nil {
			return nil, err
		}
		kek, err := xenc.UnwrapEncryptedKey(ek2, shared, xenc.DecryptOptions{})
		if err != nil {
			return nil, err
		}
		return xenc.UnwrapEncryptedKey(ek1, kek, xenc.DecryptOptions{})
	}
}

// A chain of EncryptedKeys (sections 3.5.1 and 3.6): the EncryptedData
// names the data key's EncryptedKey by ds:RetrievalMethod, and that key's
// KEK is carried by an EncryptedKey in its own KeyInfo, wrapped under a key
// xmlsec1 finds by name. xmlsec1 re-parses what a RetrievalMethod
// retrieves as a document of its own, so a second RetrievalMethod inside it
// cannot resolve; the second hop is therefore inline. xmlsec1 writes the
// same nesting, wrapping a middle key from its keys manager, which it
// selects by size. Our KeyReference form is checked by the unit tests.
func TestEncryptedKeyChainWithXmlsec1(t *testing.T) {
	shared, sharedPath := kekFile(t, 16)
	t.Run("xmlsec1 decrypts ours", func(t *testing.T) {
		kekEK, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES256GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES128, KeyEncryptionKey: shared})
		if err != nil {
			t.Fatal(err)
		}
		dataEK, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES256, KeyEncryptionKey: kekEK.SessionKey})
		if err != nil {
			t.Fatal(err)
		}
		name := xmltree.Element(nil, "ds", xmlsec.NSDSig, "KeyName")
		name.AddNamespace("ds", xmlsec.NSDSig)
		xmltree.Text(name, "kek")
		if err := kekEK.SetKeyInfo(name); err != nil {
			t.Fatal(err)
		}
		if err := dataEK.SetKeyInfo(kekEK.Element); err != nil {
			t.Fatal(err)
		}
		xmltree.SetAttr(dataEK.Element, "", "", "Id", "dk")

		doc := parse(t, []byte(envelope))
		find(doc, "http://www.w3.org/2003/05/soap-envelope", "Header").AppendChild(dataEK.Element)
		out, err := xenc.EncryptElement(doc, find(doc, "urn:example:p", "Payload"), dataEK.SessionKey, xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM})
		if err != nil {
			t.Fatal(err)
		}
		// The EncryptedData's KeyInfo names the data key's EncryptedKey.
		edoc := parse(t, out)
		ed := find(edoc, xmlsec.NSXEnc, "EncryptedData")
		ki := xmltree.Element(nil, "ds", xmlsec.NSDSig, "KeyInfo")
		ki.AddNamespace("ds", xmlsec.NSDSig)
		rm := xmltree.Element(ki, "ds", xmlsec.NSDSig, "RetrievalMethod")
		xmltree.SetAttr(rm, "", "", "Type", xenc.TypeEncryptedKey)
		xmltree.SetAttr(rm, "", "", "URI", "#dk")
		ed.AppendChild(ki)
		ed.Children = []*xdm.Node{ed.Children[0], ki, ed.Children[1]}
		chain := mustC14N(t, edoc)

		o := filepath.Join(t.TempDir(), "xmlsec1.xml")
		run(t, "--decrypt", "--enabled-retrieval-method-uris", "same-doc", "--enabled-key-data", "retrieval-method,enc-key,key-name,aes",
			"--aeskey:kek", sharedPath, "--id-attr:Id", xmlsec.NSXEnc+":EncryptedKey", "--output", o, tempFile(t, "enc.xml", chain))
		if b := readFile(t, o); !bytes.Contains(b, []byte(">hello</p:Payload>")) {
			t.Fatalf("xmlsec1 plaintext %s", b)
		}
		decryptDirect(t, chain, chainUnwrap(shared))
	})
	t.Run("we decrypt xmlsec1's", func(t *testing.T) {
		_, midPath := kekFile(t, 32)
		enc := xmlsec1Encrypt(t, dataTemplate(`<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="`+xmlsec.KeyWrapAES256+`"/>`+
			`<ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="`+xmlsec.KeyWrapAES128+`"/>`+
			`<ds:KeyInfo><ds:KeyName>kek</ds:KeyName></ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>`+
			`<xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey>`),
			"--session-key", "aes-128", "--aeskey:kek", sharedPath, "--aeskey:mid", midPath)
		decryptDirect(t, enc, chainUnwrap(shared))
	})
}

func mustC14N(t *testing.T, n *xdm.Node) []byte {
	t.Helper()
	b, err := c14n.Bytes(n, c14n.Options{Algorithm: c14n.Inclusive10})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
