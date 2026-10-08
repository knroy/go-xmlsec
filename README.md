# go-xmlsec

XML Signature, XML Encryption and WS-Security for Go. Pure Go, no cgo, no
libxml2.

Parsing and canonicalization come from [go-xml](https://github.com/knroy/go-xml);
this library never serializes XML for a digest any other way. That matters,
because a signature is only as correct as the canonical octets it covers.

> **Status: v1.** The API is stable: no breaking change within v1. Output is
> verified in both directions against two independent implementations,
> `xmlsec1` and Apache Santuario, on every commit, and signatures are
> byte-identical to Santuario's. See [what is tested](#how-it-is-tested).

## Features

- **XML Signature**: enveloped signatures over a whole document, detached
  signatures over elements by ID and over MIME attachments by `cid:`, and
  enveloping signatures over `ds:Object`; `ds:Manifest` and
  `ds:SignatureProperties`; HMAC-SHA2 with a shared secret.
- **Signature coverage**: verification reports exactly which elements and
  attachments a signature covers, the defence against XML Signature Wrapping.
- **WS-Security**: the `wsse:Security` header in processing order, binary
  security tokens (X509v3, PKIPath and PKCS7), direct, embedded,
  key-identifier, issuer-serial and `EncryptedKey` token references,
  `wsu:Id`, timestamps checked on receipt, the STR Dereference Transform,
  signature confirmation, the symmetric binding (a header `ReferenceList`,
  each `EncryptedData` naming its `EncryptedKey` by a token reference), the
  SOAP Message Security fault codes (`wss.FaultCode`, with one generic
  `ErrDecryptionFailed` for `FailedCheck`), and opt-in Basic Security
  Profile checks on what is verified and on what is decrypted.
- **XML Encryption**: RSA-OAEP key transport with an explicit MGF, AES key
  wrap, ECDH-ES key agreement, and AES-GCM for elements, element content,
  SOAP header blocks (`wsse11:EncryptedHeader`, both ways), attachments and
  arbitrary octets; decryption in place; every `KeyInfo` form of section 3.5:
  `EncryptedKey` chains, `xenc11:DerivedKey` from a master key, and key
  agreement directly on the data; as opt-ins, finite-field Diffie-Hellman
  (`dh-es`, `dh`), PBKDF2, and an allow-listed XPath on a `CipherReference`.
- **Hardened by default**: no DOCTYPE, no network or file access, no SHA-1
  or other weak algorithm unless the caller names it, algorithm allow-lists
  checked before any cryptography. The XPath, XPath Filter 2.0 and XSLT
  transforms verify only for the exact expressions or stylesheets a caller
  allows.

## Install

```
go get github.com/knroy/go-xmlsec
```

Requires Go 1.26 or later.

## Quick start

Sign a document, then verify it as the receiver. `key` is an
`xmlsec.KeyProvider`: any `crypto.Signer` with its certificate, so a PEM key,
a PKCS#11 token and a cloud KMS key all work.

```go
tree, err := xmlsec.Parse([]byte(`<Invoice><Total>100.00</Total></Invoice>`))

signed, err := dsig.SignEnveloped(tree.Root, key, dsig.SignOptions{
    SignatureAlgorithm:        xmlsec.SigRSASHA256,
    CanonicalizationAlgorithm: string(c14n.Exclusive10),
    References: []dsig.Reference{{
        URI:             "", // the whole document
        DigestAlgorithm: xmlsec.DigestSHA256,
        Transforms: []dsig.TransformSpec{
            {Algorithm: xmlsec.TransformEnvelopedSignature},
            {Algorithm: string(c14n.Exclusive10)},
        },
    }},
    KeyInfo: dsig.KeyInfoX509Data,
})
```

`signed` is the signed document as octets. Send exactly those; never
re-serialize a signed document.

```go
received, err := xmlsec.Parse(signed)
invoice := received.Root.ChildElements()[0]
sig := invoice.ChildElements()[1] // the signature is appended last

cov, err := dsig.Verify(received.Root, sig, dsig.VerifyOptions{
    Certificate:                       senderCert,
    AllowedSignatureAlgorithms:        []string{xmlsec.SigRSASHA256},
    AllowedDigestAlgorithms:           []string{xmlsec.DigestSHA256},
    AllowedCanonicalizationAlgorithms: []string{string(c14n.Exclusive10)},
})
// err == nil and cov.WholeDocumentSigned: the invoice is signed by senderCert.
```

Both snippets are adapted from `Example_enveloped` in
[dsig/example_test.go](dsig/example_test.go), with error handling left out;
`go test` compiles and runs the example, so it cannot drift from the API.
`Example_wsSecurity` in the same file signs a SOAP body inside a WS-Security
header, and [docs/usage.md](docs/usage.md) covers WS-Security, attachments
and encryption in full.

## Verifying safely

`dsig.Verify` returning nil means the signature is valid over exactly what
`Coverage` lists, and nothing more. Before trusting a message:

1. **Pin the certificate** with `VerifyOptions.Certificate` when you know the
   sender, or judge it in `VerifyOptions.TrustKey`, which runs before
   any cryptographic work. Otherwise the certificate comes from the message
   itself, and deciding whether to trust it is up to you: this library makes
   no trust decisions.
2. **Check `Coverage`.** Confirm it includes every element and attachment you
   are about to read: `CoversNodes` for the elements themselves, and
   `CoversAttachments`. A valid signature over the wrong element is how XML
   Signature Wrapping works, and an ID check (`Covers`) passes on a wrapped
   document when the element is then found by position.
3. **Pass allow-lists** (`dsig.VerifyOptions`, `xenc.DecryptOptions`) naming
   exactly the algorithms your profile permits.
4. **Parse with `xmlsec.Parse`**, or `xmlsec.ParseWithLimits` to tighten the
   limits to what your profile needs.

[docs/security.md](docs/security.md) explains each rule, with the threat model
and measured costs.

## Algorithms

Every algorithm is named explicitly when producing a signature or
ciphertext: the right canonicalization differs between document families,
and a wrong default produces a signature that looks valid and that no peer
accepts. Verification and decryption have conservative default allow-lists,
which a caller replaces by naming its own.

| Purpose | Supported |
|---|---|
| Signature | RSA PKCS#1 v1.5 and ECDSA, each with SHA-256, SHA-384, SHA-512; HMAC-SHA256, 384, 512 with a caller's shared secret (opt-in on verification); opt-in: RSA, ECDSA and HMAC with SHA-224 |
| Digest | SHA-256, SHA-384, SHA-512; opt-in: SHA-224 |
| Key information | X.509 certificates and chains with issuer-serial, SKI, subject name and `X509Digest`; raw RSA and EC keys; `KeyName`; same-document `RetrievalMethod` and `KeyInfoReference`; WS-Security token references. Names, identifiers and external references are resolved only by caller-supplied resolvers |
| Canonicalization | Canonical XML 1.0 and 1.1, Exclusive Canonical XML 1.0, with or without comments, from `go-xml/c14n` |
| Transforms | enveloped signature, base64, SwA `Attachment-Content-Signature` and `Attachment-Complete-Signature`, the WS-Security STR Dereference Transform; XPath, XPath Filter 2.0 and XSLT, verified only for allowed expressions and stylesheets |
| Key transport | RSA-OAEP (XML Encryption 1.1), MGF1 with SHA-256, SHA-384, SHA-512; opt-in: MGF1 with SHA-224 |
| Key wrap | AES-128, AES-192, AES-256 (RFC 3394) |
| Key agreement | ECDH-ES on P-256, P-384, P-521, with ConcatKDF; opt-in: finite-field `dh-es` and `dh` in 2048- to 8192-bit groups |
| Key derivation | ConcatKDF, from a master key or a shared secret; opt-in: PBKDF2 with HMAC-SHA256, 384, 512, from a password or a shared secret |
| Data encryption | AES-128-GCM, AES-192-GCM, AES-256-GCM; attachments as SwA `Attachment-Content-Only` or `Attachment-Complete` |

Never produced, and accepted only when a caller names each one: SHA-1,
DSA with SHA-1 or SHA-256, ECDSA with SHA-1, HMAC-SHA1, `rsa-oaep-mgf1p`,
`rsa-1_5`, AES-CBC, 3DES and `kw-tripledes`, which the specifications
require or allow but which are weak. The XPath, XPath Filter 2.0 and XSLT
transforms are produced on request and verified only for expressions and
stylesheets the caller allows by exact text. Refused
outright: DOCTYPE. The library never fetches anything: a URI outside the
document and its attachments is dereferenced only through a resolver the
caller supplies (`ResolveURI`), and refused without one; a relative URI
also needs the caller's `BaseURI`, never the document's `xml:base`. The
reasons, and how this measures against each specification requirement by
requirement, are in [docs/security.md](docs/security.md#conformance).

## How it is tested

| | |
|---|---|
| Unit and conformance tests | Linux, macOS and Windows on every commit; 100% statement coverage, enforced |
| Interoperability | [`xmlsec1`](https://www.aleksey.com/xmlsec/) 1.3 and [Apache Santuario](https://santuario.apache.org/) 4.0.4 verify our signatures and decrypt our output, and we do the same for theirs, on every commit. [Apache WSS4J](https://ws.apache.org/wss4j/) 4.0.1 processes our WS-Security headers, with Basic Security Profile enforcement, and decrypts our encryption, symmetric binding included, and we decrypt its |
| Byte equality | the same document signed with the same key produces a `SignatureValue` byte-identical to Santuario's, enveloped and WS-Security |
| Static analysis | `staticcheck` and `gosec`, clean, on every commit |
| Real-world documents | 122 real Peppol SMP responses, from 62 providers, all verify; kept in a separate corpus module |
| Security | XXE, external fetches, signature wrapping, key substitution, algorithm confusion, comment truncation and encryption downgrade, each a regression test |
| Fuzzing | Three targets on the verify and decrypt paths, one hour each, nightly |
| Canonicalization | done by `go-xml/c14n` v1.6.0, which publishes its figures in its own docs rather than its README: the W3C C14N 1.1 interop cases 20/20, the Baltimore Merlin interop signatures, the Recommendations' examples, and differentials against `xmllint` and `xmlsec1`. A Santuario differential and a real-message corpus are still open there. The byte-identical signatures, Canonical XML 1.1 included, and the real-world corpus above exercise it independently; see [docs/testing.md](docs/testing.md#canonicalization). |

[docs/testing.md](docs/testing.md) has the detail, including every dataset
the tests use.

## Documentation

- [Usage](docs/usage.md): signing, verifying, WS-Security, encryption
- [Security](docs/security.md): threat model, refusals, limits, assessment
- [Testing](docs/testing.md): what runs and how to run it
- [CHANGELOG.md](CHANGELOG.md) · [SECURITY.md](SECURITY.md) for reporting
  vulnerabilities · [RELEASE.md](RELEASE.md)

## License

MIT. See [LICENSE](LICENSE).
