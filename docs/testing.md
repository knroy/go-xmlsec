# Testing

```
go test ./...                      # unit and conformance tests
go test -race -cover ./...         # what CI runs
go test -run TestConformance ./... # the requirement-mapped tests only
go test -run TestConformance_AP_09 ./dsig
tests/interop-xmlsec1.sh           # the xmlsec1 differential, in a container
go test -run '^$' -fuzz '^FuzzVerify$' -fuzztime 60s ./dsig
```

Unit tests touch no network and no filesystem outside the repository, and
read no clock. Keys and certificates are generated per run.

| Layer | Where | Runs |
|---|---|---|
| Unit and conformance | `*_test.go` beside each package, named after the source file they test | every push, Linux, macOS and Windows, under `-race` |
| Differential against `xmlsec1` | `tests/interop`, build tag `interop` | every push, Linux |
| Fuzzing | `FuzzVerify`, `FuzzDecryptEncryptedKey`, `FuzzDecryptData` | nightly, one hour per target |
| Hygiene | CI | every push: no `peppol` module in the dependency graph, no `peppol` string in Go source outside `internal/` |

## Conformance tests

Named `TestConformance_<ID>_<description>` for the requirement they prove.

| ID | Requirement | Test | Status |
|---|---|---|---|
| AP-5 | rsa-sha256, sha256, exclusive C14N | `TestConformance_AP_05_AS4SignatureAlgorithms` | ✅ |
| AP-6 | aes128-gcm | `TestConformance_AP_06_AES128GCM` | ✅ |
| AP-7 | rsa-oaep with explicit mgf1sha256 and sha256 | `TestConformance_AP_07_RSAOAEPExplicitMGF` | ✅ |
| AP-8 | BST X509v3, certificate embedded | `TestConformance_AP_08_BinarySecurityToken` | ✅ |
| AP-9 | Signing attachments via cid | `TestConformance_AP_09_SwAAttachmentSigning` | ✅ |
| AP-10 | Coverage reported, not just validity | `TestConformance_AP_10_SignatureCoverage` | ✅ |
| S-3 | Inclusive C14N, enveloped | `TestConformance_S_03_SMPEnvelopedSignature` | ✅ |
| S-4 | X509Certificate in KeyInfo | `TestConformance_S_04_KeyInfoX509Data` | ✅ |

## Named tests worth knowing

| Test | Proves |
|---|---|
| `TestVerifyNegative` | rejection of a modified element, a duplicated `wsu:Id`, an algorithm outside the allow-list, a truncated signature value, too many references, the wrong certificate |
| `TestSignedInfoCanonicalizedInPlace` | `ds:SignedInfo` is canonicalized in the live tree; the fixture is checked to canonicalize differently when extracted, so the test would fail if verification extracted it |
| `TestUnverifiable` | XML 1.1 and a relative namespace URI each reach `c14n` from untrusted input and surface as `ErrUnverifiable` wrapping the cause |
| `TestWithCommentsTransforms` | each `#WithComments` transform, exclusive included, signs and verifies |
| `TestAlgorithms`, `TestAlgorithmCombinations` | every `Sig*` and `Digest*` constant; every data × MGF × OAEP digest combination |
| `TestSignRefusals` | XSLT, XPath, SHA-1, no final canonicalization, whole-document reference without enveloped, inclusive SignedInfo on a detached signature |
| `TestParseRefusesDOCTYPE` | open item X-1: the pinned options refuse a DOCTYPE, asserted rather than read from documentation |
| `TestFindByID` | duplicate IDs are refused across `wsu:Id` and `xml:id` |
| `TestPrefixBoundElsewhere` | a `wsu` or `wsse` prefix bound to another namespace higher up does not corrupt the header |
| `TestVersionIsReleasedAndDescribed` | the version constant and the changelog agree; see [RELEASE.md](../RELEASE.md) |

## The xmlsec1 differential

`tests/interop` signs and encrypts with this library and has `xmlsec1` verify
and decrypt, and the reverse. `tests/interop-xmlsec1.sh` runs it in an Alpine
container, because it needs xmlsec **1.3**: 1.2, which Debian and Ubuntu
still package, does not implement XML Encryption 1.1 `rsa-oaep`. CI runs the
same script.

| Test | Direction | Cases |
|---|---|---|
| `TestXmlsec1VerifiesOurEnvelopedSignature` | ours → xmlsec1 | RSA inclusive, RSA exclusive, ECDSA inclusive; X509Data trusted as a root; plus a control: a tampered document must be rejected |
| `TestWeVerifyXmlsec1EnvelopedSignature` | xmlsec1 → ours | the same three |
| `TestXmlsec1VerifiesOurDetachedSignature` | ours → xmlsec1 | SOAP 1.2, two `#id` references, exclusive C14N with an InclusiveNamespaces prefix list |
| `TestWeVerifyXmlsec1DetachedSignature` | xmlsec1 → ours | the same shape |
| `TestXmlsec1DecryptsOurEncryption` | ours → xmlsec1 | AES-128-GCM element, RSA-OAEP with explicit SHA-256 MGF and digest |
| `TestWeDecryptXmlsec1Encryption` | xmlsec1 → ours | the same |

What `xmlsec1` needs that a WS-Security peer does not, and what that means:

* **Registered IDs.** It has no notion of `wsu:Id`; the harness passes
  `--id-attr:Id` per element.
* **The key, directly.** It does not resolve `wsse:SecurityTokenReference`,
  so the detached cases pass the certificate on the command line, with
  `--lax-key-search` because 1.3 otherwise refuses a key `KeyInfo` does not
  name.
* **The EncryptedKey inside `EncryptedData/ds:KeyInfo`.** That is how it
  finds the session key. This library does not place it there (see
  [todo.md](todo.md)), so the harness does.

Set `GOXMLSEC_REQUIRE_XMLSEC1=1` to make a missing `xmlsec1` fail rather than
skip; the script and CI set it.

## Fuzzing

| Target | Exercises |
|---|---|
| `FuzzVerify` | parse and verify, three ways: plain, with attachments, with a supplied certificate. Seeded with real detached and enveloped signatures and with malformed ones: 100 references, an XSLT transform with a stylesheet child, bad base64, a reference to the signature itself, 200 nested namespace declarations. Mutated inputs are re-signed so that reference and transform code is reached, not just the signature check. Invariant: a nil error always comes with a non-empty `Coverage`. |
| `FuzzDecryptEncryptedKey` | `DecryptEncryptedKey`, with and without allow-lists |
| `FuzzDecryptData` | `DecryptData` and `DecryptAttachment`, under several key lengths |

First runs: about 1.3M, 2.9M and 7.6M executions, no crash, hang or slow
input.

## Coverage

At the time of writing: root 100%, `dsig` 99.7%, `wss` 96.6%, `xenc` 98.0%,
`internal/xmltree` 100%. The remaining lines are unreachable by construction:
a `crypto/rand` failure, `asn1.Marshal` of raw values, an AES key length
already checked, a namespace declaration on an element that has no parent.

## Not tested yet

* **Apache Santuario**, the second independent implementation the
  differential needs. A shared canonicalization bug between us and `xmlsec1`
  would pass today.
* **Gate 2**: signature byte-equality with phase4, over a captured corpus.
* **WSS4J** processing our headers and decrypting our output.
* **Golden files** for a signed envelope with two attachments, a signed and
  encrypted envelope, and an enveloped metadata document.
