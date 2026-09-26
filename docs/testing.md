# Testing

```
go test ./...                      # everything
go test -race -cover ./...         # what CI runs
go test -run TestConformance ./... # the requirement-mapped tests only
go test -run TestConformance_AP_09 ./dsig
```

No test touches the network or the filesystem outside the repository, and
none reads the clock. Keys and certificates are generated per run.

CI (`.github/workflows/ci.yml`) runs gofmt, vet, a `CGO_ENABLED=0` build and
`go test -race -cover` on Linux, macOS and Windows, plus the hygiene job: no
`peppol` module in the dependency graph, and no `peppol` string in Go source
outside `internal/`.

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

## Other named tests

| Test | Proves |
|---|---|
| `TestVerifyNegative` | rejection of a modified element, a duplicated `wsu:Id`, an algorithm outside the allow-list, a truncated signature value, too many references, the wrong certificate |
| `TestSignedInfoCanonicalizedInPlace` | `ds:SignedInfo` is canonicalized in the live tree; the fixture is checked to canonicalize differently when extracted, so the test would fail if verification extracted it |
| `TestUnverifiable` | XML 1.1 and a relative namespace URI each reach `c14n` from untrusted input and surface as `ErrUnverifiable` wrapping the cause |
| `TestAlgorithms` | every `Sig*` and `Digest*` constant, RSA and ECDSA P-256/384/521 |
| `TestAlgorithmCombinations` | every data × MGF × OAEP digest combination round-trips, with an OAEP label |
| `TestSignRefusals` | XSLT, XPath, SHA-1, no final canonicalization, whole-document reference without enveloped, inclusive SignedInfo on a detached signature |
| `TestParseRefusesDOCTYPE` | open item X-1: the effective DOCTYPE and entity behaviour of the pinned options, asserted rather than read from documentation |
| `TestFindByID` | duplicate IDs are refused across `wsu:Id` and `xml:id` |
| `TestHeaderAndAssignID` | deterministic IDs via the injected reader; SOAP 1.1 `mustUnderstand="1"`; one header per actor |
| `TestVersionIsReleasedAndDescribed` | the version constant and the changelog agree; see [RELEASE.md](../RELEASE.md) |

## Coverage

At the time of writing: root 73%, `dsig` 74%, `wss` 47%, `xenc` 77%, per
package. The target is 85% (acceptance criterion 19); `wss` is furthest off,
mostly the PKIPath and SOAP 1.2 actor paths.

## Not tested yet

Everything so far is checked against this module's own verifier. What
independent evidence requires, none of which exists yet:

* **Interop harness** (`internal/interop`): `xmlsec1 --verify` accepts our
  signatures and we accept `xmlsec1 --sign`'s; the same against Apache
  Santuario in a container.
* **Gate 2**: signature byte-equality with phase4 over a corpus of at least
  50 messages.
* **Golden files** for a signed envelope with two attachments, a signed and
  encrypted envelope, and an enveloped metadata document.
* **Fuzz targets** on the parse-and-verify path.
* **WSS4J** processing our headers and decrypting our output.
