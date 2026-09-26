# Testing

```
go test ./...                      # unit and conformance tests
go test -race -cover ./...         # what CI runs
go test -run TestConformance ./... # the requirement-mapped tests only
go test -run TestConformance_AP_09 ./dsig
tests/interop.sh                   # the xmlsec1 and Santuario differential, in a container
go test -run '^$' -fuzz '^FuzzVerify$' -fuzztime 60s ./dsig
```

Unit tests touch no network and no filesystem outside the repository, and
read no clock. Keys and certificates are generated per run, except the
golden-file key.

| Layer | Where | Runs |
|---|---|---|
| Unit and conformance | `*_test.go` beside each package, named after the source file they test; `internal/swa` holds the SwA MIME header and content canonicalization | every push, Linux, macOS and Windows, under `-race` |
| Differential against `xmlsec1`, Apache Santuario and WSS4J | `tests/interop`, build tag `interop`, run by `tests/interop.sh` | every push, Linux |
| Security regressions | `tests/security`: XXE, external fetches, key substitution, algorithm confusion, comment truncation, encryption downgrade | every push, all three systems; a local HTTP listener proves nothing is fetched |
| Fuzzing | `FuzzVerify`, `FuzzDecryptEncryptedKey`, `FuzzDecryptData` | nightly, one hour per target |
| Static analysis | `staticcheck` v0.8.1, `gosec` v2.29.0, pinned | every push: both clean, no `#nosec` suppressions |
| W3C interop vectors | `tests/w3c`, a nested module | every push, all three systems |
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
| `TestParseRefusesXXE`, `TestParseFetchesNothing`, `TestVerifyDereferencesNothingExternal` | every XXE and external-reference route in the [assessment](security.md#assessment) is refused or inert, with zero requests reaching a local listener |
| `TestRawKeyRoundTrip`, `TestRawKeyInfoStructure`, `TestCoveragePublicKey` | each raw-key form with RSA and P-256/384/521, self-described and pinned; a different pinned key refused; malformed and refused raw keys (short RSA, even modulus or exponent, off-curve and compressed points, explicit parameters, unknown curves) |
| `TestPinnedCertificateIgnoresEmbeddedKey`, `TestAlgorithmConfusion` | an attacker's own key is refused against a pinned certificate; HMAC, SHA-1 and key-type confusion are refused |
| `TestXPointerReferences`, `TestBase64OfNodeSet`, `TestOmittedURI`, `TestKeyInfoReference`, `TestPinnedKeyIgnoresUnsupportedKeyInfo` | the XML Signature 1.1 processing rules: XPointer forms keeping comments, base64 over a node set, the one URI-less reference, same-document `KeyInfoReference`, and a pinned key tolerating an unsupported `KeyInfo` |
| `TestSignInPlace`, `TestSignInPlaceRefusals` | in-place signing with any canonicalization, and a failed `Sign` leaving the document unchanged |
| `TestStrictSecurityTokenReference` | the Basic Security Profile rules on a received token reference |
| `TestNilInputs` (`wss`, `xenc`) | a nil or wrong-kind argument is an error, never a panic |
| `TestImplicitCanonicalization` | a received reference ending in a node set verifies through Canonical XML 1.0, and the implied algorithm is refused when outside the allow-list |
| `TestX509DataDescriptiveElements` | subject name, issuer-serial and SKI beside one certificate are accepted and ignored; a second certificate, a CRL, a `KeyName` or no certificate are refused |
| `TestFindByID` | duplicate IDs are refused across `wsu:Id` and `xml:id` |
| `TestFindByIDAttributes`, `TestSAMLAssertionByID`, `TestPlainIdReference`, `TestDefaultIDSetUnchanged` | opt-in `ID`/`Id` resolution; duplicates refused across every counted attribute; an attacker assertion with the signed `ID` refused; the default set unchanged |
| `TestPrefixBoundElsewhere` | a `wsu` or `wsse` prefix bound to another namespace higher up does not corrupt the header |
| `TestVersionIsReleasedAndDescribed` | the version constant and the changelog agree; see [RELEASE.md](../RELEASE.md) |

## The differential against xmlsec1 and Santuario

`tests/interop` signs and encrypts with this library and has two independent
implementations verify and decrypt the result, and the reverse:

* **`xmlsec1` 1.3** (libxmlsec1, C, on OpenSSL).
* **Apache Santuario 4.0.4** (Java), the XML Security library that WSS4J and
  so most Java WS-Security stacks are built on, driven through a small
  harness, `tests/santuario/Harness.java`.
* **Apache WSS4J 4.0.1**, the WS-Security engine phase4 is built on, through
  the same harness: it processes our WS-Security headers and decrypts our
  encryption.

`tests/interop.sh` builds `tests/Dockerfile` (Go, `xmlsec1` and Santuario in
one Alpine image) and runs the tests in it; CI runs the same script. Alpine,
because the differential needs xmlsec 1.3: 1.2, which Debian and Ubuntu still
package, does not implement XML Encryption 1.1 `rsa-oaep`.

| Test | Direction | Cases |
|---|---|---|
| `TestXmlsec1VerifiesOurEnvelopedSignature`, `TestSantuarioVerifiesOurEnvelopedSignature` | ours → each | RSA inclusive, RSA exclusive, ECDSA inclusive; plus a control: a tampered document must be rejected |
| `TestWeVerifyXmlsec1EnvelopedSignature`, `TestWeVerifySantuarioEnvelopedSignature` | each → ours | the same three |
| `TestXmlsec1VerifiesOurDetachedSignature`, `TestWeVerifyXmlsec1DetachedSignature` | both ways | SOAP 1.2, two `#id` references, exclusive C14N with an InclusiveNamespaces prefix list |
| `TestSignatureValueMatchesSantuarioEnveloped` | byte equality | inclusive and exclusive C14N |
| `TestSignatureValueMatchesSantuarioDetached` | byte equality, and both ways | SOAP 1.2 WS-Security header, two `#id` references |
| `TestWSS4JProcessesOurSecurityHeader` | WSS4J | a WS-Security header built by this library: timestamp, binary security token, signature over body and timestamp; WSS4J must report both as signed, with Basic Security Profile enforcement on |
| `TestWSS4JDecryptsOurEncryption` | WSS4J | an encrypted body with the `EncryptedKey` in the header, naming the recipient's token and the `EncryptedData`; WSS4J must decrypt it to the original |
| `TestWSS4JVerifiesOurAttachmentSignatures`, `TestWeVerifyWSS4JAttachmentSignatures` | WSS4J, both ways | Content- and Complete-Signature transforms over XML, text and binary parts; a tampered part must be refused |
| `TestWSS4JDecryptsOurAttachmentEncryption`, `TestWeDecryptWSS4JAttachmentEncryption` | WSS4J, both ways | Attachment-Content-Only and Attachment-Complete encryption, AES-128-GCM under RSA-OAEP |
| `TestWSS4JProcessesSignThenEncrypt` | WSS4J | sign then encrypt in WS-Security order, with the recipient key named by token reference, subject key identifier and issuer-serial, plus an encrypted signature; WSS4J decrypts, then verifies. A control that appends the `EncryptedKey` (the old order) is refused |
| `TestWSS4JDecryptsOurEncryptedHeaderAndContent` | WSS4J | a `wsse11:EncryptedHeader` and encrypted Body content |
| `TestSantuarioXPointerReferences` | Santuario, both ways | `#xpointer(/)` and `#xpointer(id('…'))` with comments; byte-identical `SignatureValue`; a changed comment is refused |
| `TestSantuarioVerifiesOurInPlaceInclusiveSignature` | ours → Santuario | an inclusive-canonicalization signature computed in place (`SignOptions.Parent`) |
| `TestReferenceImplementationsDecryptOurECDHES`, `TestWeDecryptSantuarioECDHES`, `TestWeDecryptXmlsec1ECDHES` | both ways | ECDH-ES with ConcatKDF on P-256, P-384 and P-521 |
| `TestReferenceImplementationsDecryptOurKeyWrap`, `TestWeDecryptTheirKeyWrap` | both ways | AES key wrap |
| `TestDecryptReplaceKeepsNoNamespace` | ours → both | a decrypted element that undeclares a default namespace stays in no namespace |
| `TestXmlsec1DecryptsOurEncryption`, `TestSantuarioDecryptsOurEncryption` | ours → each | AES-128-GCM element, RSA-OAEP with explicit SHA-256 MGF and digest |
| `TestWeDecryptXmlsec1Encryption`, `TestWeDecryptSantuarioEncryption` | each → ours | the same |

**ID attributes.** The Santuario harness takes leading `--id-attr NAME`
options (repeatable, unqualified names) that register extra ID attributes,
for example `santuario --id-attr ID verify doc.xml cert.pem`; `sign-enveloped`
takes an optional seventh argument, the reference URI. `TestSantuarioSAMLAssertionByID`
checks a SAML-style assertion signed over `ID` in both directions, with
byte-identical `SignatureValue`, and that Santuario fails without the
registration.

**Byte equality.** RSA PKCS#1 v1.5 signing is deterministic, so the same
document signed with the same key must produce the same `SignatureValue`
whichever implementation signs it. The byte-equality tests sign one input
with this library and with Santuario and require every `DigestValue` and the
`SignatureValue` to be identical. That is a stronger claim than "each
verifies the other": it proves `ds:SignedInfo` canonicalizes to the same
octets, which is where a silent interoperability failure would live. The
comparison refuses to pass on missing values, so it cannot succeed
vacuously.

What `xmlsec1` needs that a WS-Security peer does not:

* **Registered IDs.** It has no notion of `wsu:Id`; the harness passes
  `--id-attr:Id` per element. The Santuario harness registers `wsu:Id` and
  `xml:id` attributes as IDs, which is what a WS-Security stack does.
* **The key, directly.** Neither tool resolves `wsse:SecurityTokenReference`
  from the command line, so the detached cases pass the certificate; for
  `xmlsec1` with `--lax-key-search`, because 1.3 otherwise refuses a key
  `KeyInfo` does not name.
* **The EncryptedKey inside `EncryptedData/ds:KeyInfo`.** That is how both
  find the session key. This library does not place it there (see
  [todo.md](todo.md)), so the harness does.

Set `GOXMLSEC_REQUIRE_INTEROP=1` to make a missing tool fail rather than
skip; the script and CI set it.

## Test data

Everything the tests run against, and where it comes from.

**Keys and certificates.** Generated fresh in every run from `crypto/rand`:
RSA 2048-bit keys, and ECDSA keys on P-256, P-384 and P-521, each with a
self-signed X.509 certificate. Tests that write PEM files for the reference
tools write them to a per-test temporary directory. One exception:
`wss/testdata/golden-key.pem`, a test-only RSA key and self-signed
certificate committed so that golden signatures are reproducible. It
protects nothing.

**Documents.** Synthetic, written inline in the tests so each is visible
beside the assertion that uses it:

| Fixture | Shape | Used by |
|---|---|---|
| WS-Security envelope | SOAP 1.2 with a messaging header and a body, plus one MIME attachment by `cid:` | the conformance tests in `dsig`, `FuzzVerify` seeds, `tests/interop` |
| Enveloped metadata document | a document element declaring an unused namespace, with a comment, signed whole | S-3 and S-4, `TestSignedInfoCanonicalizedInPlace` (the unused namespace is what makes in-place canonicalization observable), `tests/interop` |
| SOAP 1.1 envelope | minimal, for header construction and ID resolution | `wss` |
| Invoice and SOAP order | the smallest documents that show each API | `dsig/example_test.go`, quoted in the README |
| Adversarial documents | XXE and DTD variants, relocated and duplicated IDs, algorithm and key substitutions | `tests/security`, `TestVerifyNegative`, `TestSignRefusals` |

**Reference implementations.** Built into one image by `tests/Dockerfile`:

| Implementation | Version | Source |
|---|---|---|
| `xmlsec1` (libxmlsec1 on OpenSSL) | 1.3.11 at the time of writing | Alpine package `xmlsec`, on `golang:1.26-alpine` |
| Apache Santuario | 4.0.4 | Maven Central `org.apache.santuario:xmlsec`, run on OpenJDK 21 |
| Apache WSS4J | 4.0.1 | Maven Central `org.apache.wss4j:wss4j-ws-security-dom`, same harness |

The harness (`tests/santuario/Harness.java`) exposes Santuario and WSS4J as
commands: `verify`, `sign-enveloped`, `sign-detached`, `encrypt`, `decrypt`,
`encrypt-ecdh`, `encrypt-kw`, `decrypt-kw`, `wss4j-verify`, `wss4j-decrypt`,
`wss4j-process` (both keys: decrypt, then verify), and the attachment
commands; `--id-attr NAME` registers extra ID attributes.

The Alpine package is not pinned to a patch release; the version in use is
printed by `xmlsec1 --version` in the container.

**Fuzz corpora.** Seeded at run time from real signatures and encryptions
produced by this library, plus the malformed seeds listed under Fuzzing.
Inputs the fuzzer finds interesting stay in the local Go fuzz cache; any
failing input is committed under `testdata/fuzz/<Target>/` as a permanent
regression seed.

**W3C XML Signature 1.1 interop vectors.** `tests/w3c`, a nested module, so
they are in this repository and CI but not in the library's module
download: 25 vectors from the 2012 interop report (Oracle), ECDSA
P-256/384/521 and RSA with SHA-256/384/512, copied unmodified under the W3C
Document License (`tests/w3c/NOTICE`, `tests/w3c/LICENSE-W3C-DOCUMENT`).
`testdata/MANIFEST.json` records the expected outcome of each; run with
`cd tests/w3c && go test ./...`. **10 verify end to end**: the nine
`ECKeyValue` vectors and the EC `DEREncodedKeyValue` one, each an enveloping
signature over a `ds:Object` (identified with `IDAttrDSig`). The other 15
are refused, each for a documented reason: 4 carry 1024-bit RSA keys, below
the 2048-bit minimum; 9 use the legacy RFC 4050 `ECDSAKeyValue` form; one
uses `KeyInfoReference` and one `X509Digest`.

**W3C XML Encryption 1.1 interop vectors.** `tests/w3c/testdata/xmlenc11`, the
2012 Oracle vectors under the same license, with their keys (the `.p12` files
unmodified, and their private keys extracted to PEM, since Go cannot read
PKCS#12). The three ECDH-ES with ConcatKDF vectors, on P-256, P-384 and
P-521, decrypt to the published plaintext. The others are refused for stated
reasons: PBKDF2 is not implemented, finite-field `dh-es` is not allowed, and
`rsa-oaep-mgf1p` and a SHA-1 MGF are not allowed.

**Real-world corpus.** 122 real Peppol SMP responses, fetched 2026-09-26 from
62 SMP providers and at least 20 distinct producing implementations, stored
byte-for-byte. They are kept in a separate, private repository,
`go-xmlsec-corpus`, not here: they carry no license grant and may contain
personal data, so they are not redistributed. Its CI runs them against this
library. **All 122 verify**, whole document signed, key from the
certificate; each signature and every digest was also checked
independently, and Santuario agrees on every one. The corpus found the two
behaviours recorded in [todo.md](todo.md) as decided departures: implicit
Canonical XML 1.0 on verification, and descriptive `X509Data` elements. The
documents exercise CRLF line endings, a UTF-8 byte-order mark, character
references and non-ASCII text.

## Golden files

`wss/golden_test.go` compares whole documents byte for byte with files in
`wss/testdata/golden`:

| Golden | Shape |
|---|---|
| `signed-envelope-two-attachments.xml` | SOAP 1.2, binary security token, one signature over the messaging header, the body and two `cid:` attachments (Attachment-Content-Signature, one `text/plain` and one `application/gzip`), exclusive C14N, RSA-SHA256, SecurityTokenReference |
| `signed-encrypted-envelope.masked.xml`, `signed-encrypted-payload.xml` | the same envelope signed, then its body payload encrypted (AES-128-GCM, RSA-OAEP with explicit SHA-256 MGF). Every `CipherValue` is masked, because the IV, session key and OAEP padding are random; the plaintext has its own golden, and the decrypted envelope must verify |
| `enveloped-metadata.xml` | enveloped, inclusive C14N, X509Data |
| `enveloped-invoice.xml` | the README quick-start document, exclusive C14N |

Every signed golden is verified, with allow-lists and a coverage check,
before it is compared, so a golden that does not verify can never be
written. They are reproducible because the key is fixed, RSA PKCS#1 v1.5
signing is deterministic, and `wsu:Id` values come from a fixed stream set
through `SetRandReader` in `wss/export_test.go`. That helper is visible only
to tests in `wss/`, which is why the goldens live there. `.gitattributes`
keeps them LF on every system.

**Regenerate only with `go test ./wss -run TestGolden -update`, then review
`git diff wss/testdata/golden` and say in the commit why the octets
changed.** An unexplained golden change is serialization drift, not a
fixture refresh. Only `wss` defines `-update`; do not pass it to `./...`.

## Fuzzing

| Target | Exercises |
|---|---|
| `FuzzVerify` | parse and verify, three ways: plain, with attachments, with a supplied certificate. Seeded with real detached and enveloped signatures and with malformed ones: 100 references, an XSLT transform with a stylesheet child, bad base64, a reference to the signature itself, 200 nested namespace declarations. Mutated inputs are re-signed so that reference and transform code is reached, not just the signature check. Invariant: a nil error always comes with a non-empty `Coverage`. |
| `FuzzDecryptEncryptedKey` | `DecryptEncryptedKey`, with and without allow-lists |
| `FuzzDecryptData` | `DecryptData` and `DecryptAttachment`, under several key lengths |

First runs: about 1.3M, 2.9M and 7.6M executions, no crash, hang or slow
input.

## Coverage

**100% of statements in every package, enforced by CI.**

The rule that keeps it honest: an unreachable branch is deleted or
restructured so that it becomes reachable, never excused and never reached
by faking the standard library. What that meant in practice:

| Was unreachable | Now |
|---|---|
| `crypto/rand.Read` errors | deleted: it cannot fail since Go 1.24 |
| namespace conflicts on a newly built, detached element | deleted: its own declaration cannot conflict |
| `aes.NewCipher` after the key length was checked | the order is swapped: `NewCipher` refuses a length AES does not have, the size check refuses a valid AES key of the wrong size for the algorithm, and both are tested |
| canonicalizing a `ds:Reference` for `Coverage.Raw` after `ds:SignedInfo` | `Raw` is taken first, so a document with no canonical form fails there; `SignedInfo` keeps its own failure case, a relative namespace declared on `ds:SignatureMethod` and so in no `Reference`'s scope (`TestUnverifiable`) |

One error is discarded, with a comment: `asn1.Marshal` of the PkiPath in
`wss/bst.go`, a sequence of `RawValue`s that are emitted verbatim and cannot
fail to encode.

## Not tested yet

* **Gate 2**: byte equality with phase4 over whole captured AS4 messages. The
  signature-level equivalent, byte equality with Santuario, is in place.
