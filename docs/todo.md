# TODO

## Not implemented

| Item | Notes |
|---|---|
| Gate 2 against phase4 | Needs the captured-message corpus (X-5), and the consumer that builds whole AS4 messages: Gate 2 compares a message, not a signature. The signature-level equivalent, byte equality with Santuario, is in place (`tests/interop`). |
| Legacy algorithms the specifications REQUIRE: SHA-1, DSA-SHA1 with `DSAKeyValue`, HMAC, RSA-SHA1, AES-CBC, 3DES, `rsa-oaep-mgf1p`, RSA v1.5 | **In progress.** Being added for verification and decryption only, outside the default allow-lists, never produced: see [security.md](security.md#conformance). |

## Acceptance criteria

v1 requires all of them. Numbers are the design document's; status is as of
the latest commit.

| # | Criterion | Status |
|---|---|---|
| 1 | `xmlsec1 --verify` accepts our enveloped and detached signatures | **Met.** `tests/interop`, every push. Santuario accepts them too. |
| 2 | We accept `xmlsec1`'s and Santuario's signatures, and reject the negative corpus: modified element, modified attachment, relocated element, duplicated `wsu:Id`, algorithm outside the allow-list, truncated signature | **Met.** `tests/interop`; `TestVerifyNegative`, AP-09, AP-10. Signatures are also byte-identical to Santuario's. |
| 3 | `Coverage` matches phase4's own over a real-message corpus | **Open.** Needs captured AS4 messages, which need a certified access point. The real SMP corpus (122 documents, all verifying) covers enveloped signatures only. |
| 4 | `xenc` round-trips every permitted algorithm combination, and its output decrypts under WSS4J | **Met.** Every combination round-trips (`TestAlgorithmCombinations`); `xmlsec1`, Santuario and WSS4J 4.0.1 all decrypt our output (`TestWSS4JDecryptsOurEncryption`, with the `EncryptedKey` composed by `SetKeyInfo` and `AddDataReference`). |
| 5 | Attachment encryption round-trips against phase4 | **Open.** Needs phase4. |
| 6 | WSS4J processes our `wsse:Security` header without warnings | **Met.** WSS4J 4.0.1, with Basic Security Profile enforcement on, processes a header built entirely by this library, a timestamp, a binary security token and a signature over body and timestamp, and reports both as signed (`TestWSS4JProcessesOurSecurityHeader`). |
| 7 | Gate 2: our `SignatureValue` byte-identical to phase4's over whole AS4 messages | **Open.** Needs the AS4 message builder this library serves, and the corpus. The signature-level equivalent, byte equality with Santuario, is met. |
| 8 | Every algorithm constant used by at least one test | **Met.** Checked mechanically: every `Sig*`, `Digest*`, `Transform*`, `Enc*`, `KeyTransport*`, `MGF1*` and `BST*` constant appears in a test. |
| 9 | `c14n.ErrRelativeNamespaceURI` and `c14n.ErrXML11` reached from untrusted input and mapped to `ErrUnverifiable` | **Met.** `TestUnverifiable`. |
| 10 | `ds:SignedInfo` canonicalized in the live tree, by a test that would fail otherwise | **Met.** `TestSignedInfoCanonicalizedInPlace`. |
| 11 | No canonicalization logic in this module | **Met.** Every digest and every emitted document goes through `go-xml/c14n`. |
| 12 | `go-xml` pinned at v1.4.0 or later, and Gate 2 run on every dependency bump | **Half met.** Pinned at v1.4.0. Gate 2 does not exist yet (7). |
| 13 | Duplicate IDs refused; `xdm.ElementByID` not on the verify path | **Met.** `TestFindByID`, `TestVerifyNegative`. |
| 14 | DOCTYPE and entity behaviour asserted by test; no `EntityResolver` | **Met.** `TestParseRefusesDOCTYPE`, `TestParseRefusesXXE`. |
| 15 | Both depth limits set explicitly | **Met.** `xmlsec.MaxParseDepth`, `xmlsec.MaxC14NDepth`. |
| 16 | One hour per fuzz target with no crash, hang or out-of-memory | **In progress.** The three one-hour runs are under way; nightly CI runs them too. |
| 17 | No `peppol-*` import, no `peppol` string outside `internal/` | **Met.** CI hygiene job. |
| 18 | `CGO_ENABLED=0` build; `go vet`, `staticcheck`, `gosec` clean | **Met.** CI; both linters pinned, no suppressions. |
| 19 | Statement coverage at least 85% | **Met.** 100%, enforced by CI. |
| 20 | README states what the module is tested against, with figures, including the canonicalization gate's status upstream | **Met.** |
| 21 | `SECURITY.md` with a disclosure address and response window | **Met.** |
| 22 | Package documentation states the threat model, including that `Verify` makes no trust decision | **Met.** `doc.go`, `dsig.Verify`. |
| 23 | Version stays `v0.x` until 1 to 19 hold | **Met.** `internal/version` is `0.0.0`; `TestVersionIsReleasedAndDescribed` rejects a major version above 0. |

**What stands between here and v1:** 3, 5, 7 and 12 need either phase4 run
against captured AS4 messages, or the AS4 message builder this library is
written for. They cannot be closed inside this repository. 16 needs the
running fuzz results.

## Open items

| # | Item | Status |
|---|---|---|
| X-1 | Effective DOCTYPE and entity behaviour of the pinned parse | **Closed by test.** A DOCTYPE, with or without entities and however encoded, is refused, and nothing is fetched (`tests/security`). |
| X-2 | `xdm.ElementByID` on duplicate IDs | **Answered** from the v1.4.0 source: it returns the first depth-first match. Not used on the verify path. |
| X-3 | Gate 1 status upstream | go-xml v1.4.0 reports `xmllint` and `xmlsec1` canonicalization differentials; a Santuario differential and a real-message corpus are still open there. This module adds indirect evidence: signatures byte-identical to Santuario's, and 147 independently produced signatures whose digests go-xml's canonicalization reproduces. |
| X-4 | AS4 canonicalization URI inherited, not stated | unchanged |
| X-5 | Real-message corpus | **Partly closed.** 122 real Peppol SMP responses from 62 providers all verify; they live in the private `go-xmlsec-corpus` repository, because they carry no license grant and may contain personal data. The 25 W3C XML-DSig 1.1 interop vectors are in this repository, `tests/w3c`, under the W3C Document License. Captured AS4 messages still need a certified access point. |
| X-6 | Does any peer require `Attachment-Complete`? | **Moot.** Implemented, for signing and encryption, and tested both ways against WSS4J. |

## Where the implementation departs from the design document

Each is deliberate, and each is decided, with its reason or evidence below.

| Departure | Why |
|---|---|
| Minimum Go 1.26, not 1.25 | **Decided.** `rsa.EncryptOAEPWithOptions` is the only standard-library route to an MGF1 hash that differs from the OAEP digest. |
| `SignOptions.SecurityTokenID` added | **Decided.** The design document's API had no way to name the binary security token a `SecurityTokenReference` points at. Searching the document for a token carrying the signing certificate would be implicit and ambiguous when a message holds two; naming it is explicit, and `Sign` checks the named token carries the signing certificate. |
| `EncryptAttachment`: the transform argument becomes `EncryptedData/@Type`, and the `CipherReference` carries `Attachment-Ciphertext-Transform` | **Decided, by evidence.** The design document put the content transform on the `CipherReference`; the SwA profile puts it in the Type. WSS4J decrypts our attachment encryption and we decrypt WSS4J's, for both Content-Only and Complete (`TestWSS4JDecryptsOurAttachmentEncryption`, `TestWeDecryptWSS4JAttachmentEncryption`). |
| Attachments are signed with the SwA signature transforms, not `#Attachment-Content-Only` | **Decided.** The design document signed with `#Attachment-Content-Only`, which the SwA profile defines as an `EncryptedData` Type, not a signature transform; WSS4J refuses it, so every attachment signature would have been rejected by a WS-Security peer. Signing and verification use `#Attachment-Content-Signature-Transform` (or Complete), which canonicalizes XML content with Exclusive C14N and text with CRLF line endings, as the profile and WSS4J do. |
| `VerifiedReference.Raw` is canonical, not the original octets | **Decided.** `xdm` keeps no source offsets. `Raw` is the reference in its SignedInfo's canonicalization, which is what a receipt built on exclusive C14N contains. |
| `SignEnveloped` and `EncryptElement` output is `Inclusive10WithComments` of the document | **Decided.** This module has no serializer and should not grow one; canonical form re-parses to the same tree. The XML declaration is dropped. |
| No `dsig/transform` sub-package or transform registry | **Decided.** The transform set is closed and small; one switch in `dsig/reference.go` is the whole pipeline. |
| The differential harness is `tests/interop`, not `internal/interop` | **Decided.** The repository keeps harnesses under `tests/`, as go-xml does. |
| Verification completes a reference ending in a node set with Canonical XML 1.0 | **Decided.** The design document made it an error on both sides. The corpus showed 118 of 122 real SMP responses rely on it, as XML-DSig 4.4.3.2 permits; refusing it made the library unusable as an SMP client. Signing stays strict. |
| `ds:X509Data` may carry the subject name, issuer-serial or SKI beside its one certificate | **Decided.** Found by the corpus: 107 real SMP responses carry them. They are ignored for key selection. |
| No `xenc/encrypt.go` and `decrypt.go` split | **Decided.** Split by mechanism instead: key transport, data cipher, cipher reference. |
