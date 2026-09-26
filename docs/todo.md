# TODO

## Not implemented

| Item | Notes |
|---|---|
| `Attachment-Complete` transform, signing and encryption | Refused with `ErrUnsupportedAlgorithm`. Its MIME header canonicalization is easy to get subtly wrong, and no peer has been seen to require it (open item X-6). |
| Interop harness, `internal/interop` | Against `xmlsec1` and Apache Santuario, which must stay two independent implementations. |
| Gate 2 against phase4 | Needs the captured-message corpus (X-5). |
| Golden files, with `-update` | See [testing.md](testing.md#not-tested-yet). |
| Fuzz targets | Malformed `ds:Signature` and `xenc:EncryptedData`, truncated base64, deep namespace nesting. |
| `ds:KeyInfo` on `xenc:EncryptedKey`, and `xenc:ReferenceList` | Not emitted; how a peer identifies the recipient key needs settling against a real profile. |
| SAML `ID` attributes | `FindByID` resolves `wsu:Id` and `xml:id` only. SAML is the likeliest second consumer. |
| `staticcheck` and `gosec` in CI | Acceptance criterion 18. |

## Acceptance criteria not yet met

v1 waits for all of them. Numbers refer to the design document.

| # | Criterion | Now |
|---|---|---|
| 1–2 | `xmlsec1` and Santuario accept our signatures, and we theirs | no harness |
| 3 | Coverage matches phase4's over the real-message corpus | no corpus |
| 4–6 | `xenc` and `wss` output accepted by WSS4J and phase4 | not tested |
| 7 | Gate 2 | not built |
| 12 | Gate 2 on every go-xml bump | not built |
| 16 | one hour per fuzz target, clean | no targets |
| 18 | `staticcheck`, `gosec` clean | not in CI |
| 19 | 85% statement coverage | 47–77% per package |
| 20 | README states the evidence with figures | done, but the figures are self-tests only |

## Open items

| # | Item | Status |
|---|---|---|
| X-1 | Effective DOCTYPE and entity behaviour of the pinned parse | **Closed by test.** A DOCTYPE, with or without entities, is refused. |
| X-2 | `xdm.ElementByID` on duplicate IDs | **Answered** from the v1.4.0 source: it returns the first depth-first match. Not used on the verify path. |
| X-3 | Gate 1 status upstream | go-xml v1.4.0's changelog now reports `xmllint` and `xmlsec1` differentials; the Santuario differential and real-message corpus are still open there. |
| X-4 | AS4 canonicalization URI inherited, not stated | unchanged |
| X-5 | Real-message corpus | unchanged |
| X-6 | Does any peer require `Attachment-Complete`? | unchanged |

## Where the implementation departs from the design document

Each is deliberate. Those not marked **Decided** are flagged for review before
the first tag, since a public API is hard to reshape afterwards.

| Departure | Why |
|---|---|
| Minimum Go 1.26, not 1.25 | **Decided.** `rsa.EncryptOAEPWithOptions` is the only standard-library route to an MGF1 hash that differs from the OAEP digest. |
| `SignOptions.SecurityTokenID` added | `Sign` otherwise has no way to know which token the `SecurityTokenReference` should point at. It is checked to carry the signing certificate. |
| `Sign` refuses inclusive `ds:SignedInfo` canonicalization | The signature is detached when `SignedInfo` is canonicalized; under inclusive canonicalization the result depends on where the caller later places it, so it would never verify. |
| `EncryptAttachment`: the transform argument becomes `EncryptedData/@Type`, and the `CipherReference` carries `Attachment-Ciphertext-Transform` | That is what the SwA profile specifies and what phase4 and WSS4J emit. The design document put the content transform on the `CipherReference`. |
| `Attachment-Content-Only` is the identity even for XML bodies | As designed. **To confirm**: the SwA profile, as WSS4J implements it, canonicalizes attachment content whose MIME type is XML with exclusive C14N. Irrelevant for compressed payloads; an interop failure waiting for an uncompressed XML attachment. |
| `VerifiedReference.Raw` is canonical, not the original octets | `xdm` keeps no source offsets. `Raw` is the reference in its SignedInfo's canonicalization, which is what a receipt built on exclusive C14N contains. |
| `SignEnveloped` and `EncryptElement` output is `Inclusive10WithComments` of the document | This module has no serializer and should not grow one; canonical form re-parses to the same tree. The XML declaration is dropped. |
| No `dsig/transform` sub-package or transform registry | The transform set is closed and small; one switch in `dsig/reference.go` is the whole pipeline. |
| No `xenc/encrypt.go` and `decrypt.go` split | Split by mechanism instead: key transport, data cipher, cipher reference. |
