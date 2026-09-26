# Changelog

Notable changes, newest first. Versions follow [semantic
versioning](https://semver.org). The module stays on **v0** until the
acceptance criteria in [docs/todo.md](docs/todo.md) hold: `v0` says the API may
move and the library has not been independently validated, which is true. See
[RELEASE.md](RELEASE.md) for how a release is cut.

## Unreleased

First implementation. Not yet tagged.

### Added

| Change | What it does | Commit |
|---|---|---|
| Root package `xmlsec` | Algorithm URI constants and hash registries (no SHA-1 anywhere), sentinel errors, `Attachment` and `AttachmentSet` with RFC 2392 percent-decoding, `KeyProvider`, and `Parse` — the one pinned set of parse options verification runs against: DOCTYPE refused, no entity resolver, depth 1000, 64 MB, 10M nodes, and `c14n.MaxDepth` set to 500 explicitly. | [`9756c04`][9756c04] |
| Package `wss` | `wsse:Security` header construction for SOAP 1.1 and 1.2, `BinarySecurityToken` (X509v3 and X509PKIPathv1), direct-reference `SecurityTokenReference`, `wsu:Timestamp`, `AssignID`, and `FindByID`, which returns `ErrAmbiguousID` on a duplicated ID rather than the first match. | [`9756c04`][9756c04] |
| Package `dsig` | XML Signature generation (`Sign` for detached WS-Security signatures, `SignEnveloped` for whole-document ones) and verification with `Coverage`, derived from what each reference actually digested. `ds:SignedInfo` is canonicalized in place in the received tree. Allow-lists are checked before any cryptographic work; XSLT and XPath transforms are refused; `c14n.ErrXML11` and `c14n.ErrRelativeNamespaceURI` surface as `ErrUnverifiable`. RSA PKCS#1 v1.5 and ECDSA (raw `r‖s`) at SHA-256/384/512. | [`9756c04`][9756c04] |
| Package `xenc` | RSA-OAEP key transport with an explicit `xenc11:MGF` and `ds:DigestMethod` (an implicit SHA-1 MGF or digest is refused on decryption), AES-GCM for inline `EncryptedData` and for SwA attachments by `CipherReference`. | [`6debe01`][6debe01] |
| Differential against `xmlsec1` 1.3, `tests/interop` | Signatures (enveloped and detached, RSA and ECDSA, inclusive and exclusive) and encryption, both directions, with a tamper control. In CI through `tests/interop-xmlsec1.sh`, an Alpine container, since xmlsec 1.2 lacks XML Encryption 1.1 `rsa-oaep`. | *this commit* |
| Fuzz targets `FuzzVerify`, `FuzzDecryptEncryptedKey`, `FuzzDecryptData` | Nightly workflow, one hour per target. Mutated signatures are re-signed so reference and transform code is reached, not only the signature check. | *this commit* |
| Error-path tests across every package | Coverage from 47–77% to 96.6–100% per package; tests live beside the source file they exercise. | *this commit* |
| Versioning, CI and release workflow | `internal/version.Version` as the source of truth, checked against this file on every CI run and against the tag on release. CI on Linux, macOS and Windows; hygiene checks for `peppol` imports and strings. | [`2281ef3`][2281ef3] |

### Fixed

| Change | Problem → solution | Commit |
|---|---|---|
| `Exclusive10WithComments` transform always failed | The plain algorithm was derived by trimming `#WithComments` from the URI, which leaves `…xml-exc-c14n` where the plain URI is `…xml-exc-c14n#`, so signing or verifying such a reference failed with an unsupported algorithm. Found by the error-path tests. The plain form now comes from an explicit map of `c14n` constants, and the ECDSA check from an explicit set of `Sig*` constants: no algorithm URI is derived from strings. | *this commit* |
| A failed `NewHeader`, `AddBinarySecurityToken` or `AddTimestamp` left a half-built element in the document | The element was attached before a namespace check that could fail. Each is now built detached, declares its own prefix and is attached last, so a `wsu` or `wsse` prefix bound elsewhere in the document is no longer an error at all. | *this commit* |
| `TestEncryptElement` was flaky | It asserted the output did not contain `hi`, which random base64 ciphertext sometimes does. Found by the fuzzing run. | *this commit* |

### Changed

| Change | Why | Commit |
|---|---|---|
| Minimum Go is 1.26, not 1.25 | `rsa.EncryptOAEPWithOptions`, the only standard-library route to an OAEP digest and MGF1 hash that differ, arrived in Go 1.26. | [`6debe01`][6debe01] |

[9756c04]: https://github.com/knroy/go-xmlsec/commit/9756c04
[6debe01]: https://github.com/knroy/go-xmlsec/commit/6debe01
[2281ef3]: https://github.com/knroy/go-xmlsec/commit/2281ef3
