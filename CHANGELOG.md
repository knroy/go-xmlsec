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
| Root package `xmlsec` | Algorithm and namespace URI constants, sentinel errors, `Attachment` and `AttachmentSet` with RFC 2392 percent-decoding, `KeyProvider`, and `Parse` — the one pinned set of parse options verification runs against: DOCTYPE refused, no entity resolver, depth 1000, 64 MB, 10M nodes, and `c14n.MaxDepth` set to 500 explicitly. | [`9756c04`][9756c04] |
| Package `wss` | `wsse:Security` header construction for SOAP 1.1 and 1.2, `BinarySecurityToken` (X509v3 and X509PKIPathv1), direct-reference `SecurityTokenReference`, `wsu:Timestamp`, `AssignID`, and `FindByID`, which returns `ErrAmbiguousID` on a duplicated ID rather than the first match. | [`9756c04`][9756c04] |
| Package `dsig` | XML Signature generation (`Sign` for detached WS-Security signatures, `SignEnveloped` for whole-document ones) and verification with `Coverage`, derived from what each reference actually digested. `ds:SignedInfo` is canonicalized in place in the received tree. Allow-lists are checked before any cryptographic work; XSLT and XPath transforms are refused; `c14n.ErrXML11` and `c14n.ErrRelativeNamespaceURI` surface as `ErrUnverifiable`. RSA PKCS#1 v1.5 and ECDSA (raw `r‖s`) at SHA-256/384/512. | [`9756c04`][9756c04] |
| Package `xenc` | RSA-OAEP key transport with an explicit `xenc11:MGF` and `ds:DigestMethod` (an implicit SHA-1 MGF or digest is refused on decryption), AES-GCM for inline `EncryptedData` and for SwA attachments by `CipherReference`. | [`6debe01`][6debe01] |
| Differential against `xmlsec1` 1.3, `tests/interop` | Signatures (enveloped and detached, RSA and ECDSA, inclusive and exclusive) and encryption, both directions, with a tamper control. In CI through `tests/interop-xmlsec1.sh`, an Alpine container, since xmlsec 1.2 lacks XML Encryption 1.1 `rsa-oaep`. | *this commit* |
| Fuzz targets `FuzzVerify`, `FuzzDecryptEncryptedKey`, `FuzzDecryptData` | Nightly workflow, one hour per target. Mutated signatures are re-signed so reference and transform code is reached, not only the signature check. | *this commit* |
| Error-path tests across every package | Coverage from 47–77% to 96.6–100% per package; tests live beside the source file they exercise. | *this commit* |
| Security assessment and `tests/security` | XXE (every entity, DTD and encoding variant), external fetches at parse and at verification with an authentic signature, key substitution, algorithm confusion, comment truncation and encryption downgrade, each a regression test run on every push. Parse memory and verification cost measured and documented in `docs/security.md`. | *this commit* |
| README rewritten for a public reader; runnable examples | It led with internal design-document terms and its examples did not compile. It now says what the library does, lists the supported algorithms and the rules for verifying safely, and its quick start comes from `Example_enveloped` and `Example_wsSecurity`, which `go test` compiles and runs. | *this commit* |
| Differential against Apache Santuario 4.0.4 | `tests/santuario/Harness.java` drives Santuario; signatures and encryption in both directions, and `SignatureValue` byte equality with Santuario for enveloped (inclusive and exclusive C14N) and WS-Security signatures. `tests/interop.sh` runs both reference implementations in one image. | *this commit* |
| `staticcheck` and `gosec` in CI | Both clean, versions pinned, no suppressions. | *this commit* |
| Test data documented | `docs/testing.md` lists every key, document, reference implementation and corpus the tests use, and where each comes from. | *this commit* |
| WSS4J 4.0.1 in the differential | It processes a WS-Security header built by this library with Basic Security Profile enforcement on, and decrypts our encryption. Acceptance criteria 4 and 6. | *this commit* |
| `EncryptedKey.SetKeyInfo`, `EncryptedKey.AddDataReference`, `EncryptOptions.DataID` | Compose an `EncryptedKey` the way a WS-Security receiver finds it: a `ds:KeyInfo` naming the recipient's key, and an `xenc:ReferenceList` naming each `EncryptedData` by its `Id`. Without them WSS4J could not decrypt our output. | *this commit* |
| `VerifyOptions.TrustKey` | A callback that sees the signer's key, and certificate when there is one, before any cryptographic or digest work, refusing with `ErrUntrusted`. Closes the pre-trust verification cost found by the security assessment. | *this commit* |
| `VerifyOptions.RequireExplicitCanonicalization` | Refuses a reference relying on the implied Canonical XML 1.0 even when that algorithm is allowed, for profiles that name their canonicalization. | *this commit* |
| `xmlsec.ParseWithLimits` | Parses under tighter byte, depth and node limits; limits can only be tightened. Exceeding any limit is now `ErrLimitExceeded` from both `Parse` and `ParseWithLimits`. | *this commit* |
| Golden files, `wss/golden_test.go` | Byte-exact expected output for a signed SOAP envelope with two attachments, a signed-then-encrypted envelope (ciphertext masked, plaintext compared), and two enveloped signatures. Regenerated only with `-update`; LF on every system; a committed test-only key makes them reproducible. | *this commit* |
| `SignOptions.IDAttributes`, `VerifyOptions.IDAttributes`, extra attributes for `wss.FindByID` | Opt-in extra ID attributes for `"#id"` references, with `dsig.IDAttrSAML` (`ID`) and `dsig.IDAttrDSig` (`Id`), so SAML assertions and XAdES documents can be signed and verified. Duplicate detection spans every counted attribute; the default is unchanged. Santuario interoperates, byte-identical. | *this commit* |
| W3C XML Signature 1.1 interop vectors, `tests/w3c` | 25 third-party vectors in a nested module, so they stay out of the library's module download, with the W3C Document License and notice beside them. Run in CI on all three systems. | *this commit* |
| Raw public keys in `ds:KeyInfo` | `ds:KeyValue` (RSA, and XML Signature 1.1 `ECKeyValue` on P-256/384/521) and `dsig11:DEREncodedKeyValue`, verified and emitted (`KeyInfoKeyValue`, `KeyInfoDEREncodedKeyValue`). `VerifyOptions.PublicKey` pins a raw key; `Coverage.PublicKey` reports the key used, and `Coverage.Certificate` is nil for a raw key. Raw RSA keys under 2048 bits are refused. 10 of the 25 W3C interop vectors now verify. | *this commit* |
| SwA signature transforms and Attachment-Complete encryption | `TransformAttachmentContentSignature` and `TransformAttachmentCompleteSignature`, with the SwA profile's MIME header and content canonicalization (section 5.4), and Attachment-Complete encryption. Interoperable with WSS4J in both directions for both. | *this commit* |
| `SignOptions.Parent`: in-place signing | XML Signature allows any canonicalization of `ds:SignedInfo`, but a detached signature is canonicalized before it is placed, so `Sign` refused inclusive canonicalization. With `Parent` set, the signature is appended first and computed where it stands, so every canonicalization works; Santuario verifies an in-place inclusive signature. Closes a drift from the XML Signature specification. | *this commit* |
| XML Signature 1.1 conformance | Refuses RSA signing keys under 2048 bits and non-NCName ids; the base64 transform over a node set; octets parsed into a node set before a canonicalization; `#xpointer(/)` and `#xpointer(id('…'))` keeping comments; same-document `KeyInfoReference`; `VerifyOptions.ResolveOmittedURI` and `Coverage.OmittedURISigned`; a pinned key ignores an unsupported `KeyInfo`. Allow-lists default to a named default set. | *this commit* |
| XML Encryption 1.1 conformance | `cid:` URIs escaped; NFC plaintext (`ErrNotNFC`); NCName ids; `xmlns=""` kept on encrypted elements; strict `EncryptionMethod`; `CipherReference` transforms checked, and same-document `CipherReference` with base64; `FindEncryptedKey`; `EncryptContent`; `EncryptHeader` (`wsse11:EncryptedHeader`); AES key wrap and ECDH-ES with ConcatKDF, interoperable with xmlsec1 and Santuario; generic decryption errors. Breaking: `EncryptedKey.AddDataReference` returns an error. | *this commit* |
| WS-Security 1.1.1 conformance | `Header.Prepend` and processing-order placement, so sign-then-encrypt is accepted by WSS4J; SOAP attributes namespaced on default-namespace envelopes; `wsse11:TokenType`; ds/xenc elements get their own `Id`; one timestamp; `ParseTimestamp` and `Timestamp.Check` (`ErrMessageExpired`); key identifier and issuer-serial references; `ResolveSecurityTokenReferenceStrict`, `MatchSecurityTokenReference`, and `VerifyOptions.StrictSecurityTokenReference`. | *this commit* |
| Legacy XML Signature algorithms, verification only | SHA-1 digest, RSA-SHA1, DSA-SHA1 with `DSAKeyValue`, HMAC-SHA1/256/384/512, as the specification requires; accepted only when named in an allow-list, never produced by `Sign`. `VerifyOptions.HMACKey` is the only HMAC key; `HMACOutputLength` is checked against CVE-2009-0217. An allow-list naming an unimplemented algorithm no longer panics. | *this commit* |
| Legacy XML Encryption algorithms, decryption only | AES-CBC, 3DES, `rsa-oaep-mgf1p` and SHA-1 OAEP digest/MGF, RSA v1.5 (`xenc.DecryptEncryptedKeyPKCS1v15`, implicit rejection), and `kw-tripledes` unwrap; accepted only when named, never produced. CBC failures share one error and a constant-time padding check. | *this commit* |
| Versioning, CI and release workflow | `internal/version.Version` as the source of truth, checked against this file on every CI run and against the tag on release. CI on Linux, macOS and Windows; hygiene checks for `peppol` imports and strings. | [`2281ef3`][2281ef3] |

### Fixed

| Change | Problem → solution | Commit |
|---|---|---|
| 13 exported functions panicked on a nil argument | Found by the security assessment. A caller passing on a failed lookup from a hostile message (no `EncryptedKey`, no token) crashed rather than got an error. Every exported function now returns an error for nil or wrong-kind input. | *this commit* |
| `Exclusive10WithComments` transform always failed | The plain algorithm was derived by trimming `#WithComments` from the URI, which leaves `…xml-exc-c14n` where the plain URI is `…xml-exc-c14n#`, so signing or verifying such a reference failed with an unsupported algorithm. Found by the error-path tests. The plain form now comes from an explicit map of `c14n` constants, and the ECDSA check from an explicit set of `Sig*` constants: no algorithm URI is derived from strings. | *this commit* |
| A failed `NewHeader`, `AddBinarySecurityToken` or `AddTimestamp` left a half-built element in the document | The element was attached before a namespace check that could fail. Each is now built detached, declares its own prefix and is attached last, so a `wsu` or `wsse` prefix bound elsewhere in the document is no longer an error at all. | *this commit* |
| `TestEncryptElement` was flaky | It asserted the output did not contain `hi`, which random base64 ciphertext sometimes does. Found by the fuzzing run. | *this commit* |

### Changed

| Change | Why | Commit |
|---|---|---|
| **Breaking:** API review before v1 | `xenc`'s positional allow-list arguments become one `xenc.DecryptOptions`, named like `dsig.VerifyOptions`, so a future option is not a breaking change. The namespace constants, `TransformAttachmentCiphertext`, `DigestSHA384XMLEnc` and `ErrNotNFC` move to the root package, where each is defined once (`NSDSig` was in both `dsig` and `xenc`). `KeyInfoSpec` becomes `KeyInfoForm`, the name of the `Coverage` field it reports. `wss.FindByIDAttributes` folds into a variadic `wss.FindByID`. `Attachment.MIMEHeaders` is a `textproto.MIMEHeader`. Removed: the unused `KeyProvider.Decrypter` and `Chain`, and `SignatureHash`, `DigestHash` and `MGFHash`, now internal. | *this commit* |
| **Breaking:** `#Attachment-Content-Only` and `#Attachment-Complete` are refused as signature transforms | They are the SwA profile's `EncryptedData` Type URIs. WSS4J refuses them in a signature, so attachment signatures made with them were rejected by every WS-Security peer. Sign attachments with `TransformAttachmentContentSignature`. | *this commit* |
| **Breaking:** `xenc.DecryptAttachment` returns `*xmlsec.Attachment` | Attachment-Complete decryption restores the MIME headers along with the body. | *this commit* |
| Verification completes a reference that ends in a node set with Canonical XML 1.0 | XML-DSig 4.4.3.2 requires it, and a corpus of 122 real Peppol SMP responses showed 118 rely on it: before this, 60 of 62 SMP providers' signatures were refused. The implied algorithm is checked against the caller's allow-list. Signing still never relies on it. | *this commit* |
| `ds:X509Data` may carry `X509SubjectName`, `X509IssuerSerial` and `X509SKI` beside its one certificate | 107 of the same responses carry them. They are ignored; the key always comes from the certificate. With both changes, all 122 SMP responses verify. | *this commit* |
| An HMAC signature method is reported as `ErrAlgorithmNotAllowed` | It was reported as malformed, because its `HMACOutputLength` child was checked before the allow-list. | *this commit* |
| Unreachable error branches deleted | `crypto/rand.Read` never returns an error since Go 1.24; a detached element's own namespace declaration cannot conflict, so `wss` declares it directly; a hand-written `indexOf` is `slices.Index`. | [`169fc0c`][169fc0c] |
| 100% statement coverage, enforced in CI | `aes.NewCipher` now runs before the algorithm's size check, so both are reachable. `dsig.Verify` canonicalizes each `ds:Reference` for `Coverage.Raw` before `ds:SignedInfo`, so each failure point has an input that reaches it. | *this commit* |
| Minimum Go is 1.26, not 1.25 | `rsa.EncryptOAEPWithOptions`, the only standard-library route to an OAEP digest and MGF1 hash that differ, arrived in Go 1.26. | [`6debe01`][6debe01] |

[9756c04]: https://github.com/knroy/go-xmlsec/commit/9756c04
[6debe01]: https://github.com/knroy/go-xmlsec/commit/6debe01
[2281ef3]: https://github.com/knroy/go-xmlsec/commit/2281ef3
[169fc0c]: https://github.com/knroy/go-xmlsec/commit/169fc0c
