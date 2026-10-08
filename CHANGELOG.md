# Changelog

Notable changes, newest first. Versions follow [semantic
versioning](https://semver.org): within v1 no exported name is removed or
changed. See [RELEASE.md](RELEASE.md) for the compatibility promise and how a
release is cut.

## Unreleased

### Changed

| Change | Why | Commit |
|---|---|---|
| `go-xml` v1.4.0 → v1.6.0 | Security-relevant, per RELEASE.md. Canonicalization: Exclusive C14N no longer renders a namespace node an XPath filter removed (Exc-C14N §1.1), which only the opt-in XPath transforms reach; no other canonical output changed, and the interop suite, the W3C vectors and the real-message corpus are unchanged. Parsing: a new tokeniser replaces the `encoding/xml` fork, refusing 20 not-well-formed documents it accepted and accepting 16 well-formed ones it refused, so `xmlsec.Parse` is stricter on malformed input and more complete on DTD edge cases (DOCTYPE stays refused). The Go floor is unchanged: `go-xml` still needs 1.25. | *this commit* |

## v1.2.1 — 2026-09-28

### Tested

| Change | Commit |
|---|---|
| Canonical XML 1.1 compared against xmlsec1 and Santuario: whole documents both ways, and byte-identical signatures over a subset whose ancestors carry `xml:base`, `xml:lang`, `xml:space` and `xml:id`. Found a Santuario 4.0.4 divergence: with two omitted ancestors carrying `xml:base` it joins only one; this library agrees with xmlsec1 and C14N 1.1 §2.4, and a test keeps the divergence visible. | [`663bfe5`][663bfe5] |

## v1.2.0 — 2026-09-28

### Added

| Change | What it does | Commit |
|---|---|---|
| Explicit IDs for reproducible output | `wss.AssignIDWith`, `Header.AddBinarySecurityTokenWithID`, `AddTimestampWithID` and `AddSignatureConfirmationWithID` take the caller's ID instead of minting one: with every ID and the clock supplied, a signed AS4 message is byte-identical from run to run, for golden files and differentials against other implementations. No package state; the minting functions share the same path. | [`cf8c78b`][cf8c78b] |
| `Coverage.CoversNodes` | Checks covered elements by node identity. `Covers`, an ID check, is satisfied by a signature-wrapped document when the application then finds the element by position; its documentation now says so, and says when `CoversAttachments` is safe. | [`cf8c78b`][cf8c78b] |

### Documented

| Change | Commit |
|---|---|
| The Go 1.26 floor: `go-xml` needs 1.25, and `rsa.EncryptOAEPWithOptions`, for an MGF digest unlike the OAEP digest, needs 1.26 (RELEASE.md). `KeyTransportRSAOAEP` is the one to use; `KeyTransportRSAOAEPMGF1P` is the decryption-only 1.0 algorithm. | [`cf8c78b`][cf8c78b], [`cb813c1`][cb813c1] |
| Canonicalization: what `go-xml/c14n` measures (the W3C C14N 1.1 interop cases, the Recommendations' examples, differentials against `xmllint` and `xmlsec1`), what this module checks independently, and that Canonical XML 1.1 is compared against no other implementation here (docs/testing.md). | [`afb42a1`][afb42a1] |

## v1.1.0 — 2026-09-26

Every requirement of the implemented specifications that v1.0.0 left out,
found by a clause-by-clause audit of XML Signature 1.1, XML Encryption 1.1,
SOAP Message Security 1.1.1, the X.509 Token and SwA profiles and BSP 1.1.
Every new feature is an opt-in; the few changes to what a v1.0.0 caller sees
are listed under Changed.

### Added

| Change | What it does | Commit |
|---|---|---|
| XPath, XPath Filter 2.0 and XSLT transforms as opt-ins | `dsig.Sign` produces them from `TransformSpec.XPath`, `XPathNamespaces`, `XPathFilters` (`dsig.XPathFilter`) and `Stylesheet`. `dsig.Verify` evaluates them only for programs in `VerifyOptions.AllowedXPathExpressions` (`dsig.XPathExpression`) or `AllowedXSLTStylesheets` (exact text, prefix bindings checked, compiled from the allow-list; stylesheets matched under Exclusive C14N), refusing anything else with `ErrTransformRefused` before any cryptographic work. `here()` supported; XSLT sandboxed with no resolvers and bounded output; `Coverage` drops any target a filter partly removed, and XSLT output covers nothing. Byte-identical transform output with Santuario; `here()` verified by xmlsec1. | [`13a61dc`][13a61dc] |
| External URI dereferencing through a caller resolver | `xmlsec.URIResolver`, passed as `dsig.SignOptions.ResolveURI`, `dsig.VerifyOptions.ResolveURI` or `xenc.DecryptOptions.ResolveURI`, supplies the octets of an absolute non-`cid:` URI in a `ds:Reference` or `xenc:CipherReference` (XML Signature §4.4.3.1); the library still never fetches. On verification it is called only after the allow-lists, `TrustKey` and the signature value pass; external references are reported in `Coverage.ExternalURIs`; errors wrap the new `xmlsec.ErrDereference`. Relative URIs resolve only against a caller's `BaseURI` (below). | [`57349cb`][57349cb] |
| PKCS7 binary security tokens | `xmlsec.BSTValueTypePKCS7`: `AddBinarySecurityToken` emits a DER certs-only PKCS#7 SignedData; `ParseBinarySecurityToken`, token references and `dsig.Verify` read one strictly (SignedData v1, data content, X.509 only, at most 16 certificates; CRLs and signer infos ignored) and return the one certificate that issued none of the others, or `ErrUnsupportedKeyInfo`. Byte-identical to OpenSSL `crl2pkcs7` and the JDK's PKCS#7 encoder. | [`bec715d`][bec715d] |
| Finite-field Diffie-Hellman and PBKDF2 (XML Encryption 1.1 §5.6.2, §5.4.2) | `xenc.DecryptAgreedKeyDH`, `DHPublicKey`, `DHPrivateKey`, `GenerateDHKey` and `EncryptOptions.RecipientDH`/`RecipientKeyName` add `dh-es` and the legacy `dh` (`xmlsec.KeyAgreementDHES`, `KeyAgreementDH`) in groups of `xenc.MinDHBits` to `MaxDHBits` (2048–8192 bits) with subgroup validation; `UnwrapEncryptedKeyPassword` and `EncryptOptions.Password`/`PBKDF2Iterations` (default `xenc.DefaultPBKDF2Iterations`) add PBKDF2 (`xmlsec.KeyDerivationPBKDF2`), also usable as a key agreement's KDF, with received iteration counts bounded to `MinPBKDF2Iterations`–`MaxPBKDF2Iterations` (1000–10,000,000) before any work. New `DecryptOptions.AllowedKeyDerivationAlgorithms` (default ConcatKDF) and `AllowedPRFAlgorithms`; none of the new algorithms is in a default set. Checked against xmlsec1 in both directions. | [`6736ffd`][6736ffd] |
| XML Signature structures and HMAC generation | `SignOptions.Objects` (`dsig.Object`; enveloping signatures, with a nil document) and `Properties` (`dsig.SignatureProperty`, in `ds:SignatureProperties`); `SignedInfoID`, `SignatureValueID`, `KeyInfoID`, with `KeyInfo` and Objects built before digesting so a reference can sign them; a signature's own Object, KeyInfo, Manifest and SignatureProperty Ids resolve without `IDAttrDSig`; `BuildManifest` and `VerifyManifest` (`xmlsec.TypeManifest`, `SignOptions.ManifestID`), which refuses a Manifest the signature does not cover; `CanonicalizationPrefixes`; `Reference.OmitURI` with `OmittedURIData`; `BaseURI` on Sign and Verify for relative URIs, never `xml:base`; HMAC-SHA224/256/384/512 produced with `HMACKey` and `HMACOutputLength`; `VerifyOptions.RequireNFC`. Interop with Santuario and xmlsec1. | [`1eb3aaa`][1eb3aaa] |
| XML Signature `KeyInfo` forms and algorithms | `ds:KeyName` (`Coverage.KeyName`, `ResolveKeyName` when alone); `X509Data` chains of up to 16 with one leaf (`Coverage.Intermediates`), `X509CRL` (`Coverage.CRLs`), `X509IssuerSerial`, `X509SKI`, `X509SubjectName` and `dsig11:X509Digest`, checked against the carried certificates under `StrictX509Data` and resolved through `ResolveX509` (`dsig.X509Identifier`) when no certificate is carried; same-document `RetrievalMethod`, one hop; `rawX509Certificate` and external `KeyInfoReference` through `ResolveKeyInfoURI`; DER-encoded DSA keys. Sign: `KeyName`, `Chain`, `X509Descriptors` (`dsig.X509Descriptor`), `KeyInfoReferenceURI`, and the forms `KeyInfoKeyName`, `KeyInfoX509Descriptors` and `KeyInfoReference`. Algorithms: `xmlsec.DigestSHA224`, `SigRSASHA224`, `SigECDSASHA224` and `SigHMACSHA224`, outside the default sets; `SigDSASHA256` and `SigECDSASHA1`, verification only. | [`51d76cc`][51d76cc] |
| XML Encryption data side | `EncryptOctets` for arbitrary octets with `Type`, `MimeType` and `Encoding`, inline or by `CipherReference` (`EncryptOptions.CipherReferenceURI`); `DecryptAndReplace`, including an `EncryptedData` that is the document element; `EncryptionProperties`; `DecryptOptions.BaseURI` for relative `CipherReference` URIs; `DecryptOptions.AllowedXPathExpressions` for XPath then base64 on a `CipherReference`, checked before `ResolveURI` and any decryption. `SetKeyInfo` and `AddDataReference` place children in schema order. | [`11aa01d`][11aa01d] |
| XML Encryption `KeyInfo` forms | an `EncryptedKey` with a `CipherReference`; `FindEncryptedKey` on an `EncryptedKey`, `KeyReference` and `EncryptedKey.AddKeyReference`; `TypeDerivedKey`, `FindDerivedKey`, `DeriveKey` and `EncryptOptions.MasterKey`, `MasterKeyName` and `DerivedKeyName`; `DecryptAgreedDataKey`, `DecryptAgreedDataKeyDH` and `EncryptOptions.DirectKeyAgreement`; `KA-Nonce` beside ECDH-ES and `dh-es` accepted and ignored; `DecryptOptions.ImpliedDataAlgorithm`, `ImpliedKeyWrapAlgorithm` and `ImpliedKeyTransportAlgorithm` for an absent `EncryptionMethod`; `xmlsec.MGF1SHA224`, opt-in on receipt. | [`bf72db6`][bf72db6] |
| WS-Security symmetric binding and decryption | `EncryptOptions.DataKeyInfo`, `wss.NewReferenceList`, `xenc.ReferencedData`, `xenc.DecryptHeader`; `FindEncryptedKey` follows a `wsse:SecurityTokenReference` to an `EncryptedKey`; `DecryptOptions.StrictBSP` (R3209, R5622, R5623, R5602, R5424, R5426, R3228, R5629, before any key is used); `xmlsec.ErrDecryptionFailed`, wrapped by every decryption and unwrap failure; `EncryptHeader` generates an Id when `DataID` is empty; an `EncryptedKey` reference carries `wsse11:TokenType`. WSS4J interop both ways. | [`996144a`][996144a] |
| WS-Security conformance | STR Dereference Transform (`xmlsec.TransformSTR`, `ResolveSecurityToken`, `Coverage.SignedTokens`); key identifier and issuer-serial `KeyInfo` (`SignOptions.KeyInfoElement`); `wsse:Embedded` and `wss.ReferencedToken`; `EncryptedKey` references by Id and `EncryptedKeySHA1` (`NewEncryptedKeyReference`, `NewEncryptedKeySHA1Reference`, `MatchEncryptedKeySHA1`); `SignatureConfirmation` (`AddSignatureConfirmation`, `SignatureValues`, `CheckSignatureConfirmations`); `FindHeader`, `FindTimestamp`, `CheckUniqueIDs`, `CheckSecurityTokenReference`; `wss.FaultCode` with `xmlsec.ErrInvalidSecurityToken` and `ErrSecurityTokenUnavailable`; `VerifyOptions.StrictBSP`. Byte-identical STR transform output with WSS4J. | [`caaf44e`][caaf44e] |
| `VerifyOptions.StrictX509Data` | Refuses an `X509IssuerSerial`, `X509SKI`, `X509SubjectName` or `dsig11:X509Digest` beside the carried certificates that describes none of them (XML Signature §4.5.4). Off by default, as in v1.0.0: a real PEPPOL SMP response carries an `X509SubjectName` left stale by a certificate renewal, which Santuario also accepts. | [`7a6a367`][7a6a367] |

### Changed

| Change | Why | Commit |
|---|---|---|
| `Sign` refuses content not in Unicode Normalization Form C with `ErrNotNFC`, whose message now reads "not in Unicode Normalization Form C" | XML Signature §8.1.3: every document a signature application generates MUST be in NFC. | [`1eb3aaa`][1eb3aaa] |
| `Sign` refuses the base64 transform after an SwA attachment transform | SwA profile §5.4.4 and BSP R6101: attachment references MUST NOT carry base64 or transfer-encoding transforms. | [`caaf44e`][caaf44e] |
| `wss.AssignID` returns an element's existing `xml:id` instead of adding a `wsu:Id` | SOAP Message Security §4: an element MUST NOT carry both. | [`caaf44e`][caaf44e] |
| An enveloped-signature transform over a node set parsed from octets is `ErrMalformed` | XML Signature §6.6.4: it applies only to a node set from the signature's own document; it used to do nothing. | [`1eb3aaa`][1eb3aaa] |
| A few refusals changed kind: an XPath transform with an expression is `ErrTransformRefused` (was `ErrMalformed`); a PBKDF2 key derivation under the default lists is `ErrAlgorithmNotAllowed` (was `ErrUnsupportedAlgorithm`) | Each now names what the caller can change: the allow-list. | [`13a61dc`][13a61dc], [`6736ffd`][6736ffd] |

## v1.0.0 — 2026-09-26

First release.

### Added

| Change | What it does | Commit |
|---|---|---|
| Root package `xmlsec` | Algorithm and namespace URI constants, sentinel errors, `Attachment` and `AttachmentSet` with RFC 2392 percent-decoding, `KeyProvider`, and `Parse` — the one pinned set of parse options verification runs against: DOCTYPE refused, no entity resolver, depth 1000, 64 MB, 10M nodes, and `c14n.MaxDepth` set to 500 explicitly. | [`9756c04`][9756c04] |
| Package `wss` | `wsse:Security` header construction for SOAP 1.1 and 1.2, `BinarySecurityToken` (X509v3 and X509PKIPathv1), direct-reference `SecurityTokenReference`, `wsu:Timestamp`, `AssignID`, and `FindByID`, which returns `ErrAmbiguousID` on a duplicated ID rather than the first match. | [`9756c04`][9756c04] |
| Package `dsig` | XML Signature generation (`Sign` for detached WS-Security signatures, `SignEnveloped` for whole-document ones) and verification with `Coverage`, derived from what each reference actually digested. `ds:SignedInfo` is canonicalized in place in the received tree. Allow-lists are checked before any cryptographic work; XSLT and XPath transforms are refused; `c14n.ErrXML11` and `c14n.ErrRelativeNamespaceURI` surface as `ErrUnverifiable`. RSA PKCS#1 v1.5 and ECDSA (raw `r‖s`) at SHA-256/384/512. | [`9756c04`][9756c04] |
| Package `xenc` | RSA-OAEP key transport with an explicit `xenc11:MGF` and `ds:DigestMethod` (an implicit SHA-1 MGF or digest is refused on decryption), AES-GCM for inline `EncryptedData` and for SwA attachments by `CipherReference`. | [`6debe01`][6debe01] |
| Differential against `xmlsec1` 1.3, `tests/interop` | Signatures (enveloped and detached, RSA and ECDSA, inclusive and exclusive) and encryption, both directions, with a tamper control. In CI through `tests/interop-xmlsec1.sh`, an Alpine container, since xmlsec 1.2 lacks XML Encryption 1.1 `rsa-oaep`. | [`1fe34f8`][1fe34f8] |
| Fuzz targets `FuzzVerify`, `FuzzDecryptEncryptedKey`, `FuzzDecryptData` | Nightly workflow, one hour per target. Mutated signatures are re-signed so reference and transform code is reached, not only the signature check. | [`1fe34f8`][1fe34f8] |
| Error-path tests across every package | Coverage from 47–77% to 96.6–100% per package; tests live beside the source file they exercise. | [`1fe34f8`][1fe34f8] |
| Security assessment and `tests/security` | XXE (every entity, DTD and encoding variant), external fetches at parse and at verification with an authentic signature, key substitution, algorithm confusion, comment truncation and encryption downgrade, each a regression test run on every push. Parse memory and verification cost measured and documented in `docs/security.md`. | [`9279afe`][9279afe] |
| README rewritten for a public reader; runnable examples | It led with internal design-document terms and its examples did not compile. It now says what the library does, lists the supported algorithms and the rules for verifying safely, and its quick start comes from `Example_enveloped` and `Example_wsSecurity`, which `go test` compiles and runs. | [`f2211c5`][f2211c5] |
| Differential against Apache Santuario 4.0.4 | `tests/santuario/Harness.java` drives Santuario; signatures and encryption in both directions, and `SignatureValue` byte equality with Santuario for enveloped (inclusive and exclusive C14N) and WS-Security signatures. `tests/interop.sh` runs both reference implementations in one image. | [`a7e1839`][a7e1839] |
| `staticcheck` and `gosec` in CI | Both clean, versions pinned, no suppressions. | [`a7e1839`][a7e1839] |
| Test data documented | `docs/testing.md` lists every key, document, reference implementation and corpus the tests use, and where each comes from. | [`a7e1839`][a7e1839] |
| WSS4J 4.0.1 in the differential | It processes a WS-Security header built by this library with Basic Security Profile enforcement on, and decrypts our encryption. | [`379ba85`][379ba85] |
| `EncryptedKey.SetKeyInfo`, `EncryptedKey.AddDataReference`, `EncryptOptions.DataID` | Compose an `EncryptedKey` the way a WS-Security receiver finds it: a `ds:KeyInfo` naming the recipient's key, and an `xenc:ReferenceList` naming each `EncryptedData` by its `Id`. Without them WSS4J could not decrypt our output. | [`379ba85`][379ba85] |
| `VerifyOptions.TrustKey` | A callback that sees the signer's key, and certificate when there is one, before any cryptographic or digest work, refusing with `ErrUntrusted`. Closes the pre-trust verification cost found by the security assessment. | [`a5b66ba`][a5b66ba] |
| `VerifyOptions.RequireExplicitCanonicalization` | Refuses a reference relying on the implied Canonical XML 1.0 even when that algorithm is allowed, for profiles that name their canonicalization. | [`ae38a45`][ae38a45] |
| `xmlsec.ParseWithLimits` | Parses under tighter byte, depth and node limits; limits can only be tightened. Exceeding any limit is now `ErrLimitExceeded` from both `Parse` and `ParseWithLimits`. | [`ae38a45`][ae38a45] |
| Golden files, `wss/golden_test.go` | Byte-exact expected output for a signed SOAP envelope with two attachments, a signed-then-encrypted envelope (ciphertext masked, plaintext compared), and two enveloped signatures. Regenerated only with `-update`; LF on every system; a committed test-only key makes them reproducible. | [`c7a3361`][c7a3361] |
| `SignOptions.IDAttributes`, `VerifyOptions.IDAttributes`, extra attributes for `wss.FindByID` | Opt-in extra ID attributes for `"#id"` references, with `dsig.IDAttrSAML` (`ID`) and `dsig.IDAttrDSig` (`Id`), so SAML assertions and XAdES documents can be signed and verified. Duplicate detection spans every counted attribute; the default is unchanged. Santuario interoperates, byte-identical. | [`c6b1e46`][c6b1e46] |
| W3C XML Signature 1.1 interop vectors, `tests/w3c` | 25 third-party vectors in a nested module, so they stay out of the library's module download, with the W3C Document License and notice beside them. Run in CI on all three systems. | [`c37f1e9`][c37f1e9] |
| Raw public keys in `ds:KeyInfo` | `ds:KeyValue` (RSA, and XML Signature 1.1 `ECKeyValue` on P-256/384/521) and `dsig11:DEREncodedKeyValue`, verified and emitted (`KeyInfoKeyValue`, `KeyInfoDEREncodedKeyValue`). `VerifyOptions.PublicKey` pins a raw key; `Coverage.PublicKey` reports the key used, and `Coverage.Certificate` is nil for a raw key. Raw RSA keys under 2048 bits are refused. 10 of the 25 W3C interop vectors now verify. | [`d39fb55`][d39fb55] |
| SwA signature transforms and Attachment-Complete encryption | `TransformAttachmentContentSignature` and `TransformAttachmentCompleteSignature`, with the SwA profile's MIME header and content canonicalization (section 5.4), and Attachment-Complete encryption. Interoperable with WSS4J in both directions for both. | [`83a4f89`][83a4f89] |
| `SignOptions.Parent`: in-place signing | XML Signature allows any canonicalization of `ds:SignedInfo`, but a detached signature is canonicalized before it is placed, so `Sign` refused inclusive canonicalization. With `Parent` set, the signature is appended first and computed where it stands, so every canonicalization works; Santuario verifies an in-place inclusive signature. Closes a drift from the XML Signature specification. | [`dd64026`][dd64026] |
| XML Signature 1.1 conformance | Refuses RSA signing keys under 2048 bits and non-NCName ids; the base64 transform over a node set; octets parsed into a node set before a canonicalization; `#xpointer(/)` and `#xpointer(id('…'))` keeping comments; same-document `KeyInfoReference`; `VerifyOptions.ResolveOmittedURI` and `Coverage.OmittedURISigned`; a pinned key ignores an unsupported `KeyInfo`. Allow-lists default to a named default set. | [`4c0b0c5`][4c0b0c5] |
| XML Encryption 1.1 conformance | `cid:` URIs escaped; NFC plaintext (`ErrNotNFC`); NCName ids; `xmlns=""` kept on encrypted elements; strict `EncryptionMethod`; `CipherReference` transforms checked, and same-document `CipherReference` with base64; `FindEncryptedKey`; `EncryptContent`; `EncryptHeader` (`wsse11:EncryptedHeader`); AES key wrap and ECDH-ES with ConcatKDF, interoperable with xmlsec1 and Santuario; generic decryption errors. Breaking: `EncryptedKey.AddDataReference` returns an error. | [`7d59007`][7d59007] |
| WS-Security 1.1.1 conformance | `Header.Prepend` and processing-order placement, so sign-then-encrypt is accepted by WSS4J; SOAP attributes namespaced on default-namespace envelopes; `wsse11:TokenType`; ds/xenc elements get their own `Id`; one timestamp; `ParseTimestamp` and `Timestamp.Check` (`ErrMessageExpired`); key identifier and issuer-serial references; `ResolveSecurityTokenReferenceStrict`, `MatchSecurityTokenReference`, and `VerifyOptions.StrictSecurityTokenReference`. | [`091298e`][091298e] |
| Legacy XML Signature algorithms, verification only | SHA-1 digest, RSA-SHA1, DSA-SHA1 with `DSAKeyValue`, HMAC-SHA1/256/384/512, as the specification requires; accepted only when named in an allow-list, never produced by `Sign`. `VerifyOptions.HMACKey` is the only HMAC key; `HMACOutputLength` is checked against CVE-2009-0217. An allow-list naming an unimplemented algorithm no longer panics. | [`b3ad29a`][b3ad29a] |
| Legacy XML Encryption algorithms, decryption only | AES-CBC, 3DES, `rsa-oaep-mgf1p` and SHA-1 OAEP digest/MGF, RSA v1.5 (`xenc.DecryptEncryptedKeyPKCS1v15`, implicit rejection), and `kw-tripledes` unwrap; accepted only when named, never produced. CBC failures share one error and a constant-time padding check. | [`3cb030f`][3cb030f] |
| Versioning, CI and release workflow | `internal/version.Version` as the source of truth, checked against this file on every CI run and against the tag on release. CI on Linux, macOS and Windows; hygiene checks for `peppol` imports and strings. | [`2281ef3`][2281ef3] |

### Fixed

| Change | Problem → solution | Commit |
|---|---|---|
| 13 exported functions panicked on a nil argument | Found by the security assessment. A caller passing on a failed lookup from a hostile message (no `EncryptedKey`, no token) crashed rather than got an error. Every exported function now returns an error for nil or wrong-kind input. | [`9279afe`][9279afe] |
| `Exclusive10WithComments` transform always failed | The plain algorithm was derived by trimming `#WithComments` from the URI, which leaves `…xml-exc-c14n` where the plain URI is `…xml-exc-c14n#`, so signing or verifying such a reference failed with an unsupported algorithm. Found by the error-path tests. The plain form now comes from an explicit map of `c14n` constants, and the ECDSA check from an explicit set of `Sig*` constants: no algorithm URI is derived from strings. | [`1fe34f8`][1fe34f8] |
| A failed `NewHeader`, `AddBinarySecurityToken` or `AddTimestamp` left a half-built element in the document | The element was attached before a namespace check that could fail. Each is now built detached, declares its own prefix and is attached last, so a `wsu` or `wsse` prefix bound elsewhere in the document is no longer an error at all. | [`1fe34f8`][1fe34f8] |
| `TestEncryptElement` was flaky | It asserted the output did not contain `hi`, which random base64 ciphertext sometimes does. Found by the fuzzing run. | [`1fe34f8`][1fe34f8] |

### Changed

| Change | Why | Commit |
|---|---|---|
| **Breaking:** API review before v1 | `xenc`'s positional allow-list arguments become one `xenc.DecryptOptions`, named like `dsig.VerifyOptions`, so a future option is not a breaking change. The namespace constants, `TransformAttachmentCiphertext`, `DigestSHA384XMLEnc` and `ErrNotNFC` move to the root package, where each is defined once (`NSDSig` was in both `dsig` and `xenc`). `KeyInfoSpec` becomes `KeyInfoForm`, the name of the `Coverage` field it reports. `wss.FindByIDAttributes` folds into a variadic `wss.FindByID`. `Attachment.MIMEHeaders` is a `textproto.MIMEHeader`. Removed: the unused `KeyProvider.Decrypter` and `Chain`, and `SignatureHash`, `DigestHash` and `MGFHash`, now internal. | [`7a8061b`][7a8061b] |
| **Breaking:** `#Attachment-Content-Only` and `#Attachment-Complete` are refused as signature transforms | They are the SwA profile's `EncryptedData` Type URIs. WSS4J refuses them in a signature, so attachment signatures made with them were rejected by every WS-Security peer. Sign attachments with `TransformAttachmentContentSignature`. | [`e4c7509`][e4c7509] |
| **Breaking:** `xenc.DecryptAttachment` returns `*xmlsec.Attachment` | Attachment-Complete decryption restores the MIME headers along with the body. | [`83a4f89`][83a4f89] |
| Verification completes a reference that ends in a node set with Canonical XML 1.0 | XML-DSig 4.4.3.2 requires it, and a corpus of 122 real Peppol SMP responses showed 118 rely on it: before this, 60 of 62 SMP providers' signatures were refused. The implied algorithm is checked against the caller's allow-list. Signing still never relies on it. | [`cc53cf7`][cc53cf7] |
| `ds:X509Data` may carry `X509SubjectName`, `X509IssuerSerial` and `X509SKI` beside its one certificate | 107 of the same responses carry them. They are ignored; the key always comes from the certificate. With both changes, all 122 SMP responses verify. | [`cc53cf7`][cc53cf7] |
| An HMAC signature method is reported as `ErrAlgorithmNotAllowed` | It was reported as malformed, because its `HMACOutputLength` child was checked before the allow-list. | [`cc53cf7`][cc53cf7] |
| Unreachable error branches deleted | `crypto/rand.Read` never returns an error since Go 1.24; a detached element's own namespace declaration cannot conflict, so `wss` declares it directly; a hand-written `indexOf` is `slices.Index`. | [`169fc0c`][169fc0c] |
| 100% statement coverage, enforced in CI | `aes.NewCipher` now runs before the algorithm's size check, so both are reachable. `dsig.Verify` canonicalizes each `ds:Reference` for `Coverage.Raw` before `ds:SignedInfo`, so each failure point has an input that reaches it. | [`e90defe`][e90defe] |
| Minimum Go is 1.26, not 1.25 | `rsa.EncryptOAEPWithOptions`, the only standard-library route to an OAEP digest and MGF1 hash that differ, arrived in Go 1.26. | [`6debe01`][6debe01] |

[9756c04]: https://github.com/knroy/go-xmlsec/commit/9756c04
[6debe01]: https://github.com/knroy/go-xmlsec/commit/6debe01
[2281ef3]: https://github.com/knroy/go-xmlsec/commit/2281ef3
[169fc0c]: https://github.com/knroy/go-xmlsec/commit/169fc0c
[1fe34f8]: https://github.com/knroy/go-xmlsec/commit/1fe34f8
[9279afe]: https://github.com/knroy/go-xmlsec/commit/9279afe
[f2211c5]: https://github.com/knroy/go-xmlsec/commit/f2211c5
[a7e1839]: https://github.com/knroy/go-xmlsec/commit/a7e1839
[379ba85]: https://github.com/knroy/go-xmlsec/commit/379ba85
[a5b66ba]: https://github.com/knroy/go-xmlsec/commit/a5b66ba
[ae38a45]: https://github.com/knroy/go-xmlsec/commit/ae38a45
[c7a3361]: https://github.com/knroy/go-xmlsec/commit/c7a3361
[c6b1e46]: https://github.com/knroy/go-xmlsec/commit/c6b1e46
[c37f1e9]: https://github.com/knroy/go-xmlsec/commit/c37f1e9
[d39fb55]: https://github.com/knroy/go-xmlsec/commit/d39fb55
[83a4f89]: https://github.com/knroy/go-xmlsec/commit/83a4f89
[dd64026]: https://github.com/knroy/go-xmlsec/commit/dd64026
[4c0b0c5]: https://github.com/knroy/go-xmlsec/commit/4c0b0c5
[7d59007]: https://github.com/knroy/go-xmlsec/commit/7d59007
[091298e]: https://github.com/knroy/go-xmlsec/commit/091298e
[b3ad29a]: https://github.com/knroy/go-xmlsec/commit/b3ad29a
[3cb030f]: https://github.com/knroy/go-xmlsec/commit/3cb030f
[7a8061b]: https://github.com/knroy/go-xmlsec/commit/7a8061b
[e4c7509]: https://github.com/knroy/go-xmlsec/commit/e4c7509
[cc53cf7]: https://github.com/knroy/go-xmlsec/commit/cc53cf7
[e90defe]: https://github.com/knroy/go-xmlsec/commit/e90defe
[13a61dc]: https://github.com/knroy/go-xmlsec/commit/13a61dc
[57349cb]: https://github.com/knroy/go-xmlsec/commit/57349cb
[bec715d]: https://github.com/knroy/go-xmlsec/commit/bec715d
[6736ffd]: https://github.com/knroy/go-xmlsec/commit/6736ffd
[1eb3aaa]: https://github.com/knroy/go-xmlsec/commit/1eb3aaa
[51d76cc]: https://github.com/knroy/go-xmlsec/commit/51d76cc
[11aa01d]: https://github.com/knroy/go-xmlsec/commit/11aa01d
[bf72db6]: https://github.com/knroy/go-xmlsec/commit/bf72db6
[996144a]: https://github.com/knroy/go-xmlsec/commit/996144a
[caaf44e]: https://github.com/knroy/go-xmlsec/commit/caaf44e
[7a6a367]: https://github.com/knroy/go-xmlsec/commit/7a6a367
[cf8c78b]: https://github.com/knroy/go-xmlsec/commit/cf8c78b
[cb813c1]: https://github.com/knroy/go-xmlsec/commit/cb813c1
[afb42a1]: https://github.com/knroy/go-xmlsec/commit/afb42a1
[663bfe5]: https://github.com/knroy/go-xmlsec/commit/663bfe5
