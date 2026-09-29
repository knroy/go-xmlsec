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
golden-file key and the PKCS#7 fixtures.

| Layer | Where | Runs |
|---|---|---|
| Unit and conformance | `*_test.go` beside each package, named after the source file they test; `internal/swa` holds the SwA MIME header and content canonicalization, and `internal/xpathfilter` the XPath allow-list matching and compilation `dsig` and `xenc` share | every push, Linux, macOS and Windows, under `-race` |
| Differential against `xmlsec1`, Apache Santuario and WSS4J | `tests/interop`, build tag `interop`, run by `tests/interop.sh` | every push, Linux |
| Security regressions | `tests/security`: XXE, external fetches, key substitution, algorithm confusion, comment truncation, encryption downgrade, transform programs outside the allow-list and prefix rebinding, Diffie-Hellman small-subgroup and weak-group attacks, PBKDF2 iteration bounds, Basic Security Profile refusals before the private key is used, one generic decryption error, key descriptions and key resolvers, token reference retargeting, signature confirmation replay | every push, all three systems; a local HTTP listener proves nothing is fetched |
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
| AP-10 | Coverage reported, not just validity; on a wrapped document `Covers` passes and `CoversNodes` refuses the forged body | `TestConformance_AP_10_SignatureCoverage` | ✅ |
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
| `TestSignRefusals` | XSLT without a stylesheet, XPath without an expression, SHA-1, no final canonicalization, whole-document reference without enveloped, inclusive SignedInfo on a detached signature |
| `TestXPathTransform`, `TestXPathFilter2Transform` (`dsig/xpath_test.go`) | the XPath transform before and after enveloped-signature, twice in a row, over reparsed octets, under a `#id` reference, with `here()` removing only its own signature, with the `xml` prefix, ending on a node set (implicit Canonical XML 1.0); XPath Filter 2.0 intersect, subtract, union, chained, over namespace nodes and with `here()`. Each is refused when not opted in, verifies when allowed, still verifies after a dropped node changes, and fails after a kept one changes; `Coverage` reports exactly what was kept |
| `TestXPathFilteredElementNotCovered` | an XPath or Filter 2.0 transform that drops the element a `#id` reference names: the signature verifies, the element is not in `Coverage`, and changing it leaves the signature valid |
| `TestXPathVerifyAdmission`, `TestXPathFilter2VerifyAdmission` | an expression outside the allow-list, a rebound prefix, bindings two entries give differently, and an XSLT allow-list are refused with `ErrTransformRefused`; an extra, missing or wrong XPath element, element content and a bad `Filter` are `ErrMalformed`; surrounding whitespace does not matter |
| `TestXPathSignErrors`, `TestXPathHereDetached`, `TestXPathShadowedPrefixes`, `TestXPathOmittedURICoverage` | syntax, unbound-prefix and dynamic errors, invalid bindings, a non-node Filter 2.0 result and unparseable octets are `ErrMalformed`; `here()` in a detached signature fails; a prefix may shadow the document's; a reference without URI whose filter drops something reports `OmittedURISigned` false |
| `TestXSLTTransform`, `TestXSLTStylesheetNamespaces` (`dsig/xslt_test.go`) | XSLT over a node set and over octets, verified against an allow-list; nothing reported covered; a stylesheet rebinding `ds`, declaring a nested namespace and sitting under a default namespace keeps its meaning |
| `TestXSLTVerifyAdmission`, `TestXSLTSandbox`, `TestXSLTOutputBound` | another stylesheet, and a prefix rebound only inside an XPath expression, are refused; `document()`, `doc()`, `unparsed-text()`, `xsl:include`, `xsl:import`, a terminating message and a serialization error fail; the output bound is `ErrLimitExceeded` |
| `TestParseRefusesDOCTYPE` | the pinned options refuse a DOCTYPE, asserted rather than read from documentation |
| `TestParseRefusesXXE`, `TestParseFetchesNothing`, `TestVerifyDereferencesNothingExternal` | every XXE and external-reference route in the [assessment](security.md#assessment) is refused or inert, with zero requests reaching a local listener |
| `TestExternalReferences`, `TestExternalCipherReference` | an absolute-URI reference signs and verifies through `ResolveURI`, raw and through a canonicalization that parses the octets, and is reported in `Coverage.ExternalURIs`; no resolver, a relative or unparsable URI and `cid:` are refused without calling it; resolver errors wrap `ErrDereference`; an external `CipherReference` decrypts raw or base64, and refused transforms never reach the resolver |
| `TestResolverCalledOnlyForAuthenticSignatures`, `TestCipherReferenceResolverAfterAllowList` | the resolver is never called for an untrusted key, a different pinned key, a disallowed signature or digest algorithm, a URI rewritten after signing, or a disallowed data algorithm |
| `TestCipherReferenceXPath`, `TestCipherReferenceXPathRefused`, `TestCipherReferenceXPathContent` (`xenc/cipherxpath_test.go`) | Example 13's XPath then base64 on an external, a whole-document and a `#id` `CipherReference`, with the ciphertext split by a comment and a decoy value beside it; `here()` in the same document; an expression not allowed or with its prefix rebound, XSLT, Filter 2.0 and an XPath transform not a `ds:Transform` are `ErrTransformRefused`, a malformed transform or allow-list entry `ErrMalformed`, and any other chain `ErrUnsupportedAlgorithm`, each before the resolver is called and before decryption; resolved octets that are not XML or carry a DOCTYPE, `here()` against a resolved document, and selected text that is not base64 are `ErrMalformed` |
| `TestCipherReferenceBaseURI` | a relative `CipherReference` URI resolves against `DecryptOptions.BaseURI` (RFC 3986), not the document's `xml:base`, and is refused with no base, no resolver, or a base that is relative or unparsable |
| `TestEncryptOctets` (`xenc/octets_test.go`) | arbitrary octets with `Type`, `MimeType`, `Encoding` and `Id`, inline and by a relative `CipherReference` decrypted through `BaseURI`; no `Type`; a same-document or unparsable reference URI, a bad `DataID` and CBC refused |
| `TestEncryptionProperties`, `TestEncryptionPropertiesRefused`, `TestEncryptedKeySchemaOrder` (`xenc/properties_test.go`) | `EncryptionProperties` after `CipherData` on element, content and attachment encryption, copied with the namespaces in scope and never moved; `MimeType` and `Encoding`; a property that is not an `xenc:EncryptionProperty`, cannot be canonicalized or declares no prefix, a conflicting `Type`, a `CipherReferenceURI` outside `EncryptOctets` and an attachment `MimeType` refused; `EncryptedKey` children placed by name in schema order whatever order they are added in |
| `TestDecryptAndReplaceRoundTrip`, `TestDecryptAndReplaceRefused` (`xenc/replace_test.go`) | encrypt then decrypt and replace restores the canonical document, for an element, an element undeclaring the default namespace, mixed content, empty content, the document element and content without a default namespace; two elements or text for Type Element, a document element's content that is not one element, octets that do not parse, close the wrapper, carry a DOCTYPE or an undeclared prefix, another or no Type, a disallowed algorithm and the wrong key are refused |
| `TestCipherReferenceXPathRefusedBeforeFetch`, `TestCipherReferenceBaseURINeverFromXMLBase` (`tests/security`) | on a `CipherReference`, an XPath with no allow-list, one not listed and the allowed text with its prefix rebound are `ErrTransformRefused` with a key that would fail decryption and no resolver call; a relative URI under an `xml:base` naming a metadata address is refused without `BaseURI` and resolved against `BaseURI` alone with it |
| `TestAttackerProgramRefusedBeforeEvaluation`, `TestXPathPrefixRebindingRefused`, `TestAllowedXSLTFetchesNothing` (`tests/security`) | an attacker's XPath, Filter 2.0 expression or stylesheet outside the allow-list is `ErrTransformRefused` ahead of the wrong-key failure, so before anything is evaluated; the allowed expression text with its prefix bound elsewhere is refused; an allowed stylesheet reaching for `file:` or `http:` through `document()`, `xsl:include` or `xsl:import` fails, with zero requests reaching a local listener |
| `TestRawKeyRoundTrip`, `TestRawKeyInfoStructure`, `TestCoveragePublicKey` | each raw-key form with RSA and P-256/384/521, self-described and pinned; a different pinned key refused; malformed and refused raw keys (short RSA, even modulus or exponent, off-curve and compressed points, explicit parameters, unknown curves) |
| `TestPinnedCertificateIgnoresEmbeddedKey`, `TestAlgorithmConfusion` | an attacker's own key is refused against a pinned certificate; HMAC, SHA-1 and key-type confusion are refused |
| `TestXPointerReferences`, `TestBase64OfNodeSet`, `TestOmittedURI`, `TestKeyInfoReference`, `TestPinnedKeyIgnoresUnsupportedKeyInfo` | the XML Signature 1.1 processing rules: XPointer forms keeping comments, base64 over a node set, the one URI-less reference, same-document `KeyInfoReference`, and a pinned key tolerating an unsupported `KeyInfo` |
| `TestSignInPlace`, `TestSignInPlaceRefusals` | in-place signing with any canonicalization, and a failed `Sign` leaving the document unchanged |
| `TestEnvelopingSignature`, `TestObjectInDetachedSignature`, `TestOwnIDs`, `TestObjectRefusals` (`dsig/object_test.go`) | an enveloping signature (nil document) over its `ds:Object`, a `ds:SignatureProperty` and its `ds:KeyInfo`, each by the `Id` Sign gave it, verifying without `IDAttrDSig` and failing once any changes; a detached signature's own `ds:Object`; a repeated Object `Id` anywhere is `ErrAmbiguousID`; only the signature's own elements, where Sign puts them, count; malformed Objects, properties and Ids refused |
| `TestManifest`, `TestVerifyManifestRefusals`, `TestBuildManifestRefusals` (`dsig/manifest_test.go`) | a `ds:Manifest` with `#id`, relative (through `BaseURI`), whole-document and omitted-URI references, signed through its own `Id` or its `ds:Object`; `VerifyManifest` reports its coverage, and a changed target fails the Manifest while the signature stays valid; an unsigned or foreign Manifest, and every malformed or disallowed reference, refused |
| `TestSignHMAC`, `TestSignHMACRefusals` (`dsig/hmac_sign_test.go`) | HMAC-SHA224, 256, 384 and 512 produced with `HMACKey`, full and truncated, verified with the same secret only; HMAC-SHA1, a short key, a `KeyInfo` and every out-of-range `HMACOutputLength` refused |
| `TestSignRefusesNonNFC`, `TestVerifyRequireNFC` (`dsig/nfc_test.go`) | `Sign` refuses a non-NFC reference or `ds:SignedInfo` with `ErrNotNFC`; `Verify` accepts one by default and refuses it with `RequireNFC` |
| `TestCanonicalizationPrefixes`, `TestSignOmittedURI` | the SignedInfo `PrefixList` is emitted and applied (rebinding a listed prefix breaks the signature), and refused detached, inclusive or malformed; a Reference without `URI` round-trips through `ResolveOmittedURI` |
| `TestBaseURI`, `TestEnvelopedOnReparsedOctets` | relative URIs resolved against `BaseURI` and never `xml:base`, reported in absolute form, refused without it or with a relative base; the enveloped-signature transform over a reparsed node set is `ErrMalformed` (XML Signature §6.6.4) |
| `TestStrictSecurityTokenReference` | the Basic Security Profile rules on a received token reference |
| `TestSTRTransformDirectReference`, `TestSTRTransformKeyIdentifier`, `TestSTRTransformEmbedded`, `TestSTRTransformOverKeyInfo` (`dsig/strtransform_test.go`) | the STR Dereference Transform over a direct, a key identifier and an embedded reference, and over the signature's own `ds:KeyInfo` reference under `StrictBSP`: the token is covered and reported in `SignedTokens`, the reference is not; the digest of a key identifier's token equals that of the element section 8.3 describes, built by hand; no resolver, a failing one or a missing token is `ErrSecurityTokenUnavailable` |
| `TestSTRTransformVerifyRefusals`, `TestSTRTransformSignRefusals`, `TestSTROctets` | missing, doubled, attributed or unknown `TransformationParameters`, inclusive canonicalization, the transform not alone or not over a reference; the `xmlns=""` rule of section 8.3 in each namespace context |
| `TestStrictBSP` (`dsig/bsp_test.go`) | each rule `StrictBSP` enforces refuses an altered, not re-signed, message with its own error, so before any cryptographic work; a reference into `ds:KeyInfo`, as WSS4J signs, is not enveloping |
| `TestKeyInfoElement` | key identifier and issuer-serial references in `ds:KeyInfo`: resolved, strict, pinned, pinned to another certificate (refused only when strict), and the resolver not called under a pinned key |
| `TestReferencedToken`, `TestCheckSecurityTokenReference` (`wss`) | tokens of any kind by direct reference and `wsse:Embedded`; R3057, R3064, R3211, R3060, R3056 and every syntax rule of `CheckSecurityTokenReference` |
| `TestFindHeader`, `TestFindTimestamp`, `TestCheckUniqueIDs`, `TestAssignIDKeepsXMLID` | one header per recipient including SOAP 1.2's ultimateReceiver, one timestamp, unique IDs across `wsu:Id`, `xml:id` and named attributes, and no `wsu:Id` beside an `xml:id` |
| `TestExplicitIDs`, `TestReproducibleAS4Signature` | `AssignIDWith` and the `…WithID` header methods refuse an empty, non-NCName or duplicated ID and keep an existing one; the AS4 shape (token, timestamp, messaging header, body, attachment) signed 25 times with every ID supplied is byte-identical, with no test hook, and verifies |
| `TestSignatureConfirmationRoundTrip`, `TestSignatureConfirmationErrors`, `TestEncryptedKeyReferences`, `TestFaultCode` | the section 8.5.2 rules; `EncryptedKey` references by ID and SHA-1, checked against the profile; each error class's fault code |
| `TestSTRTransformRetargetRefused`, `TestDuplicateIDsRefused`, `TestSignatureConfirmationMismatch`, `TestStrictBSPRefusesBeforeCrypto` (`tests/security`) | an STR-transform reference retargeted at a reference, an `Embedded` or a `ds:KeyInfo`; a planted duplicate `wsu:Id` or `xml:id`; a replayed or missing confirmation; `StrictBSP` refusing before `TrustKey` is called |
| `TestSymmetricBinding` (`xenc/str_test.go`) | WSS4J's symmetric-binding shape end to end: an RSA-OAEP `EncryptedKey` without a `ReferenceList`, a header `ReferenceList` from `wss.NewReferenceList`, Body content and an `EncryptedHeader` each naming the key by `EncryptOptions.DataKeyInfo`; received with `ReferencedData`, `FindEncryptedKey`, `DecryptData` and `DecryptHeader` under `StrictBSP` |
| `TestFindEncryptedKeySTR`, `TestFindEncryptedKeySTRErrors`, `TestDataKeyInfo` | a `SecurityTokenReference` in an `EncryptedData`'s `KeyInfo` resolves one hop to an `EncryptedKey` by `Id` or `wsu:Id`; two references, a key identifier, an external or empty URI, a missing or duplicated ID and a non-`EncryptedKey` target are refused; `DataKeyInfo` lands after the `EncryptionMethod` of every `Encrypt` function's output, copied, and a non-detached element or a `ds:KeyInfo` is refused |
| `TestReferencedData`, `TestReferencedDataErrors` | a header `ReferenceList` yields its `EncryptedData`, through an `EncryptedHeader` by `wsu:Id`, skipping `KeyReference`; an empty list, another child, a non-local URI, a missing or duplicated ID, another target and a repeated reference are refused |
| `TestDecryptHeader`, `TestDecryptHeaderContext`, `TestDecryptHeaderErrors`, `TestEncryptHeaderGeneratesID` | `DecryptHeader` restores the document `EncryptHeader` started from (SOAP 1.1 and 1.2), parses the plaintext in the `EncryptedHeader`'s namespace context; an `EncryptedHeader` with another child, text, a comment or nothing (R3230), Type Content, or outside a SOAP Header is `ErrMalformed`; a wrong key, two elements, text, bad XML and a DOCTYPE are the same `ErrDecryptionFailed`; `EncryptHeader` without `DataID` generates a fresh `Id` (R5624) |
| `TestStrictBSPEncryptedKey`, `TestStrictBSPEncryptedData`, `TestStrictBSPAttachment`, `TestStrictBSPAgreedAndDerived` | `DecryptOptions.StrictBSP` refuses `Type`, `MimeType`, `Encoding` and `Recipient` on an `EncryptedKey` (R3209, R5622, R5623, R5602), a `KeyInfo` without exactly one `SecurityTokenReference` (R5424, R5426), an `EncryptedData` in a SOAP Header (R3228) or without `KeyInfo` and unnamed by an `EncryptedKey` (R5629), in every decryption function, before any key is needed; without it the same input proceeds |
| `TestStrictBSPRefusesBeforeKeyTransport`, `TestDecryptionFailureIsGeneric` (`tests/security`) | a StrictBSP refusal never reaches the private key; a wrong RSA key, a wrong KEK, a wrong or wrong-size data key, a tampered GCM tag, bad CBC padding and an `EncryptedHeader` plaintext that is not one element are all `ErrDecryptionFailed`, with no detail in the message |
| `TestNewReferenceList` | the standalone `ReferenceList`, one `DataReference` per ID; none, a non-NCName and a repeat refused |
| `TestPKCS7RoundTrip`, `TestParsePKCS7Errors`, `TestAddBinarySecurityTokenPKCS7Errors`, `TestSecurityTokenReferencePKCS7` | PKCS7 tokens: the leaf found whatever the certificate order, lenient and strict resolution, signing and verifying through one; truncated, trailing, wrong content types, versions and tags, no or too many certificates, non-X.509 certificates, ambiguous leaves and key identifiers that do not match are refused; CRLs and signer infos are ignored |
| `TestMarshalPKCS7IsDER`, `TestPKCS7OpenSSLFixtures` | the PKCS7 encoding is DER, byte-identical to OpenSSL's `crl2pkcs7` for the same certificates, and OpenSSL's output parses in either certificate order |
| `TestNilInputs` (`wss`, `xenc`) | a nil or wrong-kind argument is an error, never a panic |
| `TestImplicitCanonicalization` | a received reference ending in a node set verifies through Canonical XML 1.0, and the implied algorithm is refused when outside the allow-list |
| `TestX509DataDescriptiveElements` | subject name and issuer-serial that describe the certificate are accepted, as are a CRL and a `KeyName` beside; another subject or SKI is ignored (refused only under `StrictX509Data`, `TestX509Descriptors`); the same certificate twice, or no certificate, are refused |
| `TestX509Chain`, `TestX509ChainOrderAndCRLs`, `TestX509Descriptors`, `TestSignX509Options` (`dsig/x509data_test.go`) | a chain signed with every descriptor and a `KeyName` verifies, the leaf found in any order across several `X509Data`, the rest reported as `Intermediates` and the CRLs in `CRLs`; each descriptor matching, SHA-1 `X509Digest` only when named, descriptors of each carried certificate (as xmlsec1 writes them); another serial, issuer, subject, SKI or digest, 17 certificates, two leaves, malformed descriptors and unknown children refused; Sign's option combinations refused |
| `TestDNEqual` (`dsig/x509data_internal_test.go`) | RFC 4514 names as Go, Santuario and xmlsec1 write them: escapes, `#hex` values, OIDs, multi-valued RDNs, case, spacing and RDN order; unparsable names never match |
| `TestResolveX509`, `TestResolveKeyName`, `TestSignKeyName`, `TestKeyInfoReferenceForms` | the resolvers receive what the message says, their errors and empty or mismatching answers are refused, `TrustKey` still applies, a disallowed algorithm and a pinned key call nothing; `KeyInfoKeyName`, `KeyInfoX509Descriptors` and same-document and external `KeyInfoReference` sign and verify |
| `TestRetrievalMethod` (`dsig/retrieval_test.go`) | each allowed `Type` to a same-document element, a raw certificate through `ResolveKeyInfoURI`, `DSAKeyValue` only for a DSA signature; transforms, a mismatched or unknown `Type`, the whole document, another document of any other type and a `RetrievalMethod` reached by reference refused |
| `TestLegacyAlgorithmsOptIn`, `TestDSA` (`dsig/legacy_test.go`) | every algorithm outside the default sets (legacy and SHA-224) refused until named; DSA-SHA256 with a (2048, 256) key in `DSAKeyValue` and `DEREncodedKeyValue`, DSA key sizes per algorithm, ECDSA-SHA1, HMAC-SHA224 |
| `TestCertpathLeaf` (`internal/certpath`) | the leaf of an unordered set, shared by PKCS7 tokens and `X509Data`: none or two is no leaf |
| `TestX509DescriptorMismatchRefused`, `TestKeyResolversNotCalledBeforeAllowLists` (`tests/security`) | a descriptor of another certificate and a chain with two leaves are refused under an authentic signature; no key resolver runs for a disallowed signature or digest algorithm, or a pinned key |
| `TestDHRoundTrip`, `TestDHKeyValueForms`, `TestDecryptAgreedKeyDHErrors`, `TestGenerateDHKeyErrors` (`xenc/dh_test.go`) | finite-field `dh-es` and `dh` in the RFC 3526 group 14 and RFC 7919 ffdhe2048 groups; every `DHKeyValue` form; a group under 2048 or over 8192 bits, a composite P, a Q not dividing P-1, a generator outside the subgroup, and a public value of 0, 1, P-1, P or outside the subgroup refused |
| `TestLegacyKDFKnownAnswers` | the Legacy KDF of section 5.6.2.2 on the specification's own Example 40 input, and on two-block outputs, against values computed independently with Python's `hashlib`. Example 41's printed result does not match Example 40's octets; see the test |
| `TestPBKDF2KnownAnswers`, `TestUnwrapEncryptedKeyPasswordErrors`, `TestPBKDF2AsAgreementKDF` (`xenc/pbkdf2_test.go`) | PBKDF2-HMAC-SHA256 and the RFC 6070 PBKDF2-HMAC-SHA1 vector as the KEK of an `xenc11:DerivedKey`; every malformed or out-of-policy parameter; PBKDF2 as a key agreement's KDF against a KEK computed independently |
| `TestDHAndPBKDF2NotAllowedByDefault`, `TestDHSubgroupAndGroupAttacksRefused`, `TestPBKDF2IterationCountBounded` (`tests/security`) | none of the three is accepted under empty allow-lists; small-subgroup, 512-bit and 16384-bit groups refused; an iteration count of 4,000,000,000 refused in under 250 ms, without derivation |
| `TestFindEncryptedKeyOfEncryptedKey`, `TestFindDerivedKey` (`xenc/resolve_test.go`), `TestEncryptedKeyChain`, `TestAddKeyReference` (`xenc/keyref_test.go`) | an `EncryptedKey` as `FindEncryptedKey`'s input: inline, `RetrievalMethod` (one or several naming one key), `KeyName`/`CarriedKeyName`, and `KeyReference` (never `DataReference`); `FindDerivedKey` by the same four routes; a key naming itself, `RetrievalMethod`s naming two keys, a duplicated `DerivedKeyName` and a `KeyInfo` out of schema order refused; a two-hop chain decrypted end to end; `KeyReference` placed before `CarriedKeyName` |
| `TestMasterKeyRoundTrip`, `TestPasswordDataKey`, `TestDeriveKeyForEncryptedKey`, `TestDeriveKeyErrors`, `TestDataKeyOptionErrors`, `TestMasterKeyAttachment` (`xenc/derivedkey_test.go`) | a data key derived by ConcatKDF from `EncryptOptions.MasterKey` (fresh `PartyUInfo`, so no two keys alike) or by PBKDF2 from `Password`, with no `EncryptedKey`; a `DerivedKey` naming an `EncryptedKey` by `KeyReference` (Example 25's form); Example 25's own 5-bit `PartyUInfo` refused; every allow-list, a missing master key, and every conflicting or weak option refused |
| `TestDirectKeyAgreement` (`xenc/agreement_test.go`), `TestDirectKeyAgreementDH` (`xenc/dh_test.go`) | the `AgreementMethod` directly in the `EncryptedData` (ECDH-ES, `dh-es`, `dh`), the key sized by the data algorithm after its allow-list; a `KA-Nonce` beside ECDH-ES and `dh-es` ignored |
| `TestEncryptedKeyCipherReference` (`xenc/keywrap_test.go`), `TestDecryptEncryptedKeyCipherReference`, `TestLegacyRSA15CipherReference` | an `EncryptedKey`'s ciphertext by same-document and external `CipherReference`, for key wrap, RSA-OAEP and RSA v1.5; a resolver failure under RSA v1.5 is an error before any RSA operation, not an implicit rejection |
| `TestImpliedAlgorithms` (`xenc/model_test.go`), `TestMGF1SHA224` | an absent `EncryptionMethod` read from `DecryptOptions.Implied*Algorithm` only, still through the allow-list; MGF1 with SHA-224 produced when named and accepted only when named |
| `TestEncryptedKeyCipherReferenceResolverAfterAllowList`, `TestEncryptedKeyChainsBounded`, `TestKeyRetrievalAmbiguityRefused` (`tests/security`) | an `EncryptedKey`'s `CipherReference` never reaches the resolver before key wrap, key transport, MGF, data, agreement, KDF digest and PBKDF2 allow-lists pass; a cycle of `EncryptedKey`s is walked one hop per call and a self-reference refused; `RetrievalMethod`s to two keys and a duplicated Id are `ErrAmbiguousID` |
| `TestFindByID` | duplicate IDs are refused across `wsu:Id` and `xml:id` |
| `TestFindByIDExtraAttributes`, `TestSAMLAssertionByID`, `TestPlainIdReference`, `TestDefaultIDSetUnchanged` | opt-in `ID`/`Id` resolution; duplicates refused across every counted attribute; an attacker assertion with the signed `ID` refused; the default set unchanged |
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
| `TestSubsetSignatureMatchesReferences` | byte equality with xmlsec1 and Santuario, and each side verifies the others' | a `#id` subset whose ancestors carry `xml:base`, `xml:lang`, `xml:space` and `xml:id`, under Canonical XML 1.0 and 1.1: the only place 1.1 differs, by not inheriting `xml:id` and by joining `xml:base` values; the two algorithms are asserted to digest it differently |
| `TestSantuarioC14N11NestedXMLBase` | a known Santuario divergence, kept visible | with two omitted ancestors carrying `xml:base`, Santuario 4.0.4 joins one, digesting `http://example.com/a/c/` where C14N 1.1 §2.4, this library and xmlsec1 give `http://example.com/a/b/c/`, and writes that value into its output; the test fails once Santuario agrees |
| `TestSignatureValueMatchesSantuarioDetached` | byte equality, and both ways | SOAP 1.2 WS-Security header, two `#id` references |
| `TestWSS4JProcessesOurSecurityHeader` | WSS4J | a WS-Security header built by this library: timestamp, binary security token, signature over body and timestamp; WSS4J must report both as signed, with Basic Security Profile enforcement on |
| `TestWSS4JDecryptsOurEncryption` | WSS4J | an encrypted body with the `EncryptedKey` in the header, naming the recipient's token and the `EncryptedData`; WSS4J must decrypt it to the original |
| `TestWSS4JVerifiesOurAttachmentSignatures`, `TestWeVerifyWSS4JAttachmentSignatures` | WSS4J, both ways | Content- and Complete-Signature transforms over XML, text and binary parts; a tampered part must be refused |
| `TestWSS4JDecryptsOurAttachmentEncryption`, `TestWeDecryptWSS4JAttachmentEncryption` | WSS4J, both ways | Attachment-Content-Only and Attachment-Complete encryption, AES-128-GCM under RSA-OAEP |
| `TestWSS4JProcessesSignThenEncrypt` | WSS4J | sign then encrypt in WS-Security order, with the recipient key named by token reference, subject key identifier and issuer-serial, plus an encrypted signature; WSS4J decrypts, then verifies. A control that appends the `EncryptedKey` (the old order) is refused |
| `TestWSS4JDecryptsOurEncryptedHeaderAndContent` | WSS4J | a `wsse11:EncryptedHeader` and encrypted Body content |
| `TestWSS4JVerifiesOurSTRTransform`, `TestWeVerifyWSS4JSTRTransform` | WSS4J, both ways | the STR Dereference Transform over a direct reference, over our own `ds:KeyInfo` reference as WSS4J signs it, and, with no token in the message, a SubjectKeyIdentifier (ours) or also an issuer serial (WSS4J's own `ds:KeyInfo` reference): each side digests the token section 8.3 builds byte for byte as the other does; ours carries a `SignatureConfirmation` WSS4J reports, our `ds:KeyInfo` names the key by `KeyInfoElement`, and we verify WSS4J's under `StrictBSP`. A control replacing the token is refused |
| `TestWeCheckWSS4JSignatureConfirmation` | WSS4J | a `SignatureConfirmation` WSS4J writes, with and without a `Value`, checked by `CheckSignatureConfirmations` |
| `TestWSS4JProcessesOurSymmetricEncryption`, `TestWeDecryptWSS4JSymmetricEncryption` | WSS4J, both ways | the symmetric binding: an `EncryptedKey` with no `ReferenceList`, a header `ReferenceList`, Body content and an `EncryptedHeader` whose `EncryptedData` name the key by a `SecurityTokenReference` with `TokenType` EncryptedKey. WSS4J decrypts ours with BSP enforcement on; we decrypt WSS4J's with `ReferencedData`, `FindEncryptedKey` and `DecryptHeader` under `StrictBSP`, which also caught WSS4J putting a bare `EncryptedData` in the Header (R3228) until the harness asked for its `Header` modifier |
| `TestPKCS7TokenWithJDK` | JDK and Santuario, both ways | a header signed with a PKCS7 token of a leaf and its CA: the JDK's PKCS#7 codec reads both certificates and Santuario verifies with the leaf; the JDK encodes the same certificates to byte-identical DER, and its token resolves to the leaf under `StrictSecurityTokenReference`. WSS4J 4.0.1 reads no PKCS7 token, so it is not the peer here |
| `TestSantuarioXPointerReferences` | Santuario, both ways | `#xpointer(/)` and `#xpointer(id('…'))` with comments; byte-identical `SignatureValue`; a changed comment is refused |
| `TestSantuarioVerifiesOurInPlaceInclusiveSignature` | ours → Santuario | an inclusive-canonicalization signature computed in place (`SignOptions.Parent`) |
| `TestPeersVerifyOurEnvelopingSignature`, `TestWeVerifySantuarioEnvelopingSignature` (`tests/interop/object_test.go`) | ours → both; Santuario → ours | an enveloping signature over `ds:Object`, `ds:SignatureProperty` and (ours) `ds:KeyInfo`; a changed Object is refused. We verify Santuario's with no ID attribute named |
| `TestSantuarioVerifiesOurManifest`, `TestWeVerifySantuarioManifest` | Santuario, both ways, digest equality | Santuario verifies our signature over a `ds:Manifest` and refuses a changed Manifest; our Manifest reference digest equals Santuario's for the same input; `VerifyManifest` accepts Santuario's. Santuario follows a Manifest only through a reference ending in a node set, which `Sign` never produces (behind a canonicalization it reparses the Manifest alone and cannot resolve its `#id`), so its Manifest following is not the check |
| `TestPeersVerifyOurCanonicalizationPrefixes` | ours → both | a `PrefixList` on `ds:CanonicalizationMethod`; rebinding the listed prefix is refused |
| `TestSantuarioVerifiesOurHMAC` | ours → Santuario | HMAC-SHA256 with a 32-octet secret; another secret is refused |
| `TestWeVerifySantuarioExternalReference`, `TestSantuarioVerifiesOurExternalReference` | Santuario, both ways | a reference to `http://example.invalid/…`, as raw octets and through exclusive C14N, served from a local file by a Santuario `ResourceResolver` and by our `ResolveURI`: nothing is fetched; Santuario refuses other octets |
| `TestSantuarioTransforms` | Santuario, both ways, digest equality | the XPath transform, the absolute `not(//ancestor-or-self::x)`, which both sides digest as the empty node set, XPath Filter 2.0 intersect, subtract and union, and XSLT; equal `DigestValue`s, so byte-identical transform output; changing a dropped node verifies, changing a kept one fails, on both sides |
| `TestXmlsec1VerifiesOurHere` | ours → xmlsec1 | `here()` in an XPath and an XPath Filter 2.0 transform. Santuario 4 has no `here()`: its JDK XPath engine reports the function unknown |
| `TestReferenceImplementationsDecryptOurECDHES`, `TestWeDecryptSantuarioECDHES`, `TestWeDecryptXmlsec1ECDHES` | both ways | ECDH-ES with ConcatKDF on P-256, P-384 and P-521 |
| `TestXmlsec1DecryptsOurDHES`, `TestWeDecryptXmlsec1DHES` | xmlsec1, both ways | finite-field `dh-es` with ConcatKDF in ffdhe2048 (X9.42 DHX keys); xmlsec1 finds the recipient key only by the `ds:KeyName` of `EncryptOptions.RecipientKeyName` |
| `TestXmlsec1DecryptsOurPBKDF2`, `TestWeDecryptXmlsec1PBKDF2` | xmlsec1, both ways | a password-derived KEK (`xenc11:DerivedKey`, PBKDF2 with HMAC-SHA256 and SHA-512) |
| `TestWeDecryptXmlsec1AgreementWithPBKDF2` | xmlsec1 → ours | PBKDF2 as the KDF of ECDH-ES and of `dh-es`, the shared secret as the password |
| `TestReferenceImplementationsDecryptOurKeyWrap`, `TestWeDecryptTheirKeyWrap` | both ways | AES key wrap |
| `TestDerivedKeyConcatKDFBothWays`, `TestDerivedKeyPBKDF2BothWays` (`keyinfo_test.go`) | xmlsec1, both ways | an `xenc11:DerivedKey` directly in the `EncryptedData`: ConcatKDF from a master key (`--concatkdf-key`, found by `MasterKeyName`, with our random `PartyUInfo`), and PBKDF2 from a password |
| `TestDirectKeyAgreementBothWays` | xmlsec1, both ways | ECDH-ES with the `AgreementMethod` directly in the `EncryptedData` |
| `TestEncryptedKeyChainWithXmlsec1` | xmlsec1, both ways | an `EncryptedKey` whose KEK a nested `EncryptedKey` carries, reached from the `EncryptedData` by `RetrievalMethod`; each side follows it with `FindEncryptedKey` twice. xmlsec1 re-parses a retrieved element as its own document, so it cannot follow a second `RetrievalMethod`, and the second hop is nested |
| `TestDecryptReplaceKeepsNoNamespace` | ours → both | a decrypted element that undeclares a default namespace stays in no namespace |
| `TestReferenceImplementationsDecryptOurOctets` | ours → both | `EncryptOctets` binary octets with a `MimeType` and no XML `Type`, the `EncryptedData` the document element; Santuario through the harness's `decrypt-octets-kw` |
| `TestReferenceImplementationsDecryptOurEncryptionProperties` | ours → both | an element whose `EncryptedData` carries `EncryptionProperties`, `MimeType` and `Encoding` |
| `TestWeDecryptAndReplaceTheirDocumentElement` | both → ours | each encrypts the document element; `DecryptAndReplace` returns, octet for octet, the canonical form of each one's own decryption |
| `TestCipherReferenceXPathDecryptedByAll` | all three | a hand-built Example 13 `CipherReference`, XPath then base64 over the ciphertext held elsewhere in the document: xmlsec1, Santuario and `DecryptAndReplace` produce the same canonical document |
| `TestWeVerifySantuarioX509Chain`, `TestWeVerifyXmlsec1X509Chain` | each → ours | a leaf and intermediate with `KeyName`, `X509IssuerSerial`, `X509SKI`, `X509SubjectName` and `X509Digest` as each writes them (xmlsec1 describing every certificate); `Coverage` reports the leaf, the intermediate and the name, and a changed serial is refused |
| `TestReferenceImplementationsVerifyOurX509Chain` | ours → each | `Chain`, every `X509Descriptor` and `KeyName`; Santuario resolves the leaf, and xmlsec1 builds the path to a trusted root through the intermediate we carry |
| `TestWeVerifySantuarioRetrievalMethod` | Santuario → ours | a `RetrievalMethod` of `Type` `X509Data` to an `X509Data` in a `ds:Object`, found with `IDAttrDSig` |
| `TestReferenceImplementationsVerifyOurSHA224`, `TestWeVerifySHA224FromReferenceImplementations` | both ways, both peers | RSA-SHA224 and ECDSA-SHA224 with SHA-224 digests; refused by default, verified when named, a tampered copy refused |
| `TestWeVerifySantuarioDSASHA256AndECDSASHA1` | Santuario → ours | DSA-SHA256 with a (2048, 256) key in `DSAKeyValue`, and ECDSA-SHA1 |
| `TestXmlsec1DecryptsOurEncryption`, `TestSantuarioDecryptsOurEncryption` | ours → each | AES-128-GCM element, RSA-OAEP with explicit SHA-256 MGF and digest |
| `TestWeDecryptXmlsec1Encryption`, `TestWeDecryptSantuarioEncryption` | each → ours | the same |

**ID attributes.** The Santuario harness takes leading `--id-attr NAME`
options (repeatable, unqualified names) that register extra ID attributes,
for example `santuario --id-attr ID verify doc.xml cert.pem`; `sign-enveloped`
takes an optional seventh argument, the reference URI. `sign-transform` signs
with enveloped-signature, one XPath, XPath Filter 2.0 or XSLT transform and
Exclusive C14N; `verify-insecure` verifies with Santuario's secure
validation off, which otherwise refuses XSLT. `TestSantuarioSAMLAssertionByID`
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
  find the session key. `xenc.FindEncryptedKey` reads this form, but placing
  the key there is left to the caller, so the harness does.

**Not cross-checked.** Santuario 4.0.4 implements neither finite-field
Diffie-Hellman (it has no `xenc:DHKeyValue`) nor PBKDF2, and neither
reference implements the Legacy KDF of `xmlenc#dh`: that is checked only by
`TestLegacyKDFKnownAnswers` and our own round trip. Santuario also has no
`DerivedKey` outside a key agreement, no `AgreementMethod` directly under an
`EncryptedData`, and no `EncryptedKey` chains, so those are checked against
xmlsec1 only. Neither tool writes an `EncryptedKey` with a
`CipherReference`, a `KeyReference`, or a missing `EncryptionMethod`; those
are unit-tested only.

Set `GOXMLSEC_REQUIRE_INTEROP=1` to make a missing tool fail rather than
skip; the script and CI set it.

## Test data

Everything the tests run against, and where it comes from.

**Keys and certificates.** Generated fresh in every run from `crypto/rand`:
RSA 2048-bit keys, and ECDSA keys on P-256, P-384 and P-521, each with a
self-signed X.509 certificate. Tests that write PEM files for the reference
tools write them to a per-test temporary directory. Exceptions: the PKCS#7
fixtures below, and `wss/testdata/golden-key.pem`, a test-only RSA key and self-signed
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
| Adversarial documents | XXE and DTD variants, relocated and duplicated IDs, algorithm and key substitutions, attacker transform programs | `tests/security`, `TestVerifyNegative`, `TestSignRefusals` |

**Reference implementations.** Built into one image by `tests/Dockerfile`:

| Implementation | Version | Source |
|---|---|---|
| `xmlsec1` (libxmlsec1 on OpenSSL) | 1.3.11 at the time of writing | Alpine package `xmlsec`, on `golang:1.26-alpine` |
| Apache Santuario | 4.0.4 | Maven Central `org.apache.santuario:xmlsec`, run on OpenJDK 21 |
| Apache WSS4J | 4.0.1 | Maven Central `org.apache.wss4j:wss4j-ws-security-dom`, same harness |

The harness (`tests/santuario/Harness.java`) exposes Santuario and WSS4J as
commands: `verify`, `sign-enveloped`, `sign-detached`, `encrypt`, `decrypt`,
`encrypt-ecdh`, `encrypt-kw`, `decrypt-kw`, `wss4j-verify`, `wss4j-decrypt`,
`wss4j-process` (both keys: decrypt, then verify), the attachment commands,
`wss4j-encrypt-symmetric` (WSS4J's `WSSecEncryptedKey` and `WSSecEncrypt`
with `setEncryptSymmKey(false)`: the symmetric-binding shape),
`sign-external` and `verify-external`, which serve one external URI from a
local file through a `ResourceResolver`, `pkcs7` (the JDK's PKCS#7 codec:
read one token, write another), `verify-hmac` (an HMAC keyed with a raw
secret file), `sign-enveloping` (a signature as the document element over a
`ds:Object` and a `ds:SignatureProperty`) and `sign-manifest` (a signature
over a `ds:Manifest` in a `ds:Object`), and, for the tests above,
`sign-transform`, `verify-insecure`, `sign-alg`, `sign-keyinfo`,
`sign-retrieval`, `verify-keyinfo`, `encrypt-legacy`, `decrypt-octets-kw`,
`wss4j-sign-str` and `wss4j-confirm`; `--id-attr NAME` registers extra ID
attributes.

**PKCS#7 fixtures.** `wss/testdata/pkcs7/openssl.p7b` and
`openssl-sorted.p7b` were written by OpenSSL 3.6 (`openssl crl2pkcs7 -nocrl
-certfile chain.pem -outform DER`) from a P-256 root, intermediate and leaf,
in two input orders; the command is repeated beside the test that reads
them. They are binary in `.gitattributes`.

The Alpine package is not pinned to a patch release; the version in use is
printed by `xmlsec1 --version` in the container.

**Fuzz corpora.** Seeded at run time from real signatures and encryptions
produced by this library, plus the malformed seeds listed under Fuzzing.
Inputs the fuzzer finds interesting stay in the local Go fuzz cache; any
failing input is committed under `testdata/fuzz/<Target>/` as a permanent
regression seed.

**W3C XML Signature 1.1 interop vectors.** `tests/w3c`, a nested module, so
they are in this repository and CI but not in the library's module
download: 34 vectors from the 2012 interop report (Oracle), ECDSA
P-256/384/521 and RSA with SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512, and
HMAC-SHA224, copied unmodified under the W3C
Document License (`tests/w3c/NOTICE`, `tests/w3c/LICENSE-W3C-DOCUMENT`).
`testdata/MANIFEST.json` records the expected outcome of each; run with
`cd tests/w3c && go test ./...`. **17 verify end to end**: the fifteen
`ECKeyValue` vectors (SHA-1 to SHA-512), the EC `DEREncodedKeyValue` one and
HMAC-SHA224 (key "testkey", from the vectors' README), each an enveloping
signature over a `ds:Object` (identified with `IDAttrDSig`). A vector whose
algorithms are outside the default sets names them in the manifest
(`allowed_signature`, `allowed_digest`), and is first checked to be refused
without them. The other 17 are refused, each for a documented reason: 7
carry 1024-bit RSA keys, below the 2048-bit minimum (one of them behind a
`KeyInfoReference`, which is followed); 9 use the legacy RFC 4050
`ECDSAKeyValue` form; one gives the key only as an `X509Digest`, whose
certificate the vectors do not publish for `ResolveX509`. None references an
external URI, so none depends on `ResolveURI`.

**W3C XML Encryption 1.1 interop vectors.** `tests/w3c/testdata/xmlenc11`, the
2012 Oracle vectors under the same license, with their keys (the `.p12` files
unmodified, and their private keys extracted to PEM, since Go cannot read
PKCS#12). The three ECDH-ES with ConcatKDF vectors, on P-256, P-384 and
P-521, decrypt to the published plaintext, and, each `EncryptedData` being
its document's element, `DecryptAndReplace` turns each into the canonical
plaintext document. The others are refused for stated
reasons: PBKDF2 and finite-field `dh-es` are not in the default set, and
named, the two `dh-es` vectors' 1024-bit group is under the 2048-bit
floor; `rsa-oaep-mgf1p` and a SHA-1 MGF are not allowed. The ECDH-ES with
PBKDF2 vector (AGRMNT.9) parses and is accepted once PBKDF2 is named, but
its KEK cannot be reproduced from any encoding of the shared secret tried;
xmlsec1's own suite leaves it out too, and the reading implemented, the
secret's octets as the password, is the one xmlsec1 uses
(`TestWeDecryptXmlsec1AgreementWithPBKDF2`). The set holds no
`DerivedKey`, `KeyReference` or `RetrievalMethod` vector, so no vector
changed outcome when those were implemented; every one still resolves its
`EncryptedKey` through `FindEncryptedKey`.

**Real-world corpus.** 122 real Peppol SMP responses, fetched 2026-09-26 from
62 SMP providers and at least 20 distinct producing implementations, stored
byte-for-byte. They are kept in a separate, private repository,
`go-xmlsec-corpus`, not here: they carry no license grant and may contain
personal data, so they are not redistributed. Its CI runs them against this
library. **All 122 verify**, whole document signed, key from the
certificate; each signature and every digest was also checked
independently, and Santuario agrees on every one. The corpus found two
behaviours this library had refused and now accepts, as the specification
allows: implicit Canonical XML 1.0 on verification, and descriptive
`X509Data` elements beside the certificate. The
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

Errors are discarded in two places, each with a comment: `asn1.Marshal` of
the PkiPath in `wss/bst.go`, a sequence of `RawValue`s that are emitted
verbatim and cannot fail to encode; and `pbkdf2.Key` in `xenc/pbkdf2.go`,
which fails only for a key length out of range, never passed, or in FIPS
140-only mode, where the nil key it then returns is refused by the key
unwrap. `xenc/export_test.go` exposes the unexported Legacy KDF to its
known-answer test.

## Canonicalization

Every digest and signature this library computes is over octets from
`go-xml/c14n`, pinned at v1.4.0. It is tested in go-xml, not here, and its
figures are published only in that module's
[docs/c14n.md](https://github.com/knroy/go-xml/blob/v1.4.0/docs/c14n.md#conformance-and-verification),
not in the conformance table of its README, where its sibling packages
report theirs. At v1.4.0:

| Check | Result |
|---|---|
| Worked examples of the three Recommendations (C14N 1.0 §3, 1.1 §3 with erratum E11-01, Exclusive §2) | 28 / 28 |
| C14N 1.1 §2.4 URI-joining examples and the Appendix A dot-segment table | 69 / 69 |
| W3C C14N 1.1 interop cases, digests checked against all five implementations | 20 / 20 |
| Differential against `xmllint`, whole documents, three algorithms | 129 / 129 |
| Differential against `xmlsec1`, node sets through signature references, six algorithms | 870 compared: 790 identical, 80 documented differences |

The W3C publishes no pass/fail conformance suite for Canonical XML beyond the
Recommendations' examples and the C14N 1.1 interop cases, so there is no
single figure to report beside the XPath and XML Schema suites. Not measured
in go-xml: a differential against Santuario, and a corpus of real signed
messages.

This module exercises `c14n` independently, through whole signatures rather
than canonical octets:

* `SignatureValue` byte-identical to Santuario's, under inclusive and
  exclusive C14N 1.0 (`TestSignatureValueMatchesSantuarioEnveloped`), and
  the interop tests above, both ways, against xmlsec1, Santuario and WSS4J,
  which use Canonical XML 1.0 and Exclusive C14N, with and without comments.
* Canonical XML 1.1: whole documents both ways against xmlsec1 and
  Santuario, and a subset whose ancestors carry the `xml:` attributes 1.1
  treats differently, byte-identical to xmlsec1 and to Santuario
  (`TestSubsetSignatureMatchesReferences`). One divergence, Santuario's:
  with two omitted ancestors carrying `xml:base` it joins only one
  (`TestSantuarioC14N11NestedXMLBase`); this library agrees with xmlsec1 and
  the Recommendation.
* The W3C XML Signature 1.1 interop vectors in `tests/w3c`, all under
  Canonical XML 1.0.
* 122 real Peppol SMP responses, inclusive C14N 1.0, all verifying (the
  private corpus above).

A `c14n` change that alters output by one byte breaks every signature made
before it; [RELEASE.md](../RELEASE.md#before-bumping-go-xml) says what to
check before bumping the pin.

## Not tested yet

* **Real messages signed with Exclusive C14N.** The corpus is Peppol SMP
  responses, inclusive C14N; AS4, which signs with Exclusive C14N, has only
  the interop tests. The one defect real messages have found, the Canonical
  XML 1.0 implied at the end of a reference, which refused most SMP
  providers, was missed by every synthetic test.
