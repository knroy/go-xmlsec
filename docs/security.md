# Security

## Threat model

This library is used to verify signatures on messages someone else wrote,
which is exactly where a subtle bug becomes a vulnerability. It is also the
place where a defect is silent: a wrong signature does not fail locally, a
peer rejects it with no diagnostic.

What `dsig.Verify` establishes, and all it establishes:

> The signature was made by the key in `Coverage.PublicKey` (the key of
> `Coverage.Certificate` when there is one), over exactly the nodes and
> attachments listed in `Coverage`.

What it does **not** establish:

* **That the certificate is trusted.** No chain building, no revocation, no
  trust anchors. `Coverage.Intermediates` and `Coverage.CRLs` are what
  `ds:X509Data` carried, unverified, for the caller's own path validation.
  When `VerifyOptions.Certificate` is nil, the certificate comes from the
  message itself, so a nil error proves only that the message
  is self-consistent.
* **That the elements you will read are the ones that were signed.** See
  below.

## External references and the resolver

The library performs no network or file I/O. A `ds:Reference` or
`xenc:CipherReference` to an absolute URI other than `cid:` is dereferenced
only through an `xmlsec.URIResolver` the caller supplies
(`SignOptions.ResolveURI`, `VerifyOptions.ResolveURI`,
`xenc.DecryptOptions.ResolveURI`); without one it is refused. A relative
URI is refused unless the caller sets a base: `BaseURI` on `SignOptions` or
`VerifyOptions` for a `ds:Reference`, `xenc.DecryptOptions.BaseURI` for a
`CipherReference`. It is then resolved against that absolute URI, and the
resolver (and, for a signature, `Coverage.ExternalURIs`) sees the result. The
base is never taken from `xml:base` or anything else in the document, which
the sender controls: a document-supplied base would let the sender move a
relative reference to any host. The resolver is therefore the caller's
server-side request forgery boundary, and it sees URIs the signer chose.

On verification it is called only after the allow-lists, `TrustKey` and the
signature value check have all passed, so a message from an untrusted or
wrong key, or one whose URI was rewritten after signing, never reaches it.
`DecryptData` calls it only after the data algorithm and the
`CipherReference` transforms, an allowed XPath expression included, are
accepted. A trusted signer can still name
any URI, so a safe resolver:

* serves only an allow-list of exact URIs or hosts, or a fixed set of local
  resources, and never follows a redirect to anywhere it would not fetch
  directly;
* never reaches `file:`, loopback, link-local or other internal addresses
  unless the allow-list names them;
* sets connect and read timeouts;
* caps the size it returns.

What it returns is what was signed: `Coverage.ExternalURIs` names each URI,
and the caller trusts that content only as far as it trusts the resolver.
Octets a canonicalization transform needs as XML are parsed with
`xmlsec.Parse`, under the same limits as any received document. A resolver
error is `ErrDereference`, wrapping the cause.

## Key resolvers run before authentication

`VerifyOptions.ResolveKeyName`, `ResolveX509` and `ResolveKeyInfoURI` resolve
a key that `ds:KeyInfo` only names: a `ds:KeyName`, `ds:X509Data` without a
certificate, and a `dsig11:KeyInfoReference` or `rawX509Certificate`
`ds:RetrievalMethod` to an absolute URI. Unlike `ResolveURI`, they must run
before the signature can be verified, so they see names and URIs from an
unauthenticated message: anyone can make them run. What bounds them:

* They are called only after every signature, digest and canonicalization
  algorithm has passed the allow-lists, and never when a key is pinned
  (`TestKeyResolversNotCalledBeforeAllowLists`).
* What they return is only a candidate key: `TrustKey` still judges it before
  any cryptographic work, and the signature must still verify under it. A
  certificate from `ResolveX509` must match every descriptor it was asked
  for, so a resolver that answers loosely cannot substitute another one.
* `ResolveKeyInfoURI` fetches one document, parsed with `xmlsec.Parse`, whose
  root must be `ds:KeyInfo`, or one DER certificate; a reference found there
  is not followed. It is the caller's server-side request forgery boundary
  exactly as `ResolveURI` is (see above), only reachable earlier: serve a
  fixed set of URIs, never an arbitrary fetch.
* `ResolveKeyName` and `ResolveX509` should look up keys the caller already
  holds, and should not fetch.

## Signature wrapping, and why Coverage exists

An attacker takes a legitimately signed message, moves the signed element
somewhere the application does not look — a wrapper element, an unused
header — and puts their own content where the application does look. The
signature still verifies, over the relocated original. An application that
reads the attacker's content believes it was signed.

Defences here:

* `Verify` returns `Coverage` as its primary result. The caller must check
  that it includes everything the profile requires, with
  `Coverage.CoversNodes` on the elements it will read, which compares by
  identity. `Coverage.Covers` compares IDs, and a wrapped document satisfies
  it: the signed element still carries its ID in its new place, while the
  unsigned element in the Body position carries none. Use `Covers` only
  when the element is then located by that same ID with `wss.FindByID`,
  which refuses a duplicated ID. Attachments have no node identity;
  `CoversAttachments` is safe when the part is read from the same
  `AttachmentSet` passed to `Verify`, which refuses a duplicated Content-ID.
* `Coverage` is built from what each reference actually digested during
  resolution, never inferred from the URI text. When an allowed XPath or
  XPath Filter 2.0 transform drops part of a reference's target (other than
  the signature itself), the target is not reported: an element only when
  all of its subtree was digested, the whole document only when nothing else
  was dropped. A reference through XSLT digests new content and reports no
  element, document or attachment. `TestXPathFilteredElementNotCovered`
  changes a filtered-out element and shows the signature still verifies and
  the element is not covered.
* `wss.FindByID` refuses an ID that appears more than once, across `wsu:Id`
  and `xml:id` together. With `IDAttributes` set, the refusal covers the
  whole effective set: a value carried by any two counted attributes, such
  as `wsu:Id` on one element and `ID` on another, is `ErrAmbiguousID`. Extra
  ID attributes are opt-in because each one widens what an attacker can use
  to plant a second target: with the default set, an `ID` or `Id` attribute
  is neither resolved nor counted. `xdm.ElementByID` is never used on the
  verify path: on duplicates it returns the first depth-first match
  (confirmed against go-xml v1.4.0), which is exactly the ambiguity the
  attack needs.
* The enveloped-signature transform removes the enclosing signature by
  identity, not every `ds:Signature` in the document. Over a node set parsed
  from octets it is refused (XML Signature §6.6.4): that tree holds no
  signature to remove, and a no-op there would hide the mistake.
* The unqualified `Id` of a signature's own `ds:Object` and `ds:KeyInfo`, and
  of a `ds:Manifest`, `ds:SignatureProperties` or `ds:SignatureProperty` in
  its `ds:Object`, counts as an ID for that signature's references only, as
  the XML Signature schema declares it, without `IDAttrDSig` and so without
  every unqualified `Id` in the document. The ambiguity rule covers it: the
  same value on any counted attribute anywhere in the document makes the
  reference `ErrAmbiguousID`, so it cannot be used to plant a second target.
* A `ds:Manifest`'s references are not part of the signature (§5.1).
  `VerifyManifest` follows one only when `Coverage.SignedElements` holds the
  Manifest or its `ds:Object`, refusing it otherwise with
  `ErrSignatureInvalid` before any reference is dereferenced, and checks its
  references under the same allow-lists, transform opt-ins and limits as a
  signature's. Its result is a separate `Coverage`, to be checked the same
  way.

`TestConformance_AP_10_SignatureCoverage` performs the relocation and checks
that `Coverage` exposes it.

## Algorithm downgrade

`VerifyOptions` and the `xenc.Decrypt*` functions take allow-lists, checked
before any cryptographic work. Pass exactly what your profile permits. An
empty list means the default set: every secure algorithm this library
implements, which is still broader than any single profile. An algorithm
kept only for legacy interoperability is outside the default set and is
accepted only when a caller names it.

## Deliberate refusals

| Refused | Why |
|---|---|
| Producing SHA-1 digests or signatures, DSA (with SHA-1 or SHA-256), HMAC-SHA1, `rsa-oaep-mgf1p`, SHA-1 OAEP digest or MGF, RSA v1.5, AES-CBC, 3DES or `kw-tripledes` | Weak, or open to the Bleichenbacher and CBC padding-oracle attacks (XML Encryption §6.1). The specifications require them, so they are implemented for **verification and decryption only**: never produced, never in a default set, accepted only when a caller names each one. The one other SHA-1 use is `ThumbprintSHA1`, a certificate identifier the X.509 Token Profile defines for token references; it selects nothing and protects nothing. |
| XSLT, XPath and XPath Filter 2.0 transforms whose program the caller did not allow | Each carries a program, and verifying would run the attacker's code on an unauthenticated message. By default all three are refused. `VerifyOptions.AllowedXPathExpressions` and `AllowedXSLTStylesheets` opt in for exact programs only: an expression must equal an allowed one with each of its prefixes bound to the allowed URI where it stands (a prefix rebinding is refused), and is compiled from the allow-list entry; a stylesheet must equal an allowed one under Exclusive C14N with every prefix the allowed one binds rendered, so a prefix used only inside an XPath expression cannot be rebound either. The check runs before any cryptographic work, so nothing is compiled or evaluated first. An allowed stylesheet runs with no module, schema, package, document, collection, text or environment resolver: `xsl:include`, `xsl:import`, `document()`, `doc()` and `unparsed-text()` fail and read nothing. On a `CipherReference`, XSLT and XPath Filter 2.0 stay refused; the XPath transform of Example 13, followed by base64, is accepted for `xenc.DecryptOptions.AllowedXPathExpressions` only, matched the same way, and checked before `ResolveURI` is called and before any decryption. It selects which text of the referenced document is the ciphertext, so an expression the sender chose could point decryption at other text; the allow-list keeps that choice the receiver's. |
| Unknown children of `ds:Transform`, `ds:CanonicalizationMethod` or `xenc:EncryptionMethod` | A transform's program is its child; ignoring unknown children would be a way round the allow-lists. XML Encryption §3.2 requires the `EncryptionMethod` refusal. |
| DOCTYPE | Entry point for XXE and entity expansion. `xmlsec.Parse` never enables it and never supplies an entity resolver; `TestParseRefusesXXE` asserts it for every variant in the assessment below. |
| Network or filesystem dereferencing by the library | Same-document references (`""`, `#id`, the two XPointer forms), `cid:` and a same-document `CipherReference`, of an `EncryptedData` or an `EncryptedKey`, resolve in the library. Any other absolute URI goes to the caller's `ResolveURI` and is refused without one; a relative URI is refused unless the caller's `BaseURI` (`SignOptions`, `VerifyOptions`, `DecryptOptions`) resolves it, never `xml:base`. `TestVerifyDereferencesNothingExternal` asserts that nothing is fetched without a resolver, and `TestResolverCalledOnlyForAuthenticSignatures` that a resolver is not called before the key is trusted and the signature value verified. See [External references](#external-references-and-the-resolver). |
| An SwA `EncryptedData` Type (`Attachment-Content-Only`, `Attachment-Complete`) used as a `ds:Transform` | The profile does not define them as signature transforms, and WS-Security peers refuse them; signing with one produced signatures no peer accepts. |
| An Attachment-Complete header repeated, or a decrypted header the SwA profile does not list | Which value a peer uses is undefined, and an unlisted header such as Content-Transfer-Encoding would change how the part is read. |
| RSA signing keys under 2048 bits | XML Signature §6.4.2 requires at least 2048 bits for creating signatures. Verification of smaller certificate keys is unchanged; raw RSA keys in `KeyInfo` need 2048 bits too. |
| KeyInfo forms other than those listed here, combinations of them, and, under `StrictX509Data`, descriptors that describe no carried certificate | Accepted, each with at most one `ds:KeyName` beside: `ds:X509Data` holding up to 16 certificates with exactly one leaf (the one that issued none of the others), `X509CRL` reported and children in other namespaces ignored; an `X509IssuerSerial`, `X509SKI`, `X509SubjectName` or `dsig11:X509Digest` beside the certificates selects nothing and is ignored, as Santuario ignores it (a real SMP signer ships a stale `X509SubjectName` after renewing its certificate), unless `StrictX509Data` requires each to describe one of them, an `X509Digest` algorithm under the digest allow-list; `ds:X509Data` without a certificate, through `ResolveX509`; a lone `ds:KeyValue` holding `ds:RSAKeyValue` or a `dsig11:ECKeyValue` with a `NamedCurve` for P-256, P-384 or P-521; a lone `dsig11:DEREncodedKeyValue` holding an RSA or ECDSA key on those curves; `ds:DSAKeyValue` or a DSA `DEREncodedKeyValue` for an explicitly allowed DSA signature only, with that algorithm's key size; a `ds:KeyName` alone, through `ResolveKeyName`; a `ds:RetrievalMethod` without transforms to a same-document element of its `Type` (`X509Data`, `RSAKeyValue`, `DSAKeyValue`, `ECKeyValue`, `DEREncodedKeyValue`), or through `ResolveKeyInfoURI` to a `rawX509Certificate`; a `dsig11:KeyInfoReference` to a `ds:KeyInfo` in the same document or, through `ResolveKeyInfoURI`, another. A reference is followed one hop only. Raw RSA keys need at least 2048 bits, an odd modulus, and an odd exponent from 3 to 2³¹−1. EC points must be uncompressed and on the curve. Refused: two leaves, under `StrictX509Data` a descriptor of a certificate not carried, explicit `ECParameters`, other curves, the RFC 4050 `ECDSAKeyValue`, `PGPData`, `SPKIData`, `MgmtData`, and any combination of forms. With a key pinned, an unsupported form is ignored rather than refused, and no resolver is called. |
| Finite-field Diffie-Hellman in a group under 2048 bits (section 5.6.2 allows 512), over 8192 bits, without Q, or other than the recipient's; a public value of 0, 1, P-1 or outside the order-Q subgroup | Logjam-class weak groups and small-subgroup attacks. `dh-es` and `dh` are implemented, OPTIONAL in XML Encryption 1.1, and accepted only when named. |
| A PBKDF2 iteration count under 1000 or over 10,000,000, a salt under 8 octets or not `Specified`, the HMAC-SHA1 PRF unless named | Weak parameters, and a sender-chosen cost. PBKDF2 is implemented, OPTIONAL, and accepted only when named. |

## Conformance

Checked requirement by requirement against the texts, with evidence in the
tests named in [testing.md](testing.md).

| Specification | Status |
|---|---|
| W3C XML Signature 1.1 | Every MUST met on generation and validation, including the base64 transform on node sets, parsing octets into a node set, the XPointer forms, `KeyInfoReference`, an omitted `URI` (through `ResolveOmittedURI`), and 2048-bit signing keys. The REQUIRED SHA-1, DSA-SHA1 with `DSAKeyValue` (1024/160 keys) and HMAC-SHA1, the RECOMMENDED RSA-SHA1, and the OPTIONAL DSA-SHA256 (2048/256 and 3072/256 keys) and ECDSA-SHA1, are implemented for verification only, as explicit opt-ins. The OPTIONAL SHA-224, RSA-SHA224 and ECDSA-SHA224 are outside the default sets and produced on request. The REQUIRED HMAC-SHA256, RECOMMENDED HMAC-SHA384/512 and OPTIONAL HMAC-SHA224 are also produced, with `SignOptions.HMACKey`, a caller's shared secret at least as long as the hash output, and no `KeyInfo`; on verification they stay outside the default set. HMAC takes its key only from `HMACKey` and enforces `HMACOutputLength` of at least half the hash and 80 bits, in whole bytes, on both sides (CVE-2009-0217). `ds:Object` (enveloping signatures), `ds:Manifest` (`BuildManifest`, `VerifyManifest`), `ds:SignatureProperties`, the `Id` of `SignedInfo`, `SignatureValue` and `KeyInfo`, a `KeyInfo` built before digesting so a reference can sign it (§4.5), an `InclusiveNamespaces` `PrefixList` on `CanonicalizationMethod`, and an omitted `URI` are produced on request. `Sign` refuses content and a `SignedInfo` not in NFC (§8.1.3); `Verify` does with `RequireNFC`. The RECOMMENDED XPath transform (with `here()`) and XPath Filter 2.0, and the OPTIONAL XSLT transform, are produced on request and verified as opt-ins for caller-allowed expressions and stylesheets only; the transform output matches Santuario byte for byte, and xmlsec1 verifies `here()`. XPath expressions are XPath 1.0 run in go-xml's XPath 1.0 compatibility mode of an XPath 2.0 engine, and stylesheets run on go-xml's XSLT processor, a version 1.0 stylesheet in its backwards-compatible mode. The RECOMMENDED HTTP dereferencing (§4.4.3.1) is met through the caller's `ResolveURI`: the library never fetches, and the octets go through the transforms as an octet stream; a relative URI is resolved against the caller's `BaseURI`, never the document's `xml:base`, and refused without one. `KeyInfo` (§4.5): `KeyName`, certificate chains in `X509Data` with the X.509 descriptors, `X509Digest` included, and `KeyInfoReference` are produced and verified, the descriptors checked against the certificates under `StrictX509Data`; same-document `RetrievalMethod` (without transforms, one hop), `X509CRL` (reported, not checked) and DER-encoded DSA keys are verified; a lone `KeyName`, a descriptor-only `X509Data`, an external `KeyInfoReference` and a `rawX509Certificate` `RetrievalMethod` are verified through caller resolvers, since the library never fetches. `PGPData`, `SPKIData` and `MgmtData` are not implemented. |
| W3C XML Encryption 1.1 | Every MUST met on the structures and processing rules, including Content encryption, same-document `CipherReference` and, through the caller's `ResolveURI`, an external one with no transform or the base64 transform, a relative one resolved against the caller's `DecryptOptions.BaseURI` (§3.3.1, never `xml:base`), `KeyInfo` resolution (`FindEncryptedKey`), NFC plaintext, `xmlns=""`, strict `EncryptionMethod` parsing, an `EncryptedKey` with a `CipherReference` (§3.3.1), `EncryptedKey` chains through `KeyReference`, `RetrievalMethod`, `CarriedKeyName` or an inline key (`FindEncryptedKey` on an `EncryptedKey`, one hop per call), `xenc11:DerivedKey` in `KeyInfo`, by `RetrievalMethod`, `DerivedKeyName` or its `ReferenceList` (`FindDerivedKey`, `DeriveKey`, `EncryptOptions.MasterKey`), an `AgreementMethod` directly under an `EncryptedData` (`DecryptAgreedDataKey`, `EncryptOptions.DirectKeyAgreement`), a `KA-Nonce` beside ECDH-ES and `dh-es` (accepted and ignored: ConcatKDF defines no use for it), an absent `EncryptionMethod` known to the recipient (`DecryptOptions.Implied*Algorithm`, still allow-listed), and the secure REQUIRED algorithms: AES-GCM, RSA-OAEP with explicit MGF, AES key wrap, ECDH-ES with ConcatKDF. The SHOULD and MAY of §2.1.4 and §4.3 step 2 (arbitrary octets, with `Type`, `MimeType` and `Encoding`, inline or by `CipherReference`: `EncryptOctets`), the decryptor's replacement of §4.1 and §4.5 (`DecryptAndReplace`, the plaintext parsed in the namespace context of the `EncryptedData`'s parent, the document element included), `EncryptionProperties` (§3.7) and the OPTIONAL XPath transform on a `CipherReference` (§3.3.1, Example 13, allow-listed like XML Signature's) are implemented; XSLT and XPath Filter 2.0 on a `CipherReference` are refused. `MimeType` and `Encoding` are advisory, emitted but never acted on. The OPTIONAL finite-field `dh-es` and `dh` (with its Legacy KDF, which section 5.6.2 makes mandatory for an implementation of DH) and PBKDF2, from a password or as a key agreement's KDF, are implemented as explicit opt-ins, outside every default set, as is MGF1 with SHA-224, produced only when named. A ConcatKDF parameter that is not a whole number of octets, such as Example 25's `PartyUInfo="03D8"`, is refused: an octet hash cannot take it. The REQUIRED legacy algorithms, AES-CBC, 3DES, `rsa-oaep-mgf1p` with SHA-1, `kw-tripledes`, and RSA v1.5 for 3DES keys, are implemented for decryption only, as explicit opt-ins. |
| OASIS SOAP Message Security 1.1.1 | Header elements prepended in processing order, SOAP attributes namespaced; `AssignID` never adds a `wsu:Id` beside an `xml:id` (§4); one header per actor or role, on sending and, through `wss.FindHeader`, on receipt (§5); direct, embedded (§7.4) and key identifier references, and `EncryptedKey` references by ID and by `EncryptedKeySHA1` (§7.7); `wsse11:TokenType` (§7.1); the STR Dereference Transform (§8.3) on signing and verification, the token of a key identifier or issuer serial built as §8.3 describes from the certificate a caller's resolver supplies, never fetched, and a reference that cannot be dereferenced a failure; `SignatureConfirmation` on both sides (§8.5); one timestamp, validated on receipt (§10); `EncryptedHeader` produced (§9.4.3, with a generated `Id` when none is given) and processed (§9.4.4, `xenc.DecryptHeader`: exactly one `EncryptedData`, the plaintext parsed in the header's context); the symmetric binding (§7.7, §9.4.1): an `EncryptedData` naming its `EncryptedKey` by a `SecurityTokenReference` (`EncryptOptions.DataKeyInfo`, followed one hop by `FindEncryptedKey`) under a standalone header `ReferenceList` (`wss.NewReferenceList`, read back by `xenc.ReferencedData`); the §12 fault codes through `wss.FaultCode`, with `FailedCheck` one generic `ErrDecryptionFailed` for every decryption failure. |
| OASIS X.509 Token Profile 1.1.1 | The X509v3, PKIPath and OPTIONAL PKCS7 token types; key identifier (SubjectKeyIdentifier, ThumbprintSHA1) and issuer-serial references, produced and matched, and placed in a signature's `ds:KeyInfo` through `SignOptions.KeyInfoElement` (§3.2). A PKCS7 token is read strictly (DER, `signedData` version 1 with `data` content, X.509 certificates only, at most 16) and its unordered certificates yield the one that issued none of the others, or `ErrUnsupportedKeyInfo`; its CRLs and signer infos are ignored, not verified. |
| OASIS SwA Profile 1.1.1 | Both signature transforms and both `EncryptedData` types, as WSS4J reads them; `Sign` refuses a `cid:` reference that does not begin with an SwA signature transform, or that carries the base64 transform (§5.4.4); `VerifyOptions.StrictBSP` refuses the first on receipt (R6101). |
| WS-I Basic Security Profile 1.1 | **Sending.** A signature conforms when it follows the profile's recipe: `KeyInfo: KeyInfoSecurityTokenReference` (with `SecurityTokenID`, or a key identifier or issuer serial as `KeyInfoElement`), Exclusive C14N for `ds:SignedInfo` and as the last transform of every same-document reference (or the STR Dereference Transform, or an SwA transform on a `cid:` reference). Encryption conforms in structure with RSA-OAEP and a `wsse:SecurityTokenReference` set on the `EncryptedKey` or as `DataKeyInfo`, but never in algorithm: R5620 and R5621 list only AES-CBC, 3DES, `rsa-1_5` and `rsa-oaep-mgf1p`, where this library encrypts with AES-GCM and XML Encryption 1.1 RSA-OAEP, which WSS4J accepts (deliberately not met; see [todo.md](todo.md#deliberately-not-met)). Not conforming, on request only: `KeyInfoX509Data` and every other `KeyInfo` form but a token reference (R5417); inclusive canonicalization, possible with `Parent` (R5404, R5423); a reference to an external URI without transforms (R5416); `RecipientHint`, the `EncryptedKey`'s `Recipient` attribute (R5602); and the `ds:KeyInfo` of ECDH-ES, finite-field DH, PBKDF2 or a derived key (R5424, R5426). **Receiving** is lenient by default. `dsig.VerifyOptions.StrictBSP` enforces the signature shape rules before any cryptographic work: R5404, R5401, R5402, R5417, R5403, R5440, R5416, R5411, R5423, R5412, R6101 and R3102, and through `wss.CheckSecurityTokenReference` R3061, R3027, R3062, R3054, R3063, R3070, R3071, R3069, R3072, R3060, R3056; it implies `StrictSecurityTokenReference`, which enforces R3059, R3058, R3074, R5215, R5212, R5205, R3066 and, with a pinned certificate, that a key identifier or issuer serial names it. `xenc.DecryptOptions.StrictBSP` enforces the encryption shape rules before any key is used: R3209, R5622, R5623, R5602 (no `Type`, `MimeType`, `Encoding` or `Recipient` on an `EncryptedKey`), R5424, R5426 (a `KeyInfo` holds exactly one `SecurityTokenReference`, so key agreement, PBKDF2 and `xenc11:DerivedKey` are refused under it, `DeriveKey` and `DecryptAgreedDataKey` included), R3228 (no `EncryptedData` directly in a SOAP Header) and R5629 (an `EncryptedData` no `EncryptedKey` names has a `KeyInfo`). R3230 (an `EncryptedHeader` holds exactly one `EncryptedData`) and R5601, R5603 (an `EncryptionMethod`) are enforced always, unless the caller supplies an implied algorithm. `wss.FindHeader` enforces R3206 and R3210, `wss.FindTimestamp` R3227, `wss.CheckUniqueIDs` R3204, and every token reference R3057, R3064 and R3211. The algorithm lists R5420, R5421, R5620, R5621, R5625 and R5626 are deliberately not enforced by either option: they name SHA-1, RSA-SHA1, HMAC-SHA1, CBC, 3DES, RSA v1.5 and `rsa-oaep-mgf1p`, which are verification- and decryption-only opt-ins here; the allow-lists decide algorithms. R3069 (`TokenType` on a reference to an `EncryptedKey`) is met by `wss.NewSecurityTokenReference` and `NewEncryptedKeyReference`, and checked by `CheckSecurityTokenReference` for an `EncryptedKeySHA1` key identifier. |

Every REQUIRED algorithm is therefore implemented. The weak ones are
verification- and decryption-only opt-ins: never produced, never in a
default set, accepted only when a caller names each one. HMAC-SHA2 is not
weak, and is produced; its security is that of the caller's shared secret,
which is why it is keyed only by `HMACKey` and never by anything in a message.

## Resource limits

All set explicitly rather than inherited, so an upstream default cannot
silently change what is accepted. Each is enforced before the work it bounds.

| Limit | Value | Where |
|---|---:|---|
| Parse depth | 1000 | `xmlsec.MaxParseDepth` |
| Document size | 64 MB | `xmlsec.MaxParseBytes` |
| Node count | 10,000,000 | `xmlsec.MaxParseNodes` |
| Canonicalization depth | 500 | `xmlsec.MaxC14NDepth`, applied to `c14n.MaxDepth` at init |
| References per signature | 64 | `dsig.DefaultMaxReferences`, or `VerifyOptions.MaxReferences`; counted before any is parsed |
| Transforms per reference | 8 | `dsig.MaxTransformsPerReference` |
| XPath evaluations per transform | one per input node | bounded by the node count above; an allowed expression is the caller's own, so its cost is too |
| XSLT output | 64 MB | `xmlsec.MaxParseBytes`, while it is written; over it is `ErrLimitExceeded` |
| Diffie-Hellman group size | 2048 to 8192 bits of P | `xenc.MinDHBits`, `xenc.MaxDHBits`, checked before any exponentiation |
| PBKDF2 iterations received | 1000 to 10,000,000 | `xenc.MinPBKDF2Iterations`, `xenc.MaxPBKDF2Iterations`, checked before any derivation; over the cap is `ErrLimitExceeded` |
| Entity expansion | per-parse budget | a fresh `xdm.EntityBudget`; moot while DOCTYPE is refused |

The two depth limits differ, so a document can parse and then fail to
canonicalize. That is a bounded outcome, not a bug.

**Bounded is not cheap.** Measured on an arm64 Mac, parsing costs up to
about 40 times the input in memory, before anything is authenticated:

| Input | Size | Outcome | Peak memory |
|---|---:|---|---:|
| 16M empty elements | 64 MB | refused at the node limit after 2.6 s | 2.7 GB |
| one element, many attributes | 60 MB | accepted | 2.3 GB |
| many namespace declarations | 60 MB | accepted | 1.5 GB |
| 1,000,000-deep nesting | 6.7 MB | refused at depth 1000 | 34 MB |
| over the byte limit | 65 MB | refused | 318 MB |

The pinned limits cannot be loosened.
A server should tighten them to what its profile needs with
`xmlsec.ParseWithLimits`: memory scales with `MaxBytes` and `MaxNodes`, so
tightening them bounds every row above.

Setting `c14n.MaxDepth` is process-global: it also bounds any other `c14n`
user in the same program.

## Documents with no canonical form

An XML 1.1 document, or one declaring a relative namespace URI, cannot be
canonicalized, so it can never be verified. `Verify` returns
`ErrUnverifiable` wrapping the `c14n` cause. Treat it as permanent: never
retry, and do not log the document content unbounded.

## Verification cost before the certificate is judged

With `VerifyOptions.Certificate` set, a signature from any other key is
rejected before a single reference is processed. With it nil, an attacker
can sign with their own key and embed their own certificate; the signature
is then valid, and every reference is digested before the caller sees
`Coverage.Certificate` and can refuse it. Measured: 64 references to one
8 MB element cost 5.1 s of CPU; the same message against a pinned
certificate is refused at once.

Pin the certificate, or the key with `VerifyOptions.PublicKey`, whenever the
sender is known in advance. When it is not,
set `VerifyOptions.TrustKey`: it sees the signer's key and
certificate before any cryptographic or digest work, so refusing an unknown sender costs
nothing. And set `MaxReferences` to what the profile needs (a WS-Security
message signing a header, a body and a few attachments needs well under 64).

## Other properties

* Digest comparison uses `crypto/subtle.ConstantTimeCompare`.
* Every failure of decryption itself wraps one exported error,
  `xmlsec.ErrDecryptionFailed`, with a fixed message and no cause: an
  RSA-OAEP transport that does not decrypt, an AES or 3DES key unwrap whose
  integrity check fails, an AES-GCM tag that does not verify, bad CBC
  padding, a data key of the wrong length, and a decrypted
  `wsse11:EncryptedHeader` that does not parse to one element (with CBC
  data, "did it parse" is itself an oracle). Report it as the WS-Security
  `wsse:FailedCheck` fault (SOAP Message Security §12) and never say which
  step failed. `TestDecryptionFailureIsGeneric` holds every cause to it.
  Structural refusals before any cryptographic work (`ErrMalformed`,
  `ErrAlgorithmNotAllowed`) stay distinct: they depend only on what the
  sender wrote, not on any key.
* CBC decryption, when allowed, returns one error for every failure, after
  decrypting the whole ciphertext and checking the padding in constant time.
  That narrows but cannot close the padding oracle, because CBC is
  unauthenticated: an attacker can still learn from what the application
  does next. Only AES-GCM closes it.
* `xenc.DecryptEncryptedKeyPKCS1v15` rejects implicitly: a bad PKCS#1 block
  yields a random key of the data algorithm's size, and the failure surfaces
  only as the generic data error. Give it a key pair used for nothing else
  (XML Encryption §6.1.3); a hardware `Decrypter` that fails faster on bad
  padding reopens the timing channel.
* RSA-OAEP and AES-GCM failures return a fixed message, not the cause.
* Session keys are returned to the caller, who should `clear` them after use.
  No key material is held in package state.
* A nil or wrong-kind argument to any exported function is an error, not a
  panic, so a lookup that found nothing in a hostile message cannot crash the
  caller.

## Assessment

Performed against every entry point, with each attack kept as a regression
test in `tests/security` or beside the package it exercises.

| Class | Attempt | Result |
|---|---|---|
| XXE | file, http and parameter entities; external and PUBLIC DTD subsets; after a comment and PI, behind a UTF-8 BOM, in UTF-16; undeclared entities in content and attributes | refused, no file read, no request made (a local listener counts attempts) |
| Entity expansion | billion laughs | refused: DOCTYPE |
| External references | XInclude, `xml-stylesheet`, `xsi:schemaLocation`, `xml:base` | parsed, nothing fetched or expanded |
| Remote dereferencing | authentic signatures whose references name `http:`, `file:`, `cid:` wrapping a URL, and an XPointer `document()`; a relative `CipherReference` under an `xml:base` naming a metadata address and `file:///etc/` | refused without a resolver, nothing fetched; with one, it is not called for an untrusted or wrong key, a disallowed algorithm, or a URI rewritten after signing; `xml:base` is never used as a base (`TestCipherReferenceBaseURINeverFromXMLBase`) |
| Transform programs | an attacker's XPath, XPath Filter 2.0 expression or stylesheet not in the allow-list, signed by the attacker against a pinned certificate; an allowed expression with its prefix rebound; the same two on a `CipherReference` (`TestCipherReferenceXPathRefusedBeforeFetch`, refused before the resolver is called); a stylesheet with a prefix rebound inside an XPath expression; an allowed stylesheet using `document()`, `doc()`, `unparsed-text()`, `xsl:include` or `xsl:import` on `file:` and `http:` URIs | refused before any cryptographic work; the stylesheets fetch nothing |
| Signature wrapping | relocated signed element; duplicated IDs across `wsu:Id` and `xml:id`, and across `ID`/`Id` and the defaults when configured; an attacker assertion carrying the signed SAML `ID` | `Coverage` exposes the relocation; duplicates refused, by `Verify` and for the whole message by `wss.CheckUniqueIDs` (`TestDuplicateIDsRefused`) |
| Token reference redirection | the unsigned reference of an STR Dereference Transform retargeted at another reference, a `wsse:Embedded` or a `ds:KeyInfo` | refused (`TestSTRTransformRetargetRefused`) |
| Signature confirmation replay | a response confirming a signature from an earlier exchange, none, or an unsigned request | refused (`TestSignatureConfirmationMismatch`) |
| Profile violations under `StrictBSP` | inclusive `SignedInfo`, an enveloping reference, a `ds:Manifest`, an XSLT transform | refused before `TrustKey` or any cryptographic work (`TestStrictBSPRefusesBeforeCrypto`) |
| Key substitution | attacker's key and certificate against a pinned certificate | refused |
| Key description | an `X509IssuerSerial`, `X509SKI`, `X509SubjectName` or `X509Digest` of another certificate beside the signer's, under `StrictX509Data`; a chain with two leaves; a lone `KeyName`, a descriptor-only `X509Data` and external `KeyInfoReference` and `RetrievalMethod` URIs under a disallowed signature or digest algorithm, and with a pinned key | refused; the key resolvers are not called (`TestX509DescriptorMismatchRefused`, `TestKeyResolversNotCalledBeforeAllowLists`) |
| Algorithm confusion | HMAC, RSA-SHA1, empty method, ECDSA URI with an RSA key and the reverse, ECDSA r = s = 0 | refused |
| Comment truncation (CVE-2017-11427 class) | signed text split by a comment | `StringValue` of the covered element returns the whole value |
| Encryption downgrade | AES size swap, AES-CBC, 3DES, `rsa-oaep-mgf1p`, `rsa-1_5`, SHA-1 MGF and digest | refused under empty allow-lists; each decrypts only when named |
| Diffie-Hellman key agreement | `dh-es`, `dh` and PBKDF2 under empty allow-lists; public values 0, 1, P-1, P and of order 2Q; 512-bit and 16384-bit originator groups; another generator | refused; an oversized group is refused before any arithmetic in it (`TestDHSubgroupAndGroupAttacksRefused`) |
| PBKDF2 cost | `IterationCount` 4,000,000,000, 10,000,001 and past `int`; 999 and 1 | refused before any derivation, in under 250 ms (`TestPBKDF2IterationCountBounded`) |
| HMAC truncation (CVE-2009-0217) | `HMACOutputLength` 0, 8, 72, 79, 81, 120, 132; HMAC keyed with the certificate; `Sign` asked for 120, 130 or 264 bits, a key shorter than the hash, or a `KeyInfo` | refused |
| Manifest | a Manifest the signature does not cover, one from another document, one whose target changed | refused (`TestVerifyManifestRefusals`, `TestManifest`) |
| Crashes | nil and wrong-kind arguments to every exported function; three fuzz targets | fixed: 13 functions panicked on nil and now return errors |
| Resource exhaustion | limits in parsing, depth, references, transforms | bounded; see the memory and verification-cost sections above |

## What a caller must still do

1. Decide whether `Coverage.Certificate`, or `Coverage.PublicKey` when
   there is no certificate, is trusted.
2. Check `Coverage` against the profile, every time.
3. Pass single-value allow-lists for the profile.
4. Parse with `xmlsec.Parse`, and keep the received octets.
5. Tighten the parse limits with `ParseWithLimits`, and pin the certificate
   or judge it in `TrustKey`; see the cost sections above.
6. Transmit `SignEnveloped` and `EncryptElement` output exactly, never
   re-serialized.
