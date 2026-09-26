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
  trust anchors. When `VerifyOptions.Certificate` is nil, the certificate
  comes from the message itself, so a nil error proves only that the message
  is self-consistent.
* **That the elements you will read are the ones that were signed.** See
  below.

## Signature wrapping, and why Coverage exists

An attacker takes a legitimately signed message, moves the signed element
somewhere the application does not look — a wrapper element, an unused
header — and puts their own content where the application does look. The
signature still verifies, over the relocated original. An application that
reads the attacker's content believes it was signed.

Defences here:

* `Verify` returns `Coverage` as its primary result. The caller must check
  that it includes everything the profile requires, and when elements are
  located by position, compare `SignedElements` by identity.
* `Coverage` is built from what each reference actually digested during
  resolution, never inferred from the URI text.
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
  identity, not every `ds:Signature` in the document.

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
| Producing SHA-1 digests or signatures, DSA, HMAC, `rsa-oaep-mgf1p`, SHA-1 OAEP digest or MGF, RSA v1.5, AES-CBC, 3DES or `kw-tripledes` | Weak, or open to the Bleichenbacher and CBC padding-oracle attacks (XML Encryption §6.1). The specifications require them, so they are implemented for **verification and decryption only**: never produced, never in a default set, accepted only when a caller names each one. The one other SHA-1 use is `ThumbprintSHA1`, a certificate identifier the X.509 Token Profile defines for token references; it selects nothing and protects nothing. |
| XSLT transform | Executes attacker-supplied code while verifying an unauthenticated message. OPTIONAL in XML Signature, so refusing it is conformant. |
| XPath and XPath Filter 2.0 transforms, on a `ds:Reference` or a `CipherReference` | Evaluate attacker-supplied expressions during verification. RECOMMENDED, not required, by XML Signature; `go-xml` makes XPath Filter implementable, and the threat model is unchanged. |
| Unknown children of `ds:Transform`, `ds:CanonicalizationMethod` or `xenc:EncryptionMethod` | A refused transform carries its program as a child; ignoring unknown children would be a way round the refusal. XML Encryption §3.2 requires the `EncryptionMethod` refusal. |
| DOCTYPE | Entry point for XXE and entity expansion. `xmlsec.Parse` never enables it and never supplies an entity resolver; `TestParseRefusesXXE` asserts it for every variant in the assessment below. |
| Network or filesystem dereferencing | Only same-document references (`""`, `#id`, the two XPointer forms), `cid:` and a same-document `CipherReference` resolve. `TestVerifyDereferencesNothingExternal` asserts it with an authentic signature. XML Signature RECOMMENDS HTTP dereferencing; refusing it removes a server-side request forgery surface. |
| An SwA `EncryptedData` Type (`Attachment-Content-Only`, `Attachment-Complete`) used as a `ds:Transform` | The profile does not define them as signature transforms, and WS-Security peers refuse them; signing with one produced signatures no peer accepts. |
| An Attachment-Complete header repeated, or a decrypted header the SwA profile does not list | Which value a peer uses is undefined, and an unlisted header such as Content-Transfer-Encoding would change how the part is read. |
| RSA signing keys under 2048 bits | XML Signature §6.4.2 requires at least 2048 bits for creating signatures. Verification of smaller certificate keys is unchanged; raw RSA keys in `KeyInfo` need 2048 bits too. |
| KeyInfo forms other than a certificate, a token reference, a lone raw key, or a same-document `KeyInfoReference` | Accepted: `ds:X509Data` with exactly one `ds:X509Certificate` (with `X509SubjectName`, `X509IssuerSerial`, `X509SKI` beside it ignored); a lone `ds:KeyValue` holding `ds:RSAKeyValue` or a `dsig11:ECKeyValue` with a `NamedCurve` for P-256, P-384 or P-521; a lone `dsig11:DEREncodedKeyValue` holding an RSA or ECDSA key on those curves; a `dsig11:KeyInfoReference` to a `ds:KeyInfo` in the same document, never to another reference. Raw RSA keys need at least 2048 bits, an odd modulus, and an odd exponent from 3 to 2³¹−1. EC points must be uncompressed and on the curve. Refused: a second certificate, explicit `ECParameters`, other curves, `DSAKeyValue` (except for an explicitly allowed `dsa-sha1`), the RFC 4050 `ECDSAKeyValue`, `RetrievalMethod`, `X509Digest`, and any combination of forms. With a key pinned, an unsupported form is ignored rather than refused. |
| Finite-field `dh-es`, PBKDF2 | OPTIONAL in XML Encryption 1.1. |

## Conformance

Checked requirement by requirement against the texts, with evidence in the
tests named in [testing.md](testing.md).

| Specification | Status |
|---|---|
| W3C XML Signature 1.1 | Every MUST met on generation and validation, including the base64 transform on node sets, parsing octets into a node set, the XPointer forms, `KeyInfoReference`, an omitted `URI` (through `ResolveOmittedURI`), and 2048-bit signing keys. The REQUIRED SHA-1, DSA-SHA1 with `DSAKeyValue` (1024/160 keys) and HMAC-SHA1/SHA256, and the RECOMMENDED RSA-SHA1 and HMAC-SHA384/512, are implemented for verification only, as explicit opt-ins; HMAC takes its key only from `VerifyOptions.HMACKey` and enforces `HMACOutputLength` of at least half the hash and 80 bits, in whole bytes (CVE-2009-0217). **Not met**, as RECOMMENDED only: the XPath transforms and HTTP dereferencing. |
| W3C XML Encryption 1.1 | Every MUST met on the structures and processing rules, including Content encryption, same-document `CipherReference`, `KeyInfo` resolution (`FindEncryptedKey`), NFC plaintext, `xmlns=""`, strict `EncryptionMethod` parsing, and the secure REQUIRED algorithms: AES-GCM, RSA-OAEP with explicit MGF, AES key wrap, ECDH-ES with ConcatKDF. The REQUIRED legacy algorithms, AES-CBC, 3DES, `rsa-oaep-mgf1p` with SHA-1, `kw-tripledes`, and RSA v1.5 for 3DES keys, are implemented for decryption only, as explicit opt-ins. |
| OASIS SOAP Message Security 1.1.1, X.509 Token Profile 1.1.1 | Header elements prepended in processing order, SOAP attributes namespaced, one timestamp validated on receipt, direct, key identifier and issuer-serial references, `wsse11:TokenType`, `EncryptedHeader`. PKCS7 tokens are not implemented (OPTIONAL). |
| WS-I Basic Security Profile 1.1 | Output conforms, except R5620 and R5621, which list only AES-CBC, 3DES, `rsa-1_5` and `rsa-oaep-mgf1p`: this library encrypts with AES-GCM and XML Encryption 1.1 RSA-OAEP, which WSS4J accepts. Receiving is lenient by default; `StrictSecurityTokenReference` and `RequireExplicitCanonicalization` enforce the profile's rules on what is received. |

Every REQUIRED algorithm is therefore implemented. The weak ones are
verification- and decryption-only opt-ins: never produced, never in a
default set, accepted only when a caller names each one.

## Resource limits

All set explicitly rather than inherited, so an upstream default cannot
silently change what is accepted. Each is enforced before the work it bounds.

| Limit | Value | Where |
|---|---:|---|
| Parse depth | 1000 | `xmlsec.MaxParseDepth` |
| Document size | 64 MB | `xmlsec.MaxParseBytes` |
| Node count | 10,000,000 | `xmlsec.MaxParseNodes` |
| Canonicalization depth | 500 | `xmlsec.MaxC14NDepth`, applied to `c14n.MaxDepth` at init |
| References per signature | 64 | `VerifyOptions.MaxReferences`, counted before any is parsed |
| Transforms per reference | 8 | `dsig.MaxTransformsPerReference` |
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
* A decryption failure after a key is unwrapped returns one generic error,
  whatever the cause.
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
| Remote dereferencing | authentic signatures whose references name `http:`, `file:`, `cid:` wrapping a URL, and an XPointer `document()` | refused, nothing fetched |
| Signature wrapping | relocated signed element; duplicated IDs across `wsu:Id` and `xml:id`, and across `ID`/`Id` and the defaults when configured; an attacker assertion carrying the signed SAML `ID` | `Coverage` exposes the relocation; duplicates refused |
| Key substitution | attacker's key and certificate against a pinned certificate | refused |
| Algorithm confusion | HMAC, RSA-SHA1, empty method, ECDSA URI with an RSA key and the reverse, ECDSA r = s = 0 | refused |
| Comment truncation (CVE-2017-11427 class) | signed text split by a comment | `StringValue` of the covered element returns the whole value |
| Encryption downgrade | AES size swap, AES-CBC, 3DES, `rsa-oaep-mgf1p`, `rsa-1_5`, SHA-1 MGF and digest | refused under empty allow-lists; each decrypts only when named |
| HMAC truncation (CVE-2009-0217) | `HMACOutputLength` 0, 8, 72, 79, 81, 120, 132; HMAC keyed with the certificate | refused |
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
