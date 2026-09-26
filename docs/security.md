# Security

## Threat model

This library is used to verify signatures on messages someone else wrote,
which is exactly where a subtle bug becomes a vulnerability. It is also the
place where a defect is silent: a wrong signature does not fail locally, a
peer rejects it with no diagnostic.

What `dsig.Verify` establishes, and all it establishes:

> The signature was made by the key in `Coverage.Certificate`, over exactly
> the nodes and attachments listed in `Coverage`.

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
  and `xml:id` together. `xdm.ElementByID` is never used on the verify path:
  on duplicates it returns the first depth-first match (confirmed against
  go-xml v1.4.0), which is exactly the ambiguity the attack needs.
* The enveloped-signature transform removes the enclosing signature by
  identity, not every `ds:Signature` in the document.

`TestConformance_AP_10_SignatureCoverage` performs the relocation and checks
that `Coverage` exposes it.

## Algorithm downgrade

`VerifyOptions` and the `xenc.Decrypt*` functions take allow-lists, checked
before any cryptographic work. Pass exactly what your profile permits. An
empty list means every algorithm implemented here, which is broader than any
single profile.

## Deliberate refusals

| Refused | Why |
|---|---|
| SHA-1, anywhere | Nothing in the target profiles needs it. Not behind a flag. |
| `rsa-oaep-mgf1p`, and RSA-OAEP without an explicit MGF or digest | Both mean SHA-1 by specification default. |
| XSLT transform | Executes attacker-supplied code while verifying an unauthenticated message. |
| XPath and XPath Filter 2.0 transforms | Evaluate attacker-supplied expressions during verification. `go-xml` v1.4.0 makes XPath Filter implementable; the threat model is unchanged. |
| Unknown children of `ds:Transform` or `ds:CanonicalizationMethod` | A refused transform carries its program as a child; ignoring unknown children would be a way round the refusal. |
| DOCTYPE | Entry point for XXE and entity expansion. `xmlsec.Parse` never enables it and never supplies an entity resolver; `TestParseRefusesDOCTYPE` asserts it. |
| Network or filesystem dereferencing | Only `""`, `#id` and `cid:` references resolve. |
| KeyInfo forms other than one `X509Certificate` or a direct `SecurityTokenReference` | Issuer-and-serial and thumbprint references are legal but are not emitted, so they are not tested, so they are not accepted. |

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

Setting `c14n.MaxDepth` is process-global: it also bounds any other `c14n`
user in the same program.

## Documents with no canonical form

An XML 1.1 document, or one declaring a relative namespace URI, cannot be
canonicalized, so it can never be verified. `Verify` returns
`ErrUnverifiable` wrapping the `c14n` cause. Treat it as permanent: never
retry, and do not log the document content unbounded.

## Other properties

* Digest comparison uses `crypto/subtle.ConstantTimeCompare`.
* RSA-OAEP and AES-GCM failures return a fixed message, not the cause.
* Session keys are returned to the caller, who should `clear` them after use.
  No key material is held in package state.

## What a caller must still do

1. Decide whether `Coverage.Certificate` is trusted.
2. Check `Coverage` against the profile, every time.
3. Pass single-value allow-lists for the profile.
4. Parse with `xmlsec.Parse`, and keep the received octets.
5. Transmit `SignEnveloped` and `EncryptElement` output exactly, never
   re-serialized.
