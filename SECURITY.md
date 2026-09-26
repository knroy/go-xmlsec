# Security Policy

## Reporting a vulnerability

Report privately, not as a public issue: open a
[security advisory](https://github.com/knroy/go-xmlsec/security/advisories/new),
or email <rax.komol@gmail.com>.

Include a minimal reproducing document, and the key or certificate if the
issue needs one. A concrete input is worth more than a description.

Expect an acknowledgement within a week. This is a single-maintainer project,
not a vendor with an on-call rotation; factor that in before depending on it.

## Supported versions

The latest v1 release. Fixes are released as a new v1 minor or patch
version, not backported.

## What counts as a vulnerability

* **A signature accepted that should not be.** A tampered document, an
  attachment, a relocated element or a duplicated ID that `dsig.Verify`
  passes with a `Coverage` that does not reveal it.
* **An algorithm accepted outside the caller's allow-list**, or SHA-1 accepted
  in any role.
* **Plaintext or key material recoverable** from `xenc` output, or a
  decryption error detailed enough to act as an oracle.
* **Resource exhaustion** disproportionate to the input, past the limits in
  [docs/security.md](docs/security.md).
* **A panic on any input.**

## What does not

* **Trusting a certificate.** `dsig.Verify` makes no trust decision; that is
  the caller's job, by design.
* **Ignoring `Coverage`.** A valid signature over the wrong elements is
  reported as exactly that. A caller that does not check `Coverage` has the
  vulnerability, not this library.
* **The refusals.** SHA-1 is refused on purpose, and the XPath, XPath
  Filter 2.0 and XSLT transforms by default. What an allowed expression or
  stylesheet does is the caller's choice; a way to run one that is not
  allowed, or to make an allowed stylesheet read a resource, is in scope.
* **Canonicalization defects** belong to
  [go-xml](https://github.com/knroy/go-xml/security) — though a report here is
  welcome and will be forwarded.

[docs/security.md](docs/security.md) has the threat model, the limits and what
a caller must still do.
