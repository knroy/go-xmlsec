# Documentation

* **[Usage](usage.md)** — signing and verifying (WS-Security, enveloped and
  enveloping), transforms and key information, encrypting keys, elements,
  attachments and octets, key agreement, and the order to compose them in.
* **[Security](security.md)** — the threat model, what `Coverage` is for, the
  deliberate refusals, the resource limits and their measured cost, the
  security assessment and its results, and what a caller must still do.
* **[Testing](testing.md)** — what runs, the conformance test IDs, how to run
  any of it, and what is not tested yet.
* **[Migrating to v2](migrating-to-v2.md)** — for go-xmlsec v1 users: the
  module path, go-xml v2's frozen trees, `xmlsec.Document`, and before/after
  code for every changed call.
* **[TODO](todo.md)** — open work against the specifications: none, and what
  is deliberately not met, and why.
* **[CHANGELOG.md](../CHANGELOG.md)** — every change, with the commit.
* **[Releasing](../RELEASE.md)** — the four steps, and why the version is a
  hand-edited constant.

Start with [security.md](security.md) if you are here to verify signatures on
messages you did not write. It is the part most likely to matter.
