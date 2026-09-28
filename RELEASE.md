# Releasing

**The constant is the source of truth; the tag follows it.**

`internal/version/version.go` holds `const Version = "X.Y.Z"`, edited by hand.
What CI asserts and what the release workflow refuses are both derived from
that line.

| Check | Runs on | Fails when |
|---|---|---|
| `TestVersionIsReleasedAndDescribed` | every push and pull request | the constant is not a `1.N.N` triple; `CHANGELOG.md` has no `## vX.Y.Z` section for it; an `## Unreleased` heading sits below that section |
| `release.yml` | the tag push | the tag does not equal the constant; the changelog section is missing or empty |

## Compatibility within v1

`v1.0.0` promises every exported name. Within v1, a minor release may add API
and a patch release only fixes; neither removes or changes anything exported.
A breaking change needs the module path `github.com/knroy/go-xmlsec/v2`.
`TestVersionIsReleasedAndDescribed` enforces the major version 1, so moving
past it is a deliberate change to that test. A module version is permanent
once the Go proxy has seen it.

A security fix that can only be made by refusing input v1 accepted, such as a
newly broken algorithm leaving a default set, is made in a minor release and
called out in the changelog: refusing an attack is not an API break.

## Steps

In this order; the version commit precedes the tag.

1. **Edit `internal/version/version.go`.** Set `Version`, without the `v`.
2. **Rename the changelog heading.** `## Unreleased` becomes
   `## vX.Y.Z — YYYY-MM-DD`. The release notes are that section verbatim, so it
   must not be empty. Replace any `*this commit*` placeholders with hashes.
3. **Commit and push, and wait for CI to go green.**

   ```
   git add internal/version/version.go CHANGELOG.md
   git commit -m "release: vX.Y.Z"
   git push
   ```

4. **Tag and push the tag.**

   ```
   git tag -a vX.Y.Z -m "go-xmlsec vX.Y.Z"
   git push origin vX.Y.Z
   ```

## What the workflow then does

1. Refuses a tag that disagrees with the constant.
2. Refuses a missing or empty changelog section, and extracts it.
3. Runs `go vet` and `go test -race` on the tagged commit.
4. Creates the GitHub release, with the changelog section as its body.

Steps 1–3 write nothing: on failure, delete the tag, fix, re-tag.

## Before bumping go-xml

A `go-xml/c14n` change that alters canonical output by one byte invalidates
every signature this module has produced. Read the go-xml changelog before
bumping the pin, and record the bump in this changelog as a security-relevant
change.

## The Go version floor

`go.mod` says `go 1.26.0`, a choice rather than an accident. Measured by
building with older toolchains:

* **Go 1.25** is the lowest possible: `go-xml` v1.4.0 itself requires it.
* **Go 1.26** is required by one call, `rsa.EncryptOAEPWithOptions`
  (`xenc/keytransport.go`), the only standard library way to encrypt
  RSA-OAEP with an MGF digest different from the OAEP digest. A 1.25 build
  would have to refuse `MGFAlgorithm` unequal to `DigestAlgorithm` on
  encryption, which XML Encryption 1.1 allows and the tests exercise.
* The code also relies on 1.26 behaviour: `ecdh` key generation ignores its
  reader and always uses the secure source, and `crypto/rand.Read` never
  returns an error (since 1.24).

Lowering the floor means giving up divergent-MGF encryption; it is not
planned unless a consumer needs it.

## Checklist

- [ ] `internal/version/version.go` bumped
- [ ] `CHANGELOG.md` heading renamed, section non-empty, hashes filled in
- [ ] committed, pushed, CI green
- [ ] annotated tag pushed
- [ ] the Release workflow went green and the release has the right notes
