# Releasing

**The constant is the source of truth; the tag follows it.**

`internal/version/version.go` holds `const Version = "X.Y.Z"`, edited by hand.
What CI asserts and what the release workflow refuses are both derived from
that line. `0.0.0` means nothing has been released.

| Check | Runs on | Fails when |
|---|---|---|
| `TestVersionIsReleasedAndDescribed` | every push and pull request | the constant is not a `0.N.N` triple; `CHANGELOG.md` has no `## vX.Y.Z` section for it; an `## Unreleased` heading sits below that section |
| `release.yml` | the tag push | the tag does not equal the constant; the changelog section is missing or empty |

## Staying on v0

The major version is 0 until the acceptance criteria in
[docs/todo.md](docs/todo.md) hold — in particular Gate 2 and a green interop
harness against two independent implementations. A `v1.0.0` on a security
library says "independently validated", and a module version is permanent
once the Go proxy has seen it. The test enforces the 0.

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
4. Creates the GitHub release, marked pre-release while on v0, with the
   changelog section as its body.

Steps 1–3 write nothing: on failure, delete the tag, fix, re-tag.

## Before bumping go-xml

A `go-xml/c14n` change that alters canonical output by one byte invalidates
every signature this module has produced. Read the go-xml changelog before
bumping the pin, and record the bump in this changelog as a security-relevant
change.

## Checklist

- [ ] `internal/version/version.go` bumped
- [ ] `CHANGELOG.md` heading renamed, section non-empty, hashes filled in
- [ ] committed, pushed, CI green
- [ ] annotated tag pushed
- [ ] the Release workflow went green and the release has the right notes
