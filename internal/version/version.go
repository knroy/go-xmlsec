// Package version holds the go-xmlsec module's release version.
//
// Internal, because the version is not part of the API.
package version

// Version is the release of go-xmlsec this source tree is, without the
// leading "v". "0.0.0" means nothing has been released yet.
//
// EDITED BY HAND, as the first step of the procedure in RELEASE.md: bump
// this, rename the CHANGELOG.md heading from Unreleased to the same version,
// commit, then push the tag. The constant is the source of truth and the tag
// follows it. Two checks keep them together:
//
//   - TestVersionIsReleasedAndDescribed, in every CI run: this is a v0
//     release triple, and CHANGELOG.md has a section for exactly it.
//   - release.yml, on the tag push: the tag must equal this constant.
//
// The major version stays 0 until the acceptance criteria in docs/todo.md
// hold. A v1 tag on a security library is a claim that cannot be withdrawn.
const Version = "0.0.0"
