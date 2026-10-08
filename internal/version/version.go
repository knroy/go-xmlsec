// Package version holds the go-xmlsec module's release version.
//
// Internal, because the version is not part of the API.
package version

// Version is the release of go-xmlsec this source tree is, without the
// leading "v".
//
// EDITED BY HAND, as the first step of the procedure in RELEASE.md: bump
// this, rename the CHANGELOG.md heading from Unreleased to the same version,
// commit, then push the tag. The constant is the source of truth and the tag
// follows it. Two checks keep them together:
//
//   - TestVersionIsReleasedAndDescribed, in every CI run: this is a v1
//     release triple, and the newest released section of CHANGELOG.md is
//     for exactly it.
//   - release.yml, on the tag push: the tag must equal this constant.
//
// The major version is 1: a breaking change to the API needs a new module
// path, github.com/knroy/go-xmlsec/v2, not a new version of this one.
const Version = "1.3.0"
