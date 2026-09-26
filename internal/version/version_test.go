package version

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestVersionIsReleasedAndDescribed(t *testing.T) {
	if !regexp.MustCompile(`^1\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`).MatchString(Version) {
		t.Fatalf("Version %q is not a v1 release triple; see RELEASE.md", Version)
	}
	log, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^## v` + regexp.QuoteMeta(Version) + `( |$)`).Match(log) {
		t.Fatalf("CHANGELOG.md has no \"## v%s\" section; rename \"## Unreleased\" as part of the release commit", Version)
	}
	if rel := strings.Index(string(log), "## v"+Version); strings.Contains(string(log[rel:]), "## Unreleased") {
		t.Fatal("CHANGELOG.md has an \"## Unreleased\" heading below the released section: the heading was never renamed")
	}
}
