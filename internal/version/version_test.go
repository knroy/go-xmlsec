package version

import (
	"os"
	"regexp"
	"slices"
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
	// The constant names the newest release: the first "## " heading is its
	// section, or "## Unreleased" directly above it.
	var headings []string
	for _, m := range regexp.MustCompile(`(?m)^## (\S+)`).FindAllSubmatch(log, -1) {
		headings = append(headings, string(m[1]))
	}
	if len(headings) > 0 && headings[0] == "Unreleased" {
		headings = headings[1:]
	}
	if len(headings) == 0 || headings[0] != "v"+Version {
		t.Fatalf("the newest CHANGELOG.md section is not \"## v%s\"; rename \"## Unreleased\" as part of the release commit", Version)
	}
	if slices.Contains(headings, "Unreleased") {
		t.Fatal("CHANGELOG.md has an \"## Unreleased\" heading below the released section: the heading was never renamed")
	}
}
