package main

import (
	"strings"
	"testing"
)

func TestVersionStringUsesInjectedReleaseMetadata(t *testing.T) {
	oldVersion, oldRelease := buildVersion, buildRelease
	oldCommit, oldDirty := buildCommit, buildDirty
	oldDate, oldTarget := buildDate, buildTarget
	defer func() {
		buildVersion, buildRelease = oldVersion, oldRelease
		buildCommit, buildDirty = oldCommit, oldDirty
		buildDate, buildTarget = oldDate, oldTarget
	}()

	buildVersion = "1.2.3"
	buildRelease = "4"
	buildCommit = "abc123def456"
	buildDirty = "true"
	buildDate = "2026-06-20T00:00:00Z"
	buildTarget = "linux/amd64"

	got := versionString()
	wantParts := []string{
		"weaverssh 1.2.3-4",
		"commit=abc123def456",
		"dirty=true",
		"date=2026-06-20T00:00:00Z",
		"target=linux/amd64",
	}
	for _, want := range wantParts {
		if !strings.Contains(got, want) {
			t.Fatalf("versionString() = %q, missing %q", got, want)
		}
	}
}
