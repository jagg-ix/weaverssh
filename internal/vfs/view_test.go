package vfs

import (
	"path/filepath"
	"testing"

	"weaverssh/internal/p9client"
)

func sampleView() ViewConfig {
	return ViewConfig{
		Version: ViewVersion,
		Rules: []ViewRule{
			{Action: ViewActionHide, Match: ".git"},
			{Action: ViewActionHide, Match: "docs/private"},
			{Action: ViewActionRename, Match: "docs", To: "Documentation"},
		},
	}
}

func TestViewPathRoundTripAndHide(t *testing.T) {
	view := sampleView()

	source, hidden, err := view.SourcePath("Documentation/api/readme.md")
	if err != nil {
		t.Fatal(err)
	}
	if source != "docs/api/readme.md" || hidden {
		t.Fatalf("SourcePath = %q hidden=%v, want docs/api/readme.md false", source, hidden)
	}

	visible, hidden, err := view.VisiblePath("docs/api/readme.md")
	if err != nil {
		t.Fatal(err)
	}
	if visible != "Documentation/api/readme.md" || hidden {
		t.Fatalf("VisiblePath = %q hidden=%v, want Documentation/api/readme.md false", visible, hidden)
	}

	for _, p := range []string{".git", ".git/config", "docs/private", "docs/private/secret.txt", "a/.git/config"} {
		if _, hidden, err := view.VisiblePath(p); err != nil || !hidden {
			t.Fatalf("VisiblePath(%q) hidden=%v err=%v, want hidden", p, hidden, err)
		}
	}
	if _, hidden, err := view.SourcePath("Documentation/private/secret.txt"); err != nil || !hidden {
		t.Fatalf("SourcePath renamed hidden path hidden=%v err=%v, want hidden", hidden, err)
	}
}

func TestViewAppliesListProjection(t *testing.T) {
	view := sampleView()
	entries := []p9client.DirEntry{
		{Name: ".git", IsDir: true},
		{Name: "docs", IsDir: true},
		{Name: "README.md", Size: 42},
	}
	projected, err := view.ApplyList("", "", entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(projected) != 2 {
		t.Fatalf("projected len=%d entries=%+v, want 2", len(projected), projected)
	}
	if projected[0].Name != "Documentation" || !projected[0].IsDir {
		t.Fatalf("first projected entry=%+v, want renamed Documentation dir", projected[0])
	}
	if projected[1].Name != "README.md" {
		t.Fatalf("second projected entry=%+v, want README.md", projected[1])
	}

	docEntries := []p9client.DirEntry{
		{Name: "api", IsDir: true},
		{Name: "private", IsDir: true},
	}
	projected, err = view.ApplyList("docs", "Documentation", docEntries)
	if err != nil {
		t.Fatal(err)
	}
	if len(projected) != 1 || projected[0].Name != "api" {
		t.Fatalf("nested projection=%+v, want only api", projected)
	}
}

func TestViewConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvViewConfig, filepath.Join(dir, "view.json"))
	want := sampleView()
	if err := SaveView(want); err != nil {
		t.Fatalf("SaveView: %v", err)
	}
	got, err := LoadView()
	if err != nil {
		t.Fatalf("LoadView: %v", err)
	}
	if got.Version != ViewVersion || len(got.Rules) != len(want.Rules) {
		t.Fatalf("LoadView=%+v want %+v", got, want)
	}
	if got.Rules[2].Match != "docs" || got.Rules[2].To != "Documentation" {
		t.Fatalf("rename rule not preserved: %+v", got.Rules[2])
	}
}

func TestViewRejectsUnsafeRules(t *testing.T) {
	bad := []ViewConfig{
		{Version: ViewVersion, Rules: []ViewRule{{Action: ViewActionHide, Match: "../secret"}}},
		{Version: ViewVersion, Rules: []ViewRule{{Action: ViewActionRename, Match: "docs/*", To: "Documentation"}}},
		{Version: ViewVersion, Rules: []ViewRule{{Action: ViewActionRename, Match: "docs", To: "../Documentation"}}},
		{Version: "unknown", Rules: []ViewRule{{Action: ViewActionHide, Match: "tmp"}}},
	}
	for _, cfg := range bad {
		if _, err := cfg.Normalize(); err == nil {
			t.Fatalf("Normalize(%+v) expected error", cfg)
		}
	}
}
