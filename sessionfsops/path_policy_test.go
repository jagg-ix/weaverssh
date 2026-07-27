package sessionfsops

import "testing"

func TestCleanRelativeRejectsTraversalBeforeNormalization(t *testing.T) {
	for _, invalid := range []string{
		"../escape",
		"dir/../escape",
		"a/b/../../escape",
		"/absolute/path",
		`dir\file`,
		"",
	} {
		if _, err := cleanRelative(invalid); err == nil {
			t.Fatalf("path %q unexpectedly accepted", invalid)
		}
	}
	for input, want := range map[string]string{
		"file0.txt": "file0.txt",
		"x/data.bin": "x/data.bin",
		"a//b": "a/b",
		"a/./b": "a/b",
	} {
		got, err := cleanRelative(input)
		if err != nil {
			t.Fatalf("path %q: %v", input, err)
		}
		if got != want {
			t.Fatalf("path %q normalized to %q want %q", input, got, want)
		}
	}
}
