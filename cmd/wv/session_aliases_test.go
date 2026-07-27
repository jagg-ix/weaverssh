package main

import (
	"os"
	"testing"

	"weaverssh/internal/app"
)

func TestNormalizeSessionAliasOperand(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "node:workstation-42:/mypath/", want: "workstation-42:/mypath/"},
		{input: "node:compute-node:/srv/file", want: "compute-node:/srv/file"},
		{input: "NODE:WORKSTATION-42:/mixed/case", want: "WORKSTATION-42:/mixed/case"},
		{input: "node:self:/tmp/file", want: "self:/tmp/file"},
		{input: "@origin:/mypath/", want: "@origin:/mypath/"},
		{input: "user@endpoint:/srv/file", want: "user@endpoint:/srv/file"},
		{input: "myuserRemote@somenode.com:~/subfieldAthome/myfile.txt", want: "myuserRemote@somenode.com:~/subfieldAthome/myfile.txt"},
		{input: "./local:file", want: "./local:file"},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			if got := normalizeSessionAliasOperand(test.input); got != test.want {
				t.Fatalf("normalizeSessionAliasOperand(%q)=%q want %q", test.input, got, test.want)
			}
		})
	}
}

func TestWVOriginExpandsToConcreteSessionPath(t *testing.T) {
	t.Setenv(app.EnvWVOrigin, "workstation-42")
	destination := os.Getenv(app.EnvWVOrigin) + ":/mypath/"
	args := normalizeSessionAliasArgs([]string{"someOnNodeFS/path/file.txt", destination})
	if len(args) != 2 || args[1] != "workstation-42:/mypath/" {
		t.Fatalf("normalized args=%q", args)
	}
	ref, matched, err := parseSessionPath(args[1])
	if err != nil {
		t.Fatal(err)
	}
	if !matched || ref.Node != "workstation-42" || ref.Path != "mypath" || !ref.TrailingSlash {
		t.Fatalf("parsed ref=%+v matched=%t", ref, matched)
	}
}

func TestNamespacedWVOriginExpandsToConcreteSessionPath(t *testing.T) {
	t.Setenv(app.EnvWVOrigin, "workstation-42")
	destination := "node:" + os.Getenv(app.EnvWVOrigin) + ":/mypath/"
	args := normalizeSessionAliasArgs([]string{"someOnNodeFS/path/file.txt", destination})
	if len(args) != 2 || args[1] != "workstation-42:/mypath/" {
		t.Fatalf("normalized args=%q", args)
	}
}

func TestSCPStyleUserHostIsNeverRewritten(t *testing.T) {
	for _, input := range []string{
		"user@endpoint:/file",
		"myuserRemote@somenode.com:~/subfieldAthome/myfile.txt",
	} {
		raw := normalizeSessionAliasOperand(input)
		if raw != input {
			t.Fatalf("unexpected rewrite: %q -> %q", input, raw)
		}
	}
}

func TestRemovedOriginKeywordIsOnlyAConcreteNodeToken(t *testing.T) {
	// The CLI parser may parse "origin" as an ordinary node ID, but no alias
	// expansion occurs here or in sessioncontrol.
	raw := normalizeSessionAliasOperand("origin:/file")
	if raw != "origin:/file" {
		t.Fatalf("unexpected rewrite: %q", raw)
	}
}
