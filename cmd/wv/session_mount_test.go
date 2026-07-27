package main

import "testing"

func TestRoutedMountSelection(t *testing.T) {
	routed, err := containsSessionPath([]string{"--cache-ttl", "2s", "node-a:/", "/mnt/work"})
	if err != nil {
		t.Fatal(err)
	}
	if !routed {
		t.Fatal("signed node mount was not selected")
	}
	routed, err = containsSessionPath([]string{"/mnt/local"})
	if err != nil {
		t.Fatal(err)
	}
	if routed {
		t.Fatal("legacy mountpoint was treated as a signed node path")
	}
}
