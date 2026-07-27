package vfs

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestProviderProfileExternalTCPPlan(t *testing.T) {
	profile := ProviderProfile{Name: "qemu-tcp", Kind: ProviderExternalTCP9P, Endpoint: "127.0.0.1:5640", Socks: "127.0.0.1:1080"}
	plan, err := profile.Plan()
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !plan.DirectlyDialable || plan.Endpoint != "127.0.0.1:5640" || plan.Socks != "127.0.0.1:1080" {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if len(plan.QEMUArgs) != 0 || len(plan.GuestMountCommand) != 0 {
		t.Fatalf("external tcp provider should not produce qemu commands: %+v", plan)
	}
}

func TestProviderProfileQEMUVirtFSPlan(t *testing.T) {
	profile := ProviderProfile{Name: "vm-share", Kind: ProviderQEMUVirtFS, SourcePath: "/srv/share", MountTag: "hostshare", MountPoint: "/mnt/hostshare", ReadOnly: true}
	plan, err := profile.Plan()
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.DirectlyDialable {
		t.Fatalf("qemu virtfs should not be directly dialable: %+v", plan)
	}
	wantArgs := []string{"-fsdev", "local,id=vm-share,path=/srv/share,security_model=mapped-xattr,readonly=on", "-device", "virtio-9p-pci,fsdev=vm-share,mount_tag=hostshare"}
	if !reflect.DeepEqual(plan.QEMUArgs, wantArgs) {
		t.Fatalf("QEMUArgs=%v want %v", plan.QEMUArgs, wantArgs)
	}
	wantMount := []string{"mount", "-t", "9p", "-o", "trans=virtio,version=9p2000.L,ro", "hostshare", "/mnt/hostshare"}
	if !reflect.DeepEqual(plan.GuestMountCommand, wantMount) {
		t.Fatalf("GuestMountCommand=%v want %v", plan.GuestMountCommand, wantMount)
	}
	if endpoint, _, ok := plan.Profile.EndpointPair(); ok || endpoint != "" {
		t.Fatalf("qemu virtfs should not resolve endpoint: endpoint=%q ok=%t", endpoint, ok)
	}
}

func TestProviderProfileValidation(t *testing.T) {
	if err := (ProviderProfile{Name: "bad/name", Kind: ProviderExternalTCP9P, Endpoint: "127.0.0.1:5640"}).Validate(); err == nil {
		t.Fatalf("unsafe provider name should fail validation")
	}
	if err := (ProviderProfile{Name: "missing", Kind: ProviderExternalTCP9P}).Validate(); err == nil || !strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("missing endpoint should fail, got %v", err)
	}
	if err := (ProviderProfile{Name: "qemu", Kind: ProviderQEMUVirtFS, SourcePath: "/tmp/x", MountTag: "bad tag"}).Validate(); err == nil {
		t.Fatalf("unsafe qemu mount tag should fail")
	}
}

func TestSaveLoadProviderAndEndpointResolution(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WEAVERSSH_VFS_CONFIG_DIR", filepath.Join(dir, "cfgdir"))
	t.Setenv("WEAVERSSH_VFS_CONFIG", filepath.Join(dir, "vfs.json"))
	t.Setenv(EnvEndpoint, "")
	t.Setenv(EnvEndpointShort, "")
	t.Setenv(EnvSocks, "")
	t.Setenv(EnvSocksShort, "")
	t.Setenv(EnvProviderConfig, "")
	t.Setenv(EnvProviderName, "")

	profile := ProviderProfile{Name: "qemu-tcp", Kind: ProviderExternalTCP9P, Endpoint: "127.0.0.1:15640", Socks: "127.0.0.1:11080"}
	path, err := SaveProviderProfile(profile)
	if err != nil {
		t.Fatalf("SaveProviderProfile: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("saved profile missing: %v", err)
	}
	cfg := Config{ProviderName: "qemu-tcp"}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	endpoint, socks := Endpoint()
	if endpoint != "127.0.0.1:15640" || socks != "127.0.0.1:11080" {
		t.Fatalf("Endpoint=%q,%q want provider endpoint", endpoint, socks)
	}
}

func TestEndpointCheckedRejectsInvalidProviderConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WEAVERSSH_VFS_CONFIG", filepath.Join(dir, "vfs.json"))
	t.Setenv(EnvEndpoint, "")
	t.Setenv(EnvEndpointShort, "")
	t.Setenv(EnvProviderConfig, "")
	t.Setenv(EnvProviderName, "")
	cfg := Config{Provider: &ProviderProfile{Name: "bad", Kind: ProviderExternalTCP9P}}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	if _, _, err := EndpointChecked(); err == nil {
		t.Fatalf("EndpointChecked should reject invalid provider config")
	}
	endpoint, socks := Endpoint()
	if endpoint != DefaultEndpoint || socks != "" {
		t.Fatalf("compat Endpoint fallback=%q,%q want default", endpoint, socks)
	}
}
