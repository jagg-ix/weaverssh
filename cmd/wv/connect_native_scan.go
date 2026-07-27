package main

// Native connection scan: wv discovers SSH connection profiles directly from
// ~/.ssh/config, PuTTY saved sessions, and known_hosts via the connectionscan
// package, so `wv connections scan` works with no external binary. Set
// WEAVERSSH_CONNECTION_SCAN_BIN / WEAVERSSH_SERVICE_DOCK_BIN to use the full
// service-dock wizard instead (see externalScanner).

import (
	"fmt"
	"path/filepath"
	"sort"

	"weaverssh/connectionscan"
)

// nativeScan runs the built-in discoverer and shapes it into a Scan. spec is a
// connectionscan config-source (empty = default ~/.ssh discovery).
func nativeScan(spec string) (*Scan, error) {
	res, err := connectionscan.DiscoverFrom(spec)
	if err != nil {
		return nil, err
	}

	scan := &Scan{OK: true, Source: "native"}
	for _, s := range res.SSHConfigSources {
		scan.SSHConfigSources = append(scan.SSHConfigSources, SSHConfigSource{
			Index:  s.Index,
			Path:   s.Path,
			Scope:  s.Scope,
			Reason: s.Reason,
			Exists: s.Exists,
		})
	}
	for _, p := range res.Profiles {
		scan.DiscoveredProfiles = append(scan.DiscoveredProfiles, discoveredToConnProfile(p))
	}
	if len(scan.DiscoveredProfiles) > 0 {
		scan.Profile = scan.DiscoveredProfiles[0]
		scan.SelectedProfile = scan.DiscoveredProfiles[0]
	}

	scan.StorePath = connectionsStorePath()
	scan.ProfilesDir = filepath.Dir(scan.StorePath)
	scan.ConfigDir = scan.ProfilesDir

	counts := map[string]int{}
	for _, p := range res.Profiles {
		counts[p.Source]++
	}
	scan.Assessment = Assessment{
		OK:      len(scan.DiscoveredProfiles) > 0,
		State:   scanState(len(scan.DiscoveredProfiles)),
		Summary: scanSummary(len(scan.DiscoveredProfiles), counts),
	}
	if len(scan.DiscoveredProfiles) == 0 {
		scan.Assessment.NextAction = "add hosts to ~/.ssh/config (or a PuTTY session), then re-run wv connections scan"
	} else {
		scan.Assessment.NextAction = "wv connections scan --import   (add discovered profiles to the store)"
	}
	return scan, nil
}

func discoveredToConnProfile(p connectionscan.DiscoveredProfile) ConnProfile {
	labels := map[string]string{"source": p.Source}
	if p.Scope != "" {
		labels["scope"] = p.Scope
	}
	return ConnProfile{
		Name:         p.Name,
		Version:      connLatestVersion,
		Description:  p.Description,
		SSHHost:      p.Host,
		SSHUser:      p.User,
		SSHPort:      p.Port,
		IdentityFile: p.IdentityFile,
		Tags:         p.Tags,
		Labels:       labels,
	}
}

func scanState(n int) string {
	if n == 0 {
		return "empty"
	}
	return "ready"
}

func scanSummary(total int, counts map[string]int) string {
	if total == 0 {
		return "no connections discovered from ssh_config, PuTTY, or known_hosts"
	}
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%s: %d", k, counts[k]))
	}
	return fmt.Sprintf("%d connections discovered (%s)", total, joinComma(parts))
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
