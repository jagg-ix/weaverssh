package apicontract

import (
	"errors"
	"fmt"
	"sort"
)

type ChangeType string

const (
	ChangeAdded     ChangeType = "added"
	ChangeRemoved   ChangeType = "removed"
	ChangeUnchanged ChangeType = "unchanged"
	ChangeModified  ChangeType = "modified"
)

type CompatibilityReport struct {
	Compatible bool             `json:"compatible"`
	Changes    []ContractChange `json:"changes"`
}

type ContractChange struct {
	ID              string        `json:"id"`
	PreviousVersion string        `json:"previous_version,omitempty"`
	CurrentVersion  string        `json:"current_version,omitempty"`
	Type            ChangeType    `json:"type"`
	Policy          Compatibility `json:"policy"`
	RemovedSymbols  []string      `json:"removed_symbols,omitempty"`
	AddedSymbols    []string      `json:"added_symbols,omitempty"`
	Compatible      bool          `json:"compatible"`
	Reason          string        `json:"reason,omitempty"`
}

func CompareLocks(previous, current Lock) (CompatibilityReport, error) {
	if err := previous.Validate(); err != nil {
		return CompatibilityReport{}, fmt.Errorf("apicontract: previous lock: %w", err)
	}
	if err := current.Validate(); err != nil {
		return CompatibilityReport{}, fmt.Errorf("apicontract: current lock: %w", err)
	}
	if previous.CatalogName != current.CatalogName {
		return CompatibilityReport{}, errors.New("apicontract: catalogs have different names")
	}
	previousByID := latestEntries(previous.Contracts)
	currentByID := latestEntries(current.Contracts)
	ids := map[string]struct{}{}
	for id := range previousByID {
		ids[id] = struct{}{}
	}
	for id := range currentByID {
		ids[id] = struct{}{}
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	report := CompatibilityReport{Compatible: true}
	for _, id := range ordered {
		before, hadBefore := previousByID[id]
		after, hasAfter := currentByID[id]
		change := ContractChange{ID: id, Compatible: true}
		switch {
		case !hadBefore && hasAfter:
			change.Type = ChangeAdded
			change.CurrentVersion = after.Version
			change.Policy = after.Compatibility
			change.AddedSymbols = append([]string(nil), after.Symbols...)
		case hadBefore && !hasAfter:
			change.Type = ChangeRemoved
			change.PreviousVersion = before.Version
			change.Policy = before.Compatibility
			change.RemovedSymbols = append([]string(nil), before.Symbols...)
			change.Compatible = before.Compatibility == CompatibilityNone
			if !change.Compatible {
				change.Reason = "contract removed"
			}
		default:
			change.PreviousVersion = before.Version
			change.CurrentVersion = after.Version
			change.Policy = after.Compatibility
			change.RemovedSymbols, change.AddedSymbols = symbolDelta(before.Symbols, after.Symbols)
			if before.SHA256 == after.SHA256 && before.Version == after.Version {
				change.Type = ChangeUnchanged
			} else {
				change.Type = ChangeModified
			}
			change.Compatible, change.Reason = evaluateCompatibility(after.Compatibility, change.RemovedSymbols, change.AddedSymbols)
		}
		if !change.Compatible {
			report.Compatible = false
		}
		report.Changes = append(report.Changes, change)
	}
	return report, nil
}

func latestEntries(entries []LockedEntry) map[string]LockedEntry {
	out := map[string]LockedEntry{}
	for _, entry := range entries {
		current, exists := out[entry.ID]
		if !exists || compareVersion(entry.Version, current.Version) > 0 {
			out[entry.ID] = entry
		}
	}
	return out
}

func symbolDelta(previous, current []string) (removed, added []string) {
	previousSet := map[string]struct{}{}
	currentSet := map[string]struct{}{}
	for _, symbol := range previous {
		previousSet[symbol] = struct{}{}
	}
	for _, symbol := range current {
		currentSet[symbol] = struct{}{}
	}
	for symbol := range previousSet {
		if _, exists := currentSet[symbol]; !exists {
			removed = append(removed, symbol)
		}
	}
	for symbol := range currentSet {
		if _, exists := previousSet[symbol]; !exists {
			added = append(added, symbol)
		}
	}
	sort.Strings(removed)
	sort.Strings(added)
	return removed, added
}

func evaluateCompatibility(policy Compatibility, removed, added []string) (bool, string) {
	switch policy {
	case CompatibilityNone:
		return true, ""
	case CompatibilityBackward:
		if len(removed) > 0 {
			return false, "backward compatibility forbids removing public symbols"
		}
	case CompatibilityForward:
		if len(added) > 0 {
			return false, "forward compatibility forbids adding public symbols"
		}
	case CompatibilityFull:
		if len(removed) > 0 || len(added) > 0 {
			return false, "full compatibility requires an unchanged public symbol set"
		}
	default:
		return false, "unknown compatibility policy"
	}
	return true, ""
}
