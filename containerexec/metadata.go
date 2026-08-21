package containerexec

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

const (
	OpenProtocolVersion  = "weaverssh.container-exec-open.v1"
	MaxOpenMetadataBytes = 4096
)

var nodeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// OpenMetadata contains route provenance only. Container target and action are
// carried later inside the accepted stream so the broker can bind identity
// before the final-node service sees an execution request.
type OpenMetadata struct {
	Protocol      string `json:"protocol"`
	TargetNode    string `json:"target_node"`
	SourceNode    string `json:"source_node,omitempty"`
	SourceBinding string `json:"source_binding,omitempty"`
	ChainSHA256   string `json:"chain_sha256,omitempty"`
}

func NewOpenMetadata(target string) ([]byte, error) {
	return encodeOpenMetadata(OpenMetadata{Protocol: OpenProtocolVersion, TargetNode: strings.TrimSpace(target)})
}

func ParseOpenMetadata(raw []byte) (OpenMetadata, error) {
	if len(raw) == 0 || len(raw) > MaxOpenMetadataBytes {
		return OpenMetadata{}, errors.New("containerexec: invalid open metadata size")
	}
	var metadata OpenMetadata
	if err := decodeStrict(raw, &metadata); err != nil {
		return OpenMetadata{}, errors.New("containerexec: invalid open metadata")
	}
	metadata.TargetNode = strings.TrimSpace(metadata.TargetNode)
	metadata.SourceNode = strings.TrimSpace(metadata.SourceNode)
	metadata.SourceBinding = strings.TrimSpace(metadata.SourceBinding)
	metadata.ChainSHA256 = strings.ToLower(strings.TrimSpace(metadata.ChainSHA256))
	if metadata.Protocol != OpenProtocolVersion || !nodeNamePattern.MatchString(metadata.TargetNode) ||
		(metadata.ChainSHA256 != "" && !validLowerSHA256(metadata.ChainSHA256)) {
		return OpenMetadata{}, errors.New("containerexec: invalid open metadata")
	}
	return metadata, nil
}

func IsOpenMetadata(raw []byte) bool {
	_, err := ParseOpenMetadata(raw)
	return err == nil
}

// BindSource is called only by the same-user broker. Forwarders preserve the
// first broker's source binding and chain while rewriting the concrete target.
func BindSource(raw []byte, source, binding, chain, target string) ([]byte, error) {
	metadata, err := ParseOpenMetadata(raw)
	if err != nil {
		return nil, err
	}
	source = strings.TrimSpace(source)
	binding = strings.TrimSpace(binding)
	chain = strings.ToLower(strings.TrimSpace(chain))
	target = strings.TrimSpace(target)
	if metadata.SourceNode == "" && metadata.SourceBinding == "" && metadata.ChainSHA256 == "" {
		metadata.SourceNode, metadata.SourceBinding, metadata.ChainSHA256 = source, binding, chain
	} else if metadata.ChainSHA256 != chain {
		return nil, errors.New("containerexec: forwarded provenance mismatch")
	}
	metadata.TargetNode = target
	if !nodeNamePattern.MatchString(metadata.SourceNode) || !nodeNamePattern.MatchString(metadata.TargetNode) || metadata.SourceBinding == "" || len(metadata.SourceBinding) > 512 || !validLowerSHA256(metadata.ChainSHA256) {
		return nil, errors.New("containerexec: invalid broker provenance")
	}
	return encodeOpenMetadata(metadata)
}

func encodeOpenMetadata(metadata OpenMetadata) ([]byte, error) {
	if metadata.Protocol != OpenProtocolVersion || !nodeNamePattern.MatchString(metadata.TargetNode) ||
		(metadata.ChainSHA256 != "" && !validLowerSHA256(metadata.ChainSHA256)) {
		return nil, errors.New("containerexec: invalid open metadata")
	}
	return json.Marshal(metadata)
}

func validLowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func decodeStrict(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("containerexec: trailing JSON")
	}
	return nil
}
