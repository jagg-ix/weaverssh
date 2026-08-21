package terminalsession

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

const (
	OpenProtocolVersion  = "weaverssh.terminal-open.v1"
	MaxOpenMetadataBytes = 4096
)

var nodeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// OpenMetadata contains route provenance only. Resume credentials and commands
// are intentionally carried later inside the accepted terminal stream.
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
		return OpenMetadata{}, errors.New("terminalsession: invalid open metadata size")
	}
	var metadata OpenMetadata
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return OpenMetadata{}, errors.New("terminalsession: invalid open metadata")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return OpenMetadata{}, errors.New("terminalsession: invalid trailing open metadata")
	}
	metadata.TargetNode = strings.TrimSpace(metadata.TargetNode)
	metadata.SourceNode = strings.TrimSpace(metadata.SourceNode)
	metadata.SourceBinding = strings.TrimSpace(metadata.SourceBinding)
	metadata.ChainSHA256 = strings.ToLower(strings.TrimSpace(metadata.ChainSHA256))
	if metadata.Protocol != OpenProtocolVersion || !nodeNamePattern.MatchString(metadata.TargetNode) {
		return OpenMetadata{}, errors.New("terminalsession: invalid open metadata")
	}
	return metadata, nil
}

func IsOpenMetadata(raw []byte) bool {
	_, err := ParseOpenMetadata(raw)
	return err == nil
}

// BindSource is called only by the same-user broker. Forwarders preserve the
// original binding and chain while rewriting the concrete target.
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
		return nil, errors.New("terminalsession: forwarded provenance mismatch")
	}
	metadata.TargetNode = target
	if !nodeNamePattern.MatchString(metadata.SourceNode) || !nodeNamePattern.MatchString(metadata.TargetNode) || metadata.SourceBinding == "" || len(metadata.SourceBinding) > 512 || len(metadata.ChainSHA256) != 64 {
		return nil, errors.New("terminalsession: invalid broker provenance")
	}
	return encodeOpenMetadata(metadata)
}

func encodeOpenMetadata(metadata OpenMetadata) ([]byte, error) {
	if metadata.Protocol != OpenProtocolVersion || !nodeNamePattern.MatchString(metadata.TargetNode) {
		return nil, errors.New("terminalsession: invalid open metadata")
	}
	return json.Marshal(metadata)
}
