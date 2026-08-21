package containerstream

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const (
	// ProcessFSOpenProtocol is the typed ServiceFS negotiation used to attach
	// one synthetic process directory over the existing session mux.
	ProcessFSOpenProtocol = "weaverssh.processfs-open.v1"
	maxProcessFSMetadata  = 12 << 10
)

// ProcessFSOpenMetadata carries a process target plus broker-authenticated
// route provenance. Source fields must be empty at the client boundary and are
// populated exactly once by the same-user session broker.
type ProcessFSOpenMetadata struct {
	Protocol      string `json:"protocol"`
	TargetNode    string `json:"target_node"`
	TargetURI     string `json:"target_uri"`
	SourceNode    string `json:"source_node,omitempty"`
	SourceBinding string `json:"source_binding,omitempty"`
	ChainSHA256   string `json:"chain_sha256,omitempty"`
}

// NewProcessFSOpenMetadata creates unbound metadata for an explicit
// vfs://container/.../.wv/processes target. It never accepts source identity
// from the caller.
func NewProcessFSOpenMetadata(targetNode, targetURI string) ([]byte, error) {
	metadata := ProcessFSOpenMetadata{
		Protocol:   ProcessFSOpenProtocol,
		TargetNode: strings.TrimSpace(targetNode),
		TargetURI:  strings.TrimSpace(targetURI),
	}
	return encodeProcessFSOpenMetadata(metadata)
}

// ParseProcessFSOpenMetadata strictly decodes typed ProcessFS negotiation.
func ParseProcessFSOpenMetadata(raw []byte) (ProcessFSOpenMetadata, error) {
	if len(raw) == 0 || len(raw) > maxProcessFSMetadata {
		return ProcessFSOpenMetadata{}, errors.New("containerstream: invalid ProcessFS open metadata size")
	}
	var metadata ProcessFSOpenMetadata
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return ProcessFSOpenMetadata{}, errors.New("containerstream: invalid ProcessFS open metadata")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ProcessFSOpenMetadata{}, errors.New("containerstream: trailing ProcessFS open metadata")
	}
	metadata.TargetNode = strings.TrimSpace(metadata.TargetNode)
	metadata.TargetURI = strings.TrimSpace(metadata.TargetURI)
	metadata.SourceNode = strings.TrimSpace(metadata.SourceNode)
	metadata.SourceBinding = strings.TrimSpace(metadata.SourceBinding)
	metadata.ChainSHA256 = strings.ToLower(strings.TrimSpace(metadata.ChainSHA256))
	if err := validateProcessFSOpenMetadata(metadata); err != nil {
		return ProcessFSOpenMetadata{}, err
	}
	return metadata, nil
}

func IsProcessFSOpenMetadata(raw []byte) bool {
	_, err := ParseProcessFSOpenMetadata(raw)
	return err == nil
}

// BindProcessFSSource installs provenance at the first broker and preserves it
// through forwarding. The requested container endpoint must equal the resolved
// route target, preventing a ServiceFS stream from crossing target boundaries.
func BindProcessFSSource(raw []byte, source, binding, chain, target string) ([]byte, error) {
	metadata, err := ParseProcessFSOpenMetadata(raw)
	if err != nil {
		return nil, err
	}
	source = strings.TrimSpace(source)
	binding = strings.TrimSpace(binding)
	chain = strings.ToLower(strings.TrimSpace(chain))
	target = strings.TrimSpace(target)
	request, err := ParseURI(metadata.TargetURI)
	if err != nil || request.FilePath != ProcessRoot || request.Endpoint != target {
		return nil, errors.New("containerstream: ProcessFS target does not match routed node")
	}
	if metadata.SourceNode == "" && metadata.SourceBinding == "" && metadata.ChainSHA256 == "" {
		metadata.SourceNode = source
		metadata.SourceBinding = binding
		metadata.ChainSHA256 = chain
	} else if metadata.ChainSHA256 != chain {
		return nil, errors.New("containerstream: forwarded ProcessFS provenance mismatch")
	}
	metadata.TargetNode = target
	return encodeProcessFSOpenMetadata(metadata)
}

func encodeProcessFSOpenMetadata(metadata ProcessFSOpenMetadata) ([]byte, error) {
	metadata.TargetNode = strings.TrimSpace(metadata.TargetNode)
	metadata.TargetURI = strings.TrimSpace(metadata.TargetURI)
	metadata.SourceNode = strings.TrimSpace(metadata.SourceNode)
	metadata.SourceBinding = strings.TrimSpace(metadata.SourceBinding)
	metadata.ChainSHA256 = strings.ToLower(strings.TrimSpace(metadata.ChainSHA256))
	if err := validateProcessFSOpenMetadata(metadata); err != nil {
		return nil, err
	}
	return json.Marshal(metadata)
}

func validateProcessFSOpenMetadata(metadata ProcessFSOpenMetadata) error {
	if metadata.Protocol != ProcessFSOpenProtocol || !targetPattern.MatchString(metadata.TargetNode) {
		return errors.New("containerstream: invalid ProcessFS open metadata")
	}
	request, err := ParseURI(metadata.TargetURI)
	if err != nil || request.Endpoint != metadata.TargetNode || request.FilePath != ProcessRoot {
		return errors.New("containerstream: invalid ProcessFS target URI")
	}
	provenanceEmpty := metadata.SourceNode == "" && metadata.SourceBinding == "" && metadata.ChainSHA256 == ""
	provenanceBound := targetPattern.MatchString(metadata.SourceNode) && metadata.SourceBinding != "" && len(metadata.SourceBinding) <= 512 && validProcessFSSHA256(metadata.ChainSHA256)
	if !provenanceEmpty && !provenanceBound {
		return errors.New("containerstream: incomplete ProcessFS broker provenance")
	}
	return nil
}

func validProcessFSSHA256(value string) bool {
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
