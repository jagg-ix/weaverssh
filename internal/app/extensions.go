package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"weaverssh/authproof"
	"weaverssh/extension"
	"weaverssh/sessionmux"
)

// EnvExtensionsConfig selects a strict JSON command-hook configuration.
const EnvExtensionsConfig = "WEAVERSSH_EXTENSIONS_CONFIG"

func resolveExtensions(configured *extension.Registry) (*extension.Registry, error) {
	if configured != nil {
		return configured, nil
	}
	path := strings.TrimSpace(os.Getenv(EnvExtensionsConfig))
	if path == "" {
		return nil, nil
	}
	registry, err := extension.LoadFile(path, func(failure extension.Failure) {
		log.Printf("extension=%s hook=%s mode=%s error=%v", failure.Extension.Name, failure.Point, failure.Mode, failure.Err)
	})
	if err != nil {
		return nil, fmt.Errorf("load extensions %s: %w", path, err)
	}
	return registry, nil
}

func runExtensionHook(
	ctx context.Context,
	registry *extension.Registry,
	point extension.Point,
	binding, localNode, peerNode, targetNode string,
	service sessionmux.ServiceID,
	metadata []byte,
	attributes map[string]string,
) error {
	if registry == nil {
		return nil
	}
	event := extension.NewEvent(point)
	event.SessionBinding = strings.TrimSpace(binding)
	event.LocalNode = strings.TrimSpace(localNode)
	event.PeerNode = strings.TrimSpace(peerNode)
	event.TargetNode = strings.TrimSpace(targetNode)
	if service.Valid() {
		event.Service = service.String()
		event.ServiceID = uint16(service)
	}
	if len(metadata) > 0 {
		event.MetadataBytes = len(metadata)
		event.MetadataSHA256 = authproof.SHA256Hex(metadata)
	}
	event.Attributes = attributes
	return registry.Run(ctx, event)
}
