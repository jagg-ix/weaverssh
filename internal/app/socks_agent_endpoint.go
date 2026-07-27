package app

import (
	"fmt"
	"strings"

	"weaverssh/display"
)

func parseSocksAgentEndpoint(endpoint string) (network, address string, err error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", "", fmt.Errorf("agent endpoint is empty")
	}
	if strings.HasPrefix(endpoint, "tcp://") {
		endpoint = strings.TrimPrefix(endpoint, "tcp://")
	}
	return display.ParseDialTarget(endpoint)
}
