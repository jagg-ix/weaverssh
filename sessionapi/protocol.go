// Package sessionapi provides bounded request/response APIs over the existing
// authenticated sessionmux control service. It never listens or dials outside
// the caller-supplied SSH/X11-derived WebSocket session.
package sessionapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"weaverssh/sessionmux"
)

const (
	ProtocolVersion         = "weaverssh.session-api.v1"
	MaxMessageBytes         = 64 << 10
	MaxContractPayloadBytes = 40 << 10

	MethodCapabilities  = "api.capabilities"
	MethodContractsList = "api.contracts"
	MethodContractGet   = "api.contract.get"
	MethodDescribe      = "session.describe"
	MethodTopology      = "topology.list"
	MethodResolve       = "node.resolve"
	MethodRoutePrepare  = "route.prepare"
)

var (
	ErrWrongProtocol    = errors.New("sessionapi: wrong protocol")
	ErrInvalidRequest   = errors.New("sessionapi: invalid request")
	ErrUnknownMethod    = errors.New("sessionapi: unknown method")
	ErrNodeNotFound     = errors.New("sessionapi: node not found")
	ErrRouteUnavailable = errors.New("sessionapi: route unavailable")
	ErrContractNotFound = errors.New("sessionapi: API contract not found")
	ErrContractTooLarge = errors.New("sessionapi: API contract exceeds in-band response limit")
)

type Request struct {
	Protocol string          `json:"protocol"`
	ID       string          `json:"id"`
	Method   string          `json:"method"`
	Params   json.RawMessage `json:"params,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Response struct {
	Protocol string          `json:"protocol"`
	ID       string          `json:"id"`
	Result   json.RawMessage `json:"result,omitempty"`
	Error    *Error          `json:"error,omitempty"`
}

type Node struct {
	ID         string   `json:"id"`
	Index      int      `json:"index"`
	Registered bool     `json:"registered"`
	Services   []string `json:"services,omitempty"`
}

type Snapshot struct {
	Protocol       string   `json:"protocol"`
	Binding        string   `json:"binding"`
	CurrentNode    string   `json:"current_node"`
	CurrentIndex   int      `json:"current_index"`
	Topology       []string `json:"topology"`
	Nodes          []Node   `json:"nodes"`
	LocalServices  []string `json:"local_services,omitempty"`
	Features       []string `json:"features"`
	PreviousNode   string   `json:"previous_node,omitempty"`
	NextNode       string   `json:"next_node,omitempty"`
	HopDepth       int      `json:"hop_depth,omitempty"`
	HopChainSHA256 string   `json:"hop_chain_sha256,omitempty"`
}

type ResolveParams struct {
	Node string `json:"node"`
}

type ResolveResult struct {
	Node  string `json:"node"`
	Index int    `json:"index"`
}

type RoutePrepareParams struct {
	Node    string `json:"node"`
	Service string `json:"service,omitempty"`
}

type RoutePlan struct {
	TargetNode  string `json:"target_node"`
	TargetIndex int    `json:"target_index"`
	Direction   string `json:"direction"`
	NextHop     string `json:"next_hop,omitempty"`
	NextBinding string `json:"next_binding,omitempty"`
	Service     string `json:"service,omitempty"`
	Available   bool   `json:"available"`
	UsesCurrent bool   `json:"uses_current_session,omitempty"`
}

type ContractListParams struct {
	Offset int `json:"offset,omitempty"`
	Limit  int `json:"limit,omitempty"`
}

type ContractDescriptor struct {
	ID            string `json:"id"`
	Version       string `json:"contract_version"`
	Kind          string `json:"kind"`
	Stability     string `json:"stability"`
	Compatibility string `json:"compatibility"`
	SHA256        string `json:"sha256"`
}

type ContractListResult struct {
	Catalog   string               `json:"catalog"`
	Revision  string               `json:"revision"`
	Total     int                  `json:"total"`
	Offset    int                  `json:"offset"`
	Contracts []ContractDescriptor `json:"contracts"`
}

type ContractGetParams struct {
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
}

type ContractDocument struct {
	Contract ContractDescriptor `json:"contract"`
	Encoding string             `json:"encoding"`
	Data     string             `json:"data"`
}

type Capabilities struct {
	Protocol string   `json:"protocol"`
	Methods  []string `json:"methods"`
}

func validateRequest(request Request) error {
	request.Protocol = strings.TrimSpace(request.Protocol)
	request.ID = strings.TrimSpace(request.ID)
	request.Method = strings.TrimSpace(request.Method)
	if request.Protocol != ProtocolVersion {
		return ErrWrongProtocol
	}
	if request.ID == "" || len(request.ID) > 128 || request.Method == "" || len(request.Method) > 128 {
		return ErrInvalidRequest
	}
	return nil
}

func serviceNames(services []sessionmux.ServiceID) []string {
	out := make([]string, 0, len(services))
	for _, service := range services {
		if service.Valid() {
			out = append(out, service.String())
		}
	}
	return out
}

func apiError(err error) *Error {
	if err == nil {
		return nil
	}
	code := "internal"
	switch {
	case errors.Is(err, ErrWrongProtocol):
		code = "wrong_protocol"
	case errors.Is(err, ErrInvalidRequest):
		code = "invalid_request"
	case errors.Is(err, ErrUnknownMethod):
		code = "unknown_method"
	case errors.Is(err, ErrNodeNotFound):
		code = "node_not_found"
	case errors.Is(err, ErrRouteUnavailable):
		code = "route_unavailable"
	case errors.Is(err, ErrContractNotFound):
		code = "contract_not_found"
	case errors.Is(err, ErrContractTooLarge):
		code = "contract_too_large"
	}
	return &Error{Code: code, Message: err.Error()}
}

func decodeParams(raw json.RawMessage, target any) error {
	if len(raw) == 0 {
		return fmt.Errorf("%w: missing params", ErrInvalidRequest)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	return nil
}
