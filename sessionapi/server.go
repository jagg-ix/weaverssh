package sessionapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"weaverssh/apicontract"
	"weaverssh/sessionmux"
)

type SnapshotFunc func(context.Context) (Snapshot, error)
type RoutePrepareFunc func(context.Context, RoutePrepareParams) (RoutePlan, error)

type Server struct {
	Snapshot     SnapshotFunc
	PrepareRoute RoutePrepareFunc
	Contracts    apicontract.Provider
}

func (s *Server) ServeStream(ctx context.Context, stream *sessionmux.Stream) error {
	if s == nil || s.Snapshot == nil || stream == nil {
		return errors.New("sessionapi: incomplete server")
	}
	if stream.Service() != sessionmux.ServiceControl || string(stream.Metadata()) != ProtocolVersion {
		_ = stream.Reset()
		return ErrWrongProtocol
	}
	defer stream.Close()
	request, err := readRequest(ctx, stream)
	if err != nil {
		if writeErr := writeResponse(stream, Response{Protocol: ProtocolVersion, Error: apiError(err)}); writeErr != nil {
			_ = stream.Reset()
			return writeErr
		}
		return nil
	}
	response := Response{Protocol: ProtocolVersion, ID: request.ID}
	result, handleErr := s.handle(ctx, request)
	if handleErr != nil {
		response.Error = apiError(handleErr)
	} else {
		encoded, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			response.Error = apiError(marshalErr)
		} else {
			response.Result = encoded
		}
	}
	if err := writeResponse(stream, response); err != nil {
		_ = stream.Reset()
		return err
	}
	return nil
}

func (s *Server) handle(ctx context.Context, request Request) (any, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	if request.Method == MethodCapabilities {
		methods := []string{MethodCapabilities, MethodDescribe, MethodTopology, MethodResolve, MethodRoutePrepare}
		if s.Contracts != nil {
			methods = append(methods, MethodContractsList, MethodContractGet)
		}
		sort.Strings(methods)
		return Capabilities{Protocol: ProtocolVersion, Methods: methods}, nil
	}
	if request.Method == MethodContractsList || request.Method == MethodContractGet {
		return s.handleContracts(ctx, request)
	}
	snapshot, err := s.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	snapshot = normalizeSnapshot(snapshot)
	switch request.Method {
	case MethodDescribe:
		return snapshot, nil
	case MethodTopology:
		return struct {
			Topology []string `json:"topology"`
			Nodes    []Node   `json:"nodes"`
		}{Topology: snapshot.Topology, Nodes: snapshot.Nodes}, nil
	case MethodResolve:
		var params ResolveParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		node, index, err := resolveNode(snapshot, params.Node)
		if err != nil {
			return nil, err
		}
		return ResolveResult{Node: node, Index: index}, nil
	case MethodRoutePrepare:
		var params RoutePrepareParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		if s.PrepareRoute != nil {
			plan, err := s.PrepareRoute(ctx, params)
			if err != nil {
				return nil, err
			}
			plan.Service = strings.TrimSpace(params.Service)
			return plan, nil
		}
		node, index, err := resolveNode(snapshot, params.Node)
		if err != nil {
			return nil, err
		}
		plan := RoutePlan{TargetNode: node, TargetIndex: index, Service: strings.TrimSpace(params.Service)}
		switch {
		case index == snapshot.CurrentIndex:
			plan.Direction = "local"
			plan.NextHop = snapshot.CurrentNode
			plan.Available = true
		case index < snapshot.CurrentIndex:
			plan.Direction = "previous"
			if snapshot.CurrentIndex > 0 {
				plan.NextHop = snapshot.Topology[snapshot.CurrentIndex-1]
			}
		case index > snapshot.CurrentIndex:
			plan.Direction = "next"
			if snapshot.CurrentIndex+1 < len(snapshot.Topology) {
				plan.NextHop = snapshot.Topology[snapshot.CurrentIndex+1]
			}
		}
		return plan, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownMethod, request.Method)
	}
}

func (s *Server) handleContracts(ctx context.Context, request Request) (any, error) {
	if s.Contracts == nil {
		return nil, fmt.Errorf("%w: contract provider unavailable", ErrUnknownMethod)
	}
	switch request.Method {
	case MethodContractsList:
		params := ContractListParams{Limit: 64}
		if len(request.Params) > 0 {
			if err := json.Unmarshal(request.Params, &params); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
			}
		}
		if params.Offset < 0 || params.Limit < 0 || params.Limit > 128 {
			return nil, ErrInvalidRequest
		}
		if params.Limit == 0 {
			params.Limit = 64
		}
		catalog, err := s.Contracts.Catalog(ctx)
		if err != nil {
			return nil, err
		}
		entries, err := s.Contracts.List(ctx)
		if err != nil {
			return nil, err
		}
		if params.Offset > len(entries) {
			params.Offset = len(entries)
		}
		end := params.Offset + params.Limit
		if end > len(entries) {
			end = len(entries)
		}
		descriptors := make([]ContractDescriptor, 0, end-params.Offset)
		for _, entry := range entries[params.Offset:end] {
			descriptors = append(descriptors, contractDescriptor(entry))
		}
		return ContractListResult{Catalog: catalog.Name, Revision: catalog.Revision, Total: len(entries), Offset: params.Offset, Contracts: descriptors}, nil
	case MethodContractGet:
		var params ContractGetParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		payload, entry, err := s.Contracts.Read(ctx, params.ID, params.Version)
		if err != nil {
			if errors.Is(err, apicontract.ErrContractNotFound) {
				return nil, fmt.Errorf("%w: %v", ErrContractNotFound, err)
			}
			return nil, err
		}
		if len(payload) > MaxContractPayloadBytes {
			return nil, ErrContractTooLarge
		}
		encoding, data := "utf-8", string(payload)
		if !utf8.Valid(payload) {
			encoding, data = "base64", base64.StdEncoding.EncodeToString(payload)
		}
		return ContractDocument{Contract: contractDescriptor(entry), Encoding: encoding, Data: data}, nil
	default:
		return nil, ErrUnknownMethod
	}
}

func contractDescriptor(entry apicontract.LockedEntry) ContractDescriptor {
	return ContractDescriptor{ID: entry.ID, Version: entry.Version, Kind: string(entry.Kind), Stability: string(entry.Stability), Compatibility: string(entry.Compatibility), SHA256: entry.SHA256}
}

func normalizeSnapshot(snapshot Snapshot) Snapshot {
	snapshot.Protocol = ProtocolVersion
	snapshot.Binding = strings.TrimSpace(snapshot.Binding)
	snapshot.CurrentNode = strings.TrimSpace(snapshot.CurrentNode)
	snapshot.Topology = append([]string(nil), snapshot.Topology...)
	for index := range snapshot.Topology {
		snapshot.Topology[index] = strings.TrimSpace(snapshot.Topology[index])
	}
	if snapshot.CurrentIndex < 0 || snapshot.CurrentIndex >= len(snapshot.Topology) || snapshot.Topology[snapshot.CurrentIndex] != snapshot.CurrentNode {
		snapshot.CurrentIndex = indexOf(snapshot.Topology, snapshot.CurrentNode)
	}
	if snapshot.CurrentIndex > 0 && snapshot.PreviousNode == "" {
		snapshot.PreviousNode = snapshot.Topology[snapshot.CurrentIndex-1]
	}
	if snapshot.CurrentIndex >= 0 && snapshot.CurrentIndex+1 < len(snapshot.Topology) && snapshot.NextNode == "" {
		snapshot.NextNode = snapshot.Topology[snapshot.CurrentIndex+1]
	}
	snapshot.Features = uniqueSorted(snapshot.Features)
	snapshot.LocalServices = uniqueSorted(snapshot.LocalServices)
	snapshot.Nodes = append([]Node(nil), snapshot.Nodes...)
	sort.Slice(snapshot.Nodes, func(i, j int) bool { return snapshot.Nodes[i].Index < snapshot.Nodes[j].Index })
	return snapshot
}

func resolveNode(snapshot Snapshot, raw string) (string, int, error) {
	name := strings.TrimSpace(raw)
	switch strings.ToLower(name) {
	case "self", "local", "here", "this", "current", ".":
		name = snapshot.CurrentNode
	case "previous", "prev":
		if snapshot.CurrentIndex <= 0 {
			return "", -1, fmt.Errorf("%w: no previous node", ErrNodeNotFound)
		}
		name = snapshot.Topology[snapshot.CurrentIndex-1]
	case "next":
		if snapshot.CurrentIndex < 0 || snapshot.CurrentIndex+1 >= len(snapshot.Topology) {
			return "", -1, fmt.Errorf("%w: no next node", ErrNodeNotFound)
		}
		name = snapshot.Topology[snapshot.CurrentIndex+1]
	case "endpoint", "last":
		if len(snapshot.Topology) == 0 {
			return "", -1, ErrNodeNotFound
		}
		name = snapshot.Topology[len(snapshot.Topology)-1]
	}
	index := indexOf(snapshot.Topology, name)
	if index < 0 {
		return "", -1, fmt.Errorf("%w: %s", ErrNodeNotFound, name)
	}
	return name, index, nil
}

func readRequest(ctx context.Context, reader io.Reader) (Request, error) {
	type result struct {
		request Request
		err     error
	}
	resultCh := make(chan result, 1)
	go func() {
		payload, err := readMessage(reader)
		if err != nil {
			resultCh <- result{err: err}
			return
		}
		var request Request
		err = json.Unmarshal(payload, &request)
		resultCh <- result{request: request, err: err}
	}()
	select {
	case decoded := <-resultCh:
		if decoded.err != nil {
			return Request{}, fmt.Errorf("%w: %v", ErrInvalidRequest, decoded.err)
		}
		if err := validateRequest(decoded.request); err != nil {
			return Request{}, err
		}
		return decoded.request, nil
	case <-ctx.Done():
		return Request{}, ctx.Err()
	}
}

func writeResponse(writer io.Writer, response Response) error {
	response.Protocol = ProtocolVersion
	payload, err := json.Marshal(response)
	if err != nil {
		return err
	}
	return writeMessage(writer, payload)
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func indexOf(values []string, want string) int {
	for index, value := range values {
		if value == want {
			return index
		}
	}
	return -1
}

func HopChainDigest(encoded string) string {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(digest[:])
}
