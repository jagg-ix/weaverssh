package mapreduce

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type Topology struct {
	ChainSHA256 string
	Nodes       []string
	CurrentNode string
}

func (t Topology) normalized() (Topology, error) {
	out := t
	out.ChainSHA256 = strings.ToLower(strings.TrimSpace(out.ChainSHA256))
	out.CurrentNode = strings.TrimSpace(out.CurrentNode)
	seen := map[string]bool{}
	nodes := make([]string, 0, len(out.Nodes))
	for _, node := range out.Nodes {
		node = strings.TrimSpace(node)
		if node == "" || seen[node] || !validNodeName(node) {
			return Topology{}, errors.New("mapreduce: invalid topology")
		}
		seen[node] = true
		nodes = append(nodes, node)
	}
	out.Nodes = nodes
	if len(out.ChainSHA256) != 64 || len(out.Nodes) == 0 || !seen[out.CurrentNode] {
		return Topology{}, errors.New("mapreduce: invalid topology")
	}
	return out, nil
}

func (t Topology) Role(node string) string {
	node = strings.TrimSpace(node)
	if len(t.Nodes) == 1 && t.Nodes[0] == node {
		return "single"
	}
	for i, value := range t.Nodes {
		if value != node {
			continue
		}
		if i == 0 {
			return "origin"
		}
		if i == len(t.Nodes)-1 {
			return "endpoint"
		}
		return "intermediate"
	}
	return ""
}

func (t Topology) Contains(node string) bool {
	for _, value := range t.Nodes {
		if value == strings.TrimSpace(node) {
			return true
		}
	}
	return false
}

type EngineConfig struct {
	Topology Topology
	Registry *Registry
	Policy   *Policy
	Reporter func(error)
}

type Engine struct {
	topology Topology
	registry *Registry
	policy   *Policy
	reporter func(error)
}

func NewEngine(config EngineConfig) (*Engine, error) {
	topology, err := config.Topology.normalized()
	if err != nil {
		return nil, err
	}
	if config.Registry == nil || config.Registry.Empty() {
		return nil, errors.New("mapreduce: plugin registry is required")
	}
	if config.Policy == nil {
		return nil, errors.New("mapreduce: policy is required")
	}
	return &Engine{topology: topology, registry: config.Registry, policy: config.Policy, reporter: config.Reporter}, nil
}

func (e *Engine) Description() Description {
	if e == nil {
		return Description{}
	}
	return Description{
		Protocol:     ProtocolVersion,
		CurrentNode:  e.topology.CurrentNode,
		PolicySHA256: e.policy.SHA256(),
		Plugins:      e.registry.Descriptions(),
		Limits:       HardLimits(),
	}
}

func (e *Engine) Execute(ctx context.Context, metadata OpenMetadata, raw Request) (Response, error) {
	if e == nil {
		return Response{}, errors.New("mapreduce: nil engine")
	}
	metadata, err := e.validateMetadata(metadata)
	if err != nil {
		return Response{}, err
	}
	request, err := NormalizeRequest(raw)
	if err != nil {
		return Response{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	items, inputBytes := InputMetrics(request)
	plugin := request.Plugin
	if request.Operation == OperationDescribe {
		plugin = "system.describe"
	}
	invocation := Invocation{
		SourceNode:             metadata.SourceNode,
		TargetNode:             metadata.TargetNode,
		SourceRole:             e.topology.Role(metadata.SourceNode),
		Operation:              request.Operation,
		Plugin:                 plugin,
		Labels:                 request.Labels,
		Items:                  items,
		InputBytes:             inputBytes,
		RequestedParallel:      request.RequestedParallel,
		RequestedTimeoutMillis: request.RequestedTimeoutMillis,
		Fanout:                 request.Fanout,
	}
	decision, err := e.policy.Evaluate(invocation)
	if err != nil {
		return Response{Protocol: ProtocolVersion, ID: request.ID, Decision: decision}, err
	}
	timeoutMillis := request.RequestedTimeoutMillis
	if timeoutMillis <= 0 || timeoutMillis > decision.Limits.MaxDurationMillis {
		timeoutMillis = decision.Limits.MaxDurationMillis
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMillis)*time.Millisecond)
	defer cancel()

	response := Response{Protocol: ProtocolVersion, ID: request.ID, Decision: decision}
	switch request.Operation {
	case OperationDescribe:
		response.Description = e.Description()
	case OperationMap:
		response.Records, err = e.executeMap(callCtx, metadata, request, decision.Limits)
	case OperationReduce:
		response.Records, err = e.executeReduce(callCtx, metadata, request, decision.Limits)
	case OperationRun:
		var mapped []Record
		mapped, err = e.executeMap(callCtx, metadata, request, decision.Limits)
		if err == nil {
			var groups []Group
			groups, err = GroupRecords(mapped, decision.Limits.MaxValuesPerKey)
			if err == nil {
				reduceRequest := request
				reduceRequest.Operation = OperationReduce
				reduceRequest.Records = nil
				reduceRequest.Groups = groups
				response.Records, err = e.executeReduce(callCtx, metadata, reduceRequest, decision.Limits)
			}
		}
	default:
		err = ErrInvalidRequest
	}
	if err != nil {
		e.report(err)
		return response, err
	}
	if err := validateOutput(response.Records, decision.Limits); err != nil {
		e.report(err)
		return response, err
	}
	return response, nil
}

func (e *Engine) validateMetadata(raw OpenMetadata) (OpenMetadata, error) {
	metadata := raw
	if metadata.Protocol == "" {
		metadata.Protocol = OpenProtocolVersion
	}
	metadata.SourceNode = strings.TrimSpace(metadata.SourceNode)
	metadata.SourceBinding = strings.TrimSpace(metadata.SourceBinding)
	metadata.ChainSHA256 = strings.ToLower(strings.TrimSpace(metadata.ChainSHA256))
	metadata.TargetNode = strings.TrimSpace(metadata.TargetNode)
	if metadata.Protocol != OpenProtocolVersion || metadata.SourceNode == "" || metadata.TargetNode == "" || metadata.SourceBinding == "" || len(metadata.SourceBinding) > 512 || metadata.ChainSHA256 != e.topology.ChainSHA256 {
		return OpenMetadata{}, errors.New("mapreduce: invalid open metadata")
	}
	if !e.topology.Contains(metadata.SourceNode) || !e.topology.Contains(metadata.TargetNode) || metadata.TargetNode != e.topology.CurrentNode {
		return OpenMetadata{}, errors.New("mapreduce: metadata is not bound to local topology")
	}
	return metadata, nil
}

func (e *Engine) executeMap(ctx context.Context, metadata OpenMetadata, request Request, limits Limits) ([]Record, error) {
	parallel := request.RequestedParallel
	if parallel <= 0 {
		parallel = 1
	}
	if parallel > limits.MaxParallel {
		parallel = limits.MaxParallel
	}
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()
	results := make([][]Record, len(request.Records))
	jobs := make(chan int)
	var errMu sync.Mutex
	var firstErr error
	setErr := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
			cancelWorkers()
		}
		errMu.Unlock()
	}
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for index := range jobs {
			if workerCtx.Err() != nil {
				return
			}
			input := MapInput{JobID: request.ID, SourceNode: metadata.SourceNode, TargetNode: metadata.TargetNode, Labels: cloneLabels(request.Labels), Record: request.Records[index]}
			output, err := e.registry.Map(workerCtx, request.Plugin, input)
			if err == nil {
				for _, record := range output {
					if validateErr := validateRecord(record); validateErr != nil {
						err = validateErr
						break
					}
				}
			}
			if err != nil {
				setErr(err)
				return
			}
			copied := make([]Record, len(output))
			for i, record := range output {
				copied[i] = Record{Key: record.Key, Value: append([]byte(nil), record.Value...)}
			}
			results[index] = copied
		}
	}
	wg.Add(parallel)
	for i := 0; i < parallel; i++ {
		go worker()
	}

sendLoop:
	for index := range request.Records {
		select {
		case jobs <- index:
		case <-workerCtx.Done():
			break sendLoop
		}
	}
	close(jobs)
	wg.Wait()
	errMu.Lock()
	err := firstErr
	errMu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []Record
	for _, records := range results {
		out = append(out, records...)
		if err := validateOutput(out, limits); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (e *Engine) executeReduce(ctx context.Context, metadata OpenMetadata, request Request, limits Limits) ([]Record, error) {
	groups := append([]Group(nil), request.Groups...)
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].Key < groups[j].Key })
	parallel := request.RequestedParallel
	if parallel <= 0 {
		parallel = 1
	}
	if parallel > limits.MaxParallel {
		parallel = limits.MaxParallel
	}
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()
	results := make([]Record, len(groups))
	jobs := make(chan int)
	var errMu sync.Mutex
	var firstErr error
	setErr := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
			cancelWorkers()
		}
		errMu.Unlock()
	}
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for index := range jobs {
			if workerCtx.Err() != nil {
				return
			}
			group := groups[index]
			if len(group.Values) > limits.MaxValuesPerKey {
				setErr(fmt.Errorf("%w: key %q values %d > %d", ErrLimitExceeded, group.Key, len(group.Values), limits.MaxValuesPerKey))
				return
			}
			input := ReduceInput{JobID: request.ID, SourceNode: metadata.SourceNode, TargetNode: metadata.TargetNode, Labels: cloneLabels(request.Labels), Group: group}
			output, err := e.registry.Reduce(workerCtx, request.Plugin, input)
			if err == nil {
				err = validateRecord(output)
			}
			if err != nil {
				setErr(err)
				return
			}
			results[index] = Record{Key: output.Key, Value: append([]byte(nil), output.Value...)}
		}
	}
	wg.Add(parallel)
	for i := 0; i < parallel; i++ {
		go worker()
	}

sendLoop:
	for index := range groups {
		select {
		case jobs <- index:
		case <-workerCtx.Done():
			break sendLoop
		}
	}
	close(jobs)
	wg.Wait()
	errMu.Lock()
	err := firstErr
	errMu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateOutput(results, limits); err != nil {
		return nil, err
	}
	return results, nil
}

func validateOutput(records []Record, limits Limits) error {
	if len(records) > limits.MaxOutputRecords {
		return fmt.Errorf("%w: output records %d > %d", ErrLimitExceeded, len(records), limits.MaxOutputRecords)
	}
	_, bytes := OutputMetrics(records)
	if bytes > limits.MaxOutputBytes {
		return fmt.Errorf("%w: output bytes %d > %d", ErrLimitExceeded, bytes, limits.MaxOutputBytes)
	}
	return nil
}

func (e *Engine) report(err error) {
	if err == nil || e == nil || e.reporter == nil {
		return
	}
	defer func() { _ = recover() }()
	e.reporter(err)
}
