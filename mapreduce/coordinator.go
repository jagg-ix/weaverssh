package mapreduce

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Coordinator composes independently authorized map and reduce calls. Every
// target re-evaluates its local rule policy; coordinator success never bypasses
// a target's own constraints.
type Coordinator struct {
	Caller Caller
}

func (c Coordinator) Run(ctx context.Context, spec JobSpec) ([]Record, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c.Caller == nil {
		return nil, errors.New("mapreduce: coordinator caller is required")
	}
	plugin := strings.TrimSpace(spec.Plugin)
	if !validName(plugin) || len(spec.Records) == 0 || len(spec.Records) > MaxRecords {
		return nil, ErrInvalidRequest
	}
	if err := validateLabels(spec.Labels); err != nil {
		return nil, err
	}
	targets, partitions, err := partitionTargets(spec.MapTargets, spec.Records)
	if err != nil {
		return nil, err
	}
	reduceTarget := strings.TrimSpace(spec.ReduceTarget)
	if reduceTarget == "" {
		reduceTarget = targets[0]
	}
	if !validNodeName(reduceTarget) {
		return nil, ErrInvalidRequest
	}
	fanout := uniqueCount(append(append([]string(nil), targets...), reduceTarget))
	if fanout > HardLimits().MaxFanout {
		return nil, ErrLimitExceeded
	}

	jobID := NewJobID()
	mappedByTarget := make([][]Record, len(targets))
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error
	for index, target := range targets {
		index, target := index, target
		records := partitions[index]
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, callErr := c.Caller.Call(workerCtx, target, Request{
				Protocol: ProtocolVersion, ID: jobID + "-map-" + fmt.Sprint(index), Operation: OperationMap, Plugin: plugin,
				Records: records, Labels: cloneLabels(spec.Labels), RequestedParallel: spec.RequestedParallel,
				RequestedTimeoutMillis: spec.RequestedTimeoutMillis, Fanout: fanout,
			})
			if callErr != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = callErr
					cancel()
				}
				errMu.Unlock()
				return
			}
			mappedByTarget[index] = append([]Record(nil), response.Records...)
		}()
	}
	wg.Wait()
	errMu.Lock()
	mapErr := firstErr
	errMu.Unlock()
	if mapErr != nil {
		return nil, mapErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var mapped []Record
	for _, records := range mappedByTarget {
		mapped = append(mapped, records...)
	}
	groups, err := GroupRecords(mapped, MaxValuesPerGroup)
	if err != nil {
		return nil, err
	}
	response, err := c.Caller.Call(ctx, reduceTarget, Request{
		Protocol: ProtocolVersion, ID: jobID + "-reduce", Operation: OperationReduce, Plugin: plugin,
		Groups: groups, Labels: cloneLabels(spec.Labels), RequestedParallel: spec.RequestedParallel,
		RequestedTimeoutMillis: spec.RequestedTimeoutMillis, Fanout: fanout,
	})
	if err != nil {
		return nil, err
	}
	return response.Records, nil
}

func partitionTargets(rawTargets []string, records []Record) ([]string, [][]Record, error) {
	seen := map[string]bool{}
	targets := make([]string, 0, len(rawTargets))
	for _, target := range rawTargets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if !validNodeName(target) {
			return nil, nil, ErrInvalidRequest
		}
		if !seen[target] {
			seen[target] = true
			targets = append(targets, target)
		}
	}
	if len(targets) == 0 || len(targets) > HardLimits().MaxFanout {
		return nil, nil, ErrInvalidRequest
	}
	partitions := make([][]Record, len(targets))
	for index, record := range records {
		targetIndex := index % len(targets)
		partitions[targetIndex] = append(partitions[targetIndex], Record{Key: record.Key, Value: append([]byte(nil), record.Value...)})
	}
	// Empty partitions are removed so the fanout reflects actual calls.
	compactTargets := make([]string, 0, len(targets))
	compactPartitions := make([][]Record, 0, len(targets))
	for index, target := range targets {
		if len(partitions[index]) > 0 {
			compactTargets = append(compactTargets, target)
			compactPartitions = append(compactPartitions, partitions[index])
		}
	}
	return compactTargets, compactPartitions, nil
}

func uniqueCount(values []string) int {
	set := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = true
		}
	}
	return len(set)
}

func SortedRecords(records []Record) []Record {
	out := append([]Record(nil), records...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
