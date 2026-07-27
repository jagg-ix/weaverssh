package mapreduce

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	ProtocolVersion     = "weaverssh.mapreduce.v1"
	OpenProtocolVersion = "weaverssh.mapreduce-open.v1"
	PolicyVersion       = "weaverssh.mapreduce-policy.v1"
	PluginConfigVersion = "weaverssh.mapreduce-plugins.v1"

	MaxMessageBytes     = 16 << 20
	MaxRecords          = 4096
	MaxGroups           = 4096
	MaxValuesPerGroup   = 4096
	MaxRecordKeyBytes   = 1024
	MaxRecordValueBytes = 1 << 20
	MaxLabels           = 32
	MaxLabelKeyBytes    = 64
	MaxLabelValueBytes  = 1024
	MaxPluginNameBytes  = 128
	MaxJobIDBytes       = 128
	MaxErrorBytes       = 4096
)

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Operation string

const (
	OperationDescribe Operation = "describe"
	OperationMap      Operation = "map"
	OperationReduce   Operation = "reduce"
	OperationRun      Operation = "run"
)

func (o Operation) Valid() bool {
	switch o {
	case OperationDescribe, OperationMap, OperationReduce, OperationRun:
		return true
	default:
		return false
	}
}

type Record struct {
	Key   string `json:"key"`
	Value []byte `json:"value"`
}

type Group struct {
	Key    string   `json:"key"`
	Values [][]byte `json:"values"`
}

type Request struct {
	Protocol               string            `json:"protocol"`
	ID                     string            `json:"id"`
	Operation              Operation         `json:"operation"`
	Plugin                 string            `json:"plugin,omitempty"`
	Records                []Record          `json:"records,omitempty"`
	Groups                 []Group           `json:"groups,omitempty"`
	Labels                 map[string]string `json:"labels,omitempty"`
	RequestedParallel      int               `json:"requested_parallel,omitempty"`
	RequestedTimeoutMillis int64             `json:"requested_timeout_millis,omitempty"`
	Fanout                 int               `json:"fanout,omitempty"`
}

type Response struct {
	Protocol    string          `json:"protocol"`
	ID          string          `json:"id"`
	Records     []Record        `json:"records,omitempty"`
	Description Description     `json:"description,omitempty"`
	Decision    DecisionSummary `json:"decision,omitempty"`
	Error       *ResponseError  `json:"error,omitempty"`
}

type ResponseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type OpenMetadata struct {
	Protocol      string `json:"protocol"`
	SourceNode    string `json:"source_node,omitempty"`
	SourceBinding string `json:"source_binding,omitempty"`
	ChainSHA256   string `json:"chain_sha256,omitempty"`
	TargetNode    string `json:"target_node"`
}

type Limits struct {
	MaxItems          int   `json:"max_items"`
	MaxInputBytes     int64 `json:"max_input_bytes"`
	MaxOutputRecords  int   `json:"max_output_records"`
	MaxOutputBytes    int64 `json:"max_output_bytes"`
	MaxParallel       int   `json:"max_parallel"`
	MaxFanout         int   `json:"max_fanout"`
	MaxDurationMillis int64 `json:"max_duration_millis"`
	MaxValuesPerKey   int   `json:"max_values_per_key"`
}

func HardLimits() Limits {
	return Limits{
		MaxItems:          MaxRecords,
		MaxInputBytes:     MaxMessageBytes,
		MaxOutputRecords:  MaxRecords,
		MaxOutputBytes:    MaxMessageBytes,
		MaxParallel:       64,
		MaxFanout:         64,
		MaxDurationMillis: int64((10 * time.Minute) / time.Millisecond),
		MaxValuesPerKey:   MaxValuesPerGroup,
	}
}

type DecisionSummary struct {
	Allowed      bool     `json:"allowed"`
	RuleNames    []string `json:"rule_names,omitempty"`
	Limits       Limits   `json:"limits,omitempty"`
	PolicySHA256 string   `json:"policy_sha256,omitempty"`
}

type PluginDescription struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	HasMap      bool   `json:"has_map"`
	HasReduce   bool   `json:"has_reduce"`
	MapHooks    int    `json:"map_hooks,omitempty"`
	ReduceHooks int    `json:"reduce_hooks,omitempty"`
}

type Description struct {
	Protocol     string              `json:"protocol"`
	CurrentNode  string              `json:"current_node"`
	PolicySHA256 string              `json:"policy_sha256"`
	Plugins      []PluginDescription `json:"plugins"`
	Limits       Limits              `json:"hard_limits"`
}

type Invocation struct {
	SourceNode             string
	TargetNode             string
	SourceRole             string
	Operation              Operation
	Plugin                 string
	Labels                 map[string]string
	Items                  int
	InputBytes             int64
	RequestedParallel      int
	RequestedTimeoutMillis int64
	Fanout                 int
}

type JobSpec struct {
	Plugin                 string
	Records                []Record
	MapTargets             []string
	ReduceTarget           string
	Labels                 map[string]string
	RequestedParallel      int
	RequestedTimeoutMillis int64
}

var (
	ErrInvalidRequest    = errors.New("mapreduce: invalid request")
	ErrDenied            = errors.New("mapreduce: denied by policy")
	ErrPluginNotFound    = errors.New("mapreduce: plugin not found")
	ErrMapUnavailable    = errors.New("mapreduce: map stage unavailable")
	ErrReduceUnavailable = errors.New("mapreduce: reduce stage unavailable")
	ErrLimitExceeded     = errors.New("mapreduce: constraint limit exceeded")
)

func NormalizeRequest(raw Request) (Request, error) {
	out := raw
	if out.Protocol == "" {
		out.Protocol = ProtocolVersion
	}
	out.ID = strings.TrimSpace(out.ID)
	out.Plugin = strings.TrimSpace(out.Plugin)
	out.Labels = cloneLabels(out.Labels)
	if out.Protocol != ProtocolVersion || !out.Operation.Valid() || out.ID == "" || len(out.ID) > MaxJobIDBytes {
		return Request{}, ErrInvalidRequest
	}
	if out.Operation != OperationDescribe {
		if !validName(out.Plugin) {
			return Request{}, fmt.Errorf("%w: invalid plugin", ErrInvalidRequest)
		}
	}
	if out.RequestedParallel < 0 || out.RequestedTimeoutMillis < 0 || out.Fanout < 0 {
		return Request{}, ErrInvalidRequest
	}
	if err := validateLabels(out.Labels); err != nil {
		return Request{}, err
	}
	switch out.Operation {
	case OperationDescribe:
		if out.Plugin != "" || len(out.Records) != 0 || len(out.Groups) != 0 {
			return Request{}, ErrInvalidRequest
		}
	case OperationMap, OperationRun:
		if len(out.Records) == 0 || len(out.Records) > MaxRecords || len(out.Groups) != 0 {
			return Request{}, ErrInvalidRequest
		}
		for _, record := range out.Records {
			if err := validateRecord(record); err != nil {
				return Request{}, err
			}
		}
	case OperationReduce:
		if len(out.Groups) == 0 || len(out.Groups) > MaxGroups || len(out.Records) != 0 {
			return Request{}, ErrInvalidRequest
		}
		for _, group := range out.Groups {
			if err := validateGroup(group); err != nil {
				return Request{}, err
			}
		}
	}
	return out, nil
}

func validateRecord(record Record) error {
	if len(record.Key) > MaxRecordKeyBytes || strings.IndexByte(record.Key, 0) >= 0 || len(record.Value) > MaxRecordValueBytes {
		return fmt.Errorf("%w: invalid record", ErrInvalidRequest)
	}
	return nil
}

func validateGroup(group Group) error {
	if len(group.Key) > MaxRecordKeyBytes || strings.IndexByte(group.Key, 0) >= 0 || len(group.Values) == 0 || len(group.Values) > MaxValuesPerGroup {
		return fmt.Errorf("%w: invalid reduce group", ErrInvalidRequest)
	}
	for _, value := range group.Values {
		if len(value) > MaxRecordValueBytes {
			return fmt.Errorf("%w: reduce value too large", ErrInvalidRequest)
		}
	}
	return nil
}

func validateLabels(labels map[string]string) error {
	if len(labels) > MaxLabels {
		return fmt.Errorf("%w: too many labels", ErrInvalidRequest)
	}
	for key, value := range labels {
		if key == "" || key != strings.TrimSpace(key) || len(key) > MaxLabelKeyBytes || len(value) > MaxLabelValueBytes || strings.IndexByte(key, 0) >= 0 || strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("%w: invalid label", ErrInvalidRequest)
		}
	}
	return nil
}

func InputMetrics(request Request) (int, int64) {
	items := 0
	var bytes int64
	switch request.Operation {
	case OperationMap, OperationRun:
		items = len(request.Records)
		for _, r := range request.Records {
			bytes += int64(len(r.Key) + len(r.Value))
		}
	case OperationReduce:
		items = len(request.Groups)
		for _, g := range request.Groups {
			bytes += int64(len(g.Key))
			for _, value := range g.Values {
				bytes += int64(len(value))
			}
		}
	}
	return items, bytes
}

func OutputMetrics(records []Record) (int, int64) {
	var bytes int64
	for _, r := range records {
		bytes += int64(len(r.Key) + len(r.Value))
	}
	return len(records), bytes
}

func GroupRecords(records []Record, maxValues int) ([]Group, error) {
	if maxValues <= 0 {
		maxValues = MaxValuesPerGroup
	}
	grouped := make(map[string][][]byte)
	for _, record := range records {
		values := grouped[record.Key]
		if len(values) >= maxValues {
			return nil, fmt.Errorf("%w: key %q exceeds max values", ErrLimitExceeded, record.Key)
		}
		grouped[record.Key] = append(values, append([]byte(nil), record.Value...))
	}
	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]Group, 0, len(keys))
	for _, key := range keys {
		out = append(out, Group{Key: key, Values: grouped[key]})
	}
	return out, nil
}

func NewJobID() string {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("job-%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func validName(value string) bool {
	return len(value) <= MaxPluginNameBytes && namePattern.MatchString(value)
}

func validNodeName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 || strings.IndexByte(value, 0) >= 0 {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func cloneLabels(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for k, v := range values {
		out[k] = v
	}
	return out
}
