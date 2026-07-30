package fabricbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"weaverssh/evidencebinding"
)

const (
	SubmitPath   = "/v1/fabric/submit"
	EvaluatePath = "/v1/fabric/evaluate"
	HealthPath   = "/healthz"
)

type Config struct {
	Token           string
	PeerBinary      string
	Orderer         string
	OrdererCA       string
	PeerAddresses   []string
	PeerTLSRoots    []string
	QueryFunction   string
	WaitForEvent    time.Duration
	CommandTimeout  time.Duration
	AdditionalEnv   []string
	MaxRequestBytes int64
}

type CommandRunner interface {
	Run(context.Context, []string, string, ...string) ([]byte, []byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, environment []string, name string, args ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = environment
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

type Server struct {
	Config Config
	Runner CommandRunner
}

type anchorRequest struct {
	Channel        string                           `json:"channel"`
	Chaincode      string                           `json:"chaincode"`
	Contract       string                           `json:"contract,omitempty"`
	Function       string                           `json:"function"`
	IdempotencyKey string                           `json:"idempotency_key"`
	Statement      evidencebinding.AnchorStatement `json:"statement"`
}

type anchorResponse struct {
	TransactionID string                           `json:"transaction_id"`
	BlockNumber   uint64                           `json:"block_number"`
	Successful    bool                             `json:"successful"`
	Statement     evidencebinding.AnchorStatement `json:"statement"`
}

type chaincodeRecord struct {
	IdempotencyKey string                           `json:"idempotency_key"`
	Statement      evidencebinding.AnchorStatement `json:"statement"`
	TransactionID  string                           `json:"transaction_id"`
}

func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(HealthPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc(SubmitPath, s.handleSubmit)
	mux.HandleFunc(EvaluatePath, s.handleEvaluate)
	return mux
}

func (s Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	body, ok := s.authorizedRequest(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.commandTimeout())
	defer cancel()
	if err := s.invoke(ctx, body); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	record, err := s.query(ctx, body, s.queryFunction())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if err := validateRecord(body, record); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	height, err := s.channelHeight(ctx, body.Channel)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if height < 2 {
		writeError(w, http.StatusBadGateway, errors.New("Fabric channel has no committed application block"))
		return
	}
	writeJSON(w, http.StatusOK, anchorResponse{TransactionID: record.TransactionID, BlockNumber: height - 1, Successful: true, Statement: record.Statement})
}

func (s Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	body, ok := s.authorizedRequest(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.commandTimeout())
	defer cancel()
	record, err := s.query(ctx, body, body.Function)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if err := validateRecord(body, record); err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, anchorResponse{TransactionID: record.TransactionID, Successful: true, Statement: record.Statement})
}

func validateRecord(request anchorRequest, record chaincodeRecord) error {
	if record.Statement != request.Statement || record.IdempotencyKey != request.IdempotencyKey || strings.TrimSpace(record.TransactionID) == "" {
		return evidencebinding.ErrAnchorMismatch
	}
	return nil
}

func (s Server) authorizedRequest(w http.ResponseWriter, r *http.Request) (anchorRequest, bool) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return anchorRequest{}, false
	}
	if token := strings.TrimSpace(s.Config.Token); token != "" && r.Header.Get("Authorization") != "Bearer "+token {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return anchorRequest{}, false
	}
	limit := s.Config.MaxRequestBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, limit))
	decoder.DisallowUnknownFields()
	var body anchorRequest
	if err := decoder.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return anchorRequest{}, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("trailing JSON value")
		}
		writeError(w, http.StatusBadRequest, err)
		return anchorRequest{}, false
	}
	if strings.TrimSpace(body.Channel) == "" || strings.TrimSpace(body.Chaincode) == "" || strings.TrimSpace(body.Function) == "" || strings.TrimSpace(body.IdempotencyKey) == "" {
		writeError(w, http.StatusBadRequest, errors.New("channel, chaincode, function, and idempotency_key are required"))
		return anchorRequest{}, false
	}
	if err := body.Statement.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return anchorRequest{}, false
	}
	return body, true
}

func (s Server) invoke(ctx context.Context, request anchorRequest) error {
	statement, err := request.Statement.CanonicalBytes()
	if err != nil {
		return err
	}
	constructor, err := constructorJSON(functionName(request.Contract, request.Function), request.IdempotencyKey, string(statement))
	if err != nil {
		return err
	}
	args := []string{"chaincode", "invoke", "-C", request.Channel, "-n", request.Chaincode, "-c", constructor, "--waitForEvent", "--waitForEventTimeout", s.waitForEvent().String()}
	if orderer := strings.TrimSpace(s.Config.Orderer); orderer != "" {
		args = append(args, "-o", orderer)
	}
	if ca := strings.TrimSpace(s.Config.OrdererCA); ca != "" {
		args = append(args, "--tls", "--cafile", ca)
	}
	args = append(args, s.peerArguments()...)
	_, stderr, err := s.runner().Run(ctx, s.environment(), s.peerBinary(), args...)
	if err != nil {
		return fmt.Errorf("peer chaincode invoke: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	return nil
}

func (s Server) query(ctx context.Context, request anchorRequest, function string) (chaincodeRecord, error) {
	constructor, err := constructorJSON(functionName(request.Contract, function), request.IdempotencyKey)
	if err != nil {
		return chaincodeRecord{}, err
	}
	args := []string{"chaincode", "query", "-C", request.Channel, "-n", request.Chaincode, "-c", constructor}
	args = append(args, s.peerArguments()...)
	stdout, stderr, err := s.runner().Run(ctx, s.environment(), s.peerBinary(), args...)
	if err != nil {
		return chaincodeRecord{}, fmt.Errorf("peer chaincode query: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	var record chaincodeRecord
	if err := decodeJSONObject(stdout, &record); err != nil {
		return chaincodeRecord{}, fmt.Errorf("decode chaincode record: %w", err)
	}
	return record, nil
}

func (s Server) channelHeight(ctx context.Context, channel string) (uint64, error) {
	stdout, stderr, err := s.runner().Run(ctx, s.environment(), s.peerBinary(), "channel", "getinfo", "-c", channel)
	if err != nil {
		return 0, fmt.Errorf("peer channel getinfo: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	var info struct {
		Height json.Number `json:"height"`
	}
	if err := decodeJSONObject(stdout, &info); err != nil {
		return 0, err
	}
	return strconv.ParseUint(info.Height.String(), 10, 64)
}

func (s Server) peerArguments() []string {
	var args []string
	for _, value := range s.Config.PeerAddresses {
		if value = strings.TrimSpace(value); value != "" {
			args = append(args, "--peerAddresses", value)
		}
	}
	for _, value := range s.Config.PeerTLSRoots {
		if value = strings.TrimSpace(value); value != "" {
			args = append(args, "--tlsRootCertFiles", value)
		}
	}
	return args
}

func (s Server) environment() []string { return append(os.Environ(), s.Config.AdditionalEnv...) }
func (s Server) runner() CommandRunner {
	if s.Runner != nil {
		return s.Runner
	}
	return ExecRunner{}
}
func (s Server) peerBinary() string {
	if value := strings.TrimSpace(s.Config.PeerBinary); value != "" {
		return value
	}
	return "peer"
}
func (s Server) queryFunction() string {
	if value := strings.TrimSpace(s.Config.QueryFunction); value != "" {
		return value
	}
	return "ReadEvidenceAnchor"
}
func (s Server) waitForEvent() time.Duration {
	if s.Config.WaitForEvent > 0 {
		return s.Config.WaitForEvent
	}
	return 30 * time.Second
}
func (s Server) commandTimeout() time.Duration {
	if s.Config.CommandTimeout > 0 {
		return s.Config.CommandTimeout
	}
	return 60 * time.Second
}

func functionName(contract, function string) string {
	contract, function = strings.TrimSpace(contract), strings.TrimSpace(function)
	if contract == "" || strings.Contains(function, ":") {
		return function
	}
	return contract + ":" + function
}

func constructorJSON(function string, arguments ...string) (string, error) {
	encoded, err := json.Marshal(struct {
		Function string   `json:"Function"`
		Args     []string `json:"Args"`
	}{Function: function, Args: arguments})
	return string(encoded), err
}

func decodeJSONObject(data []byte, destination any) error {
	for index, value := range data {
		if value != '{' {
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(data[index:]))
		decoder.UseNumber()
		if err := decoder.Decode(destination); err != nil {
			continue
		}
		var trailing any
		if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) {
			return nil
		}
	}
	return errors.New("no complete JSON object found")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{"ok": false, "error": err.Error()})
}
