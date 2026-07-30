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
	Token            string
	PeerBinary       string
	Orderer          string
	OrdererCA        string
	PeerAddresses    []string
	PeerTLSRoots     []string
	WaitForEvent     time.Duration
	CommandTimeout   time.Duration
	AdditionalEnv    []string
	MaxRequestBytes  int64
}

type CommandRunner interface {
	Run(context.Context, []string, string, ...string) ([]byte, []byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, environment []string, name string, args ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = environment
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

type Server struct {
	Config Config
	Runner CommandRunner
}

type anchorRequest struct {
	Channel        string                          `json:"channel"`
	Chaincode      string                          `json:"chaincode"`
	Contract       string                          `json:"contract,omitempty"`
	Function       string                          `json:"function"`
	IdempotencyKey string                          `json:"idempotency_key"`
	Statement      evidencebinding.AnchorStatement `json:"statement"`
}

type anchorResponse struct {
	TransactionID string                          `json:"transaction_id"`
	BlockNumber   uint64                          `json:"block_number"`
	Successful    bool                            `json:"successful"`
	Statement     evidencebinding.AnchorStatement `json:"statement"`
}

type chaincodeRecord struct {
	IdempotencyKey string                          `json:"idempotency_key"`
	Statement      evidencebinding.AnchorStatement `json:"statement"`
	TransactionID  string                          `json:"transaction_id"`
}

func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(HealthPath, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writeError(writer, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc(SubmitPath, s.handleSubmit)
	mux.HandleFunc(EvaluatePath, s.handleEvaluate)
	return mux
}

func (s Server) handleSubmit(writer http.ResponseWriter, request *http.Request) {
	body, ok := s.authorizedRequest(writer, request)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), s.commandTimeout())
	defer cancel()
	if err := s.invoke(ctx, body); err != nil {
		writeError(writer, http.StatusBadGateway, err)
		return
	}
	record, err := s.query(ctx, body)
	if err != nil {
		writeError(writer, http.StatusBadGateway, err)
		return
	}
	if record.Statement != body.Statement || record.IdempotencyKey != body.IdempotencyKey || strings.TrimSpace(record.TransactionID) == "" {
		writeError(writer, http.StatusConflict, evidencebinding.ErrAnchorMismatch)
		return
	}
	height, err := s.channelHeight(ctx, body.Channel)
	if err != nil {
		writeError(writer, http.StatusBadGateway, err)
		return
	}
	if height < 2 {
		writeError(writer, http.StatusBadGateway, errors.New("Fabric channel height does not contain a committed application block"))
		return
	}
	writeJSON(writer, http.StatusOK, anchorResponse{
		TransactionID: record.TransactionID,
		BlockNumber: height - 1,
		Successful: true,
		Statement: record.Statement,
	})
}

func (s Server) handleEvaluate(writer http.ResponseWriter, request *http.Request) {
	body, ok := s.authorizedRequest(writer, request)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), s.commandTimeout())
	defer cancel()
	record, err := s.query(ctx, body)
	if err != nil {
		writeError(writer, http.StatusBadGateway, err)
		return
	}
	if record.Statement != body.Statement || record.IdempotencyKey != body.IdempotencyKey || strings.TrimSpace(record.TransactionID) == "" {
		writeError(writer, http.StatusConflict, evidencebinding.ErrAnchorMismatch)
		return
	}
	writeJSON(writer, http.StatusOK, anchorResponse{
		TransactionID: record.TransactionID,
		Successful: true,
		Statement: record.Statement,
	})
}

func (s Server) authorizedRequest(writer http.ResponseWriter, request *http.Request) (anchorRequest, bool) {
	if request.Method != http.MethodPost {
		writeError(writer, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return anchorRequest{}, false
	}
	if token := strings.TrimSpace(s.Config.Token); token != "" {
		if request.Header.Get("Authorization") != "Bearer "+token {
			writeError(writer, http.StatusUnauthorized, errors.New("unauthorized"))
			return anchorRequest{}, false
		}
	}
	limit := s.Config.MaxRequestBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, limit))
	decoder.DisallowUnknownFields()
	var body anchorRequest
	if err := decoder.Decode(&body); err != nil {
		writeError(writer, http.StatusBadRequest, err)
		return anchorRequest{}, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("trailing JSON value")
		}
		writeError(writer, http.StatusBadRequest, err)
		return anchorRequest{}, false
	}
	if strings.TrimSpace(body.Channel) == "" || strings.TrimSpace(body.Chaincode) == "" || strings.TrimSpace(body.Function) == "" || strings.TrimSpace(body.IdempotencyKey) == "" {
		writeError(writer, http.StatusBadRequest, errors.New("channel, chaincode, function, and idempotency_key are required"))
		return anchorRequest{}, false
	}
	if err := body.Statement.Validate(); err != nil {
		writeError(writer, http.StatusBadRequest, err)
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

func (s Server) query(ctx context.Context, request anchorRequest) (chaincodeRecord, error) {
	constructor, err := constructorJSON(functionName(request.Contract, request.Function), request.IdempotencyKey)
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
	var info struct { Height json.Number `json:"height"` }
	if err := decodeJSONObject(stdout, &info); err != nil {
		return 0, err
	}
	height, err := strconv.ParseUint(info.Height.String(), 10, 64)
	if err != nil {
		return 0, err
	}
	return height, nil
}

func (s Server) peerArguments() []string {
	var args []string
	for _, address := range s.Config.PeerAddresses {
		if strings.TrimSpace(address) != "" {
			args = append(args, "--peerAddresses", strings.TrimSpace(address))
		}
	}
	for _, root := range s.Config.PeerTLSRoots {
		if strings.TrimSpace(root) != "" {
			args = append(args, "--tlsRootCertFiles", strings.TrimSpace(root))
		}
	}
	return args
}

func (s Server) environment() []string { return append(os.Environ(), s.Config.AdditionalEnv...) }
func (s Server) runner() CommandRunner {
	if s.Runner != nil { return s.Runner }
	return ExecRunner{}
}
func (s Server) peerBinary() string {
	if value := strings.TrimSpace(s.Config.PeerBinary); value != "" { return value }
	return "peer"
}
func (s Server) waitForEvent() time.Duration {
	if s.Config.WaitForEvent > 0 { return s.Config.WaitForEvent }
	return 30 * time.Second
}
func (s Server) commandTimeout() time.Duration {
	if s.Config.CommandTimeout > 0 { return s.Config.CommandTimeout }
	return 60 * time.Second
}

func functionName(contract, function string) string {
	contract = strings.TrimSpace(contract)
	function = strings.TrimSpace(function)
	if contract == "" || strings.Contains(function, ":") { return function }
	return contract + ":" + function
}

func constructorJSON(function string, arguments ...string) (string, error) {
	returnString, err := json.Marshal(struct {
		Function string   `json:"Function"`
		Args     []string `json:"Args"`
	}{Function: function, Args: arguments})
	return string(returnString), err
}

func decodeJSONObject(data []byte, destination any) error {
	for index, value := range data {
		if value != '{' { continue }
		decoder := json.NewDecoder(bytes.NewReader(data[index:]))
		decoder.UseNumber()
		if err := decoder.Decode(destination); err != nil { continue }
		var trailing any
		if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) { return nil }
	}
	return errors.New("no complete JSON object found")
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, err error) {
	writeJSON(writer, status, map[string]any{"ok": false, "error": err.Error()})
}
