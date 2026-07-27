package mapreduce

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

func NewOpenMetadata(target string) ([]byte, error) {
	metadata := OpenMetadata{Protocol: OpenProtocolVersion, TargetNode: strings.TrimSpace(target)}
	if metadata.TargetNode == "" || !validNodeName(metadata.TargetNode) {
		return nil, errors.New("mapreduce: invalid target node")
	}
	return json.Marshal(metadata)
}

// BindSource assigns provenance to an unbound local request. Routed brokers
// preserve an existing chain-bound source and only rewrite the concrete target.
func BindSource(raw []byte, sourceNode, sourceBinding, chainSHA256, targetNode string) ([]byte, error) {
	metadata, err := ParseOpenMetadata(raw)
	if err != nil {
		return nil, err
	}
	chainSHA256 = strings.ToLower(strings.TrimSpace(chainSHA256))
	targetNode = strings.TrimSpace(targetNode)
	if metadata.SourceNode == "" && metadata.SourceBinding == "" && metadata.ChainSHA256 == "" {
		metadata.SourceNode = strings.TrimSpace(sourceNode)
		metadata.SourceBinding = strings.TrimSpace(sourceBinding)
		metadata.ChainSHA256 = chainSHA256
	} else {
		metadata.SourceNode = strings.TrimSpace(metadata.SourceNode)
		metadata.SourceBinding = strings.TrimSpace(metadata.SourceBinding)
		metadata.ChainSHA256 = strings.ToLower(strings.TrimSpace(metadata.ChainSHA256))
		if metadata.ChainSHA256 != chainSHA256 {
			return nil, errors.New("mapreduce: forwarded provenance chain mismatch")
		}
	}
	metadata.TargetNode = targetNode
	if !validNodeName(metadata.SourceNode) || !validNodeName(metadata.TargetNode) || metadata.SourceBinding == "" || len(metadata.SourceBinding) > 512 || len(metadata.ChainSHA256) != 64 {
		return nil, errors.New("mapreduce: invalid broker provenance")
	}
	return json.Marshal(metadata)
}

func ParseOpenMetadata(raw []byte) (OpenMetadata, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return OpenMetadata{}, errors.New("mapreduce: invalid open metadata size")
	}
	var metadata OpenMetadata
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return OpenMetadata{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return OpenMetadata{}, errors.New("mapreduce: trailing open metadata")
	}
	if metadata.Protocol == "" {
		metadata.Protocol = OpenProtocolVersion
	}
	metadata.TargetNode = strings.TrimSpace(metadata.TargetNode)
	if metadata.Protocol != OpenProtocolVersion || metadata.TargetNode == "" {
		return OpenMetadata{}, errors.New("mapreduce: invalid open metadata")
	}
	return metadata, nil
}

func IsOpenMetadata(raw []byte) bool {
	metadata, err := ParseOpenMetadata(raw)
	return err == nil && metadata.Protocol == OpenProtocolVersion
}

func (e *Engine) Serve(ctx context.Context, stream io.ReadWriteCloser, metadataRaw []byte) error {
	if e == nil || stream == nil {
		return errors.New("mapreduce: incomplete server")
	}
	defer stream.Close()
	metadata, err := ParseOpenMetadata(metadataRaw)
	if err != nil {
		return err
	}
	request, err := readRequest(stream)
	if err != nil {
		_ = writeResponse(stream, errorResponse("", err, DecisionSummary{}))
		return nil
	}
	response, execErr := e.Execute(ctx, metadata, request)
	if execErr != nil {
		return writeResponse(stream, errorResponse(request.ID, execErr, response.Decision))
	}
	return writeResponse(stream, response)
}

func CallStream(ctx context.Context, stream io.ReadWriteCloser, request Request) (Response, error) {
	if stream == nil {
		return Response{}, errors.New("mapreduce: nil stream")
	}
	defer stream.Close()
	normalized, err := NormalizeRequest(request)
	if err != nil {
		return Response{}, err
	}
	if err := writeRequest(stream, normalized); err != nil {
		return Response{}, err
	}
	response, err := readResponse(stream)
	if err != nil {
		return Response{}, err
	}
	if response.ID != normalized.ID {
		return Response{}, errors.New("mapreduce: response ID mismatch")
	}
	if response.Error != nil {
		return response, fmt.Errorf("mapreduce %s: %s", response.Error.Code, response.Error.Message)
	}
	return response, nil
}

func writeRequest(writer io.Writer, request Request) error {
	request.Protocol = ProtocolVersion
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	return writeFrame(writer, payload)
}

func readRequest(reader io.Reader) (Request, error) {
	payload, err := readFrame(reader)
	if err != nil {
		return Request{}, err
	}
	var request Request
	if err := decodeStrict(payload, &request); err != nil {
		return Request{}, err
	}
	return NormalizeRequest(request)
}

func writeResponse(writer io.Writer, response Response) error {
	response.Protocol = ProtocolVersion
	payload, err := json.Marshal(response)
	if err != nil {
		return err
	}
	return writeFrame(writer, payload)
}

func readResponse(reader io.Reader) (Response, error) {
	payload, err := readFrame(reader)
	if err != nil {
		return Response{}, err
	}
	var response Response
	if err := decodeStrict(payload, &response); err != nil {
		return Response{}, err
	}
	if response.Protocol != ProtocolVersion {
		return Response{}, errors.New("mapreduce: wrong response protocol")
	}
	return response, nil
}

func writeFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > MaxMessageBytes {
		return errors.New("mapreduce: invalid message size")
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if err := writeAll(writer, header); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func readFrame(reader io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > MaxMessageBytes {
		return nil, errors.New("mapreduce: invalid message size")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func decodeStrict(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("mapreduce: trailing JSON data")
	}
	return nil
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func errorResponse(id string, err error, decision DecisionSummary) Response {
	code := "internal"
	switch {
	case errors.Is(err, ErrInvalidRequest):
		code = "invalid_request"
	case errors.Is(err, ErrDenied):
		code = "denied"
	case errors.Is(err, ErrPluginNotFound):
		code = "plugin_not_found"
	case errors.Is(err, ErrMapUnavailable):
		code = "map_unavailable"
	case errors.Is(err, ErrReduceUnavailable):
		code = "reduce_unavailable"
	case errors.Is(err, ErrLimitExceeded):
		code = "limit_exceeded"
	case errors.Is(err, context.DeadlineExceeded):
		code = "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		code = "canceled"
	}
	message := "mapreduce operation failed"
	if err != nil {
		message = err.Error()
	}
	if len(message) > MaxErrorBytes {
		message = message[:MaxErrorBytes]
	}
	return Response{Protocol: ProtocolVersion, ID: id, Decision: decision, Error: &ResponseError{Code: code, Message: message}}
}
