package sessioncontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"weaverssh/sessionmux"
)

func ServeReconnectStream(
	ctx context.Context,
	stream io.ReadWriteCloser,
	registry *Registry,
	config ReconnectServerConfig,
) (ReconnectAccepted, error) {
	if stream == nil || registry == nil || len(config.AuthorityPublicKey) != ed25519.PublicKeySize {
		return ReconnectAccepted{}, ErrReconnectProtocol
	}
	now := reconnectNow(config.Now)
	ttl := config.ChallengeTTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	challenge, err := NewReconnectChallenge(config.LocalContext, config.PeerNode, config.TransportID, config.SessionBinding, ttl, now)
	if err != nil {
		return ReconnectAccepted{}, err
	}
	if err := writeReconnectFrame(stream, ReconnectChallengeEnvelope{
		Type: reconnectChallengeType, Protocol: ReconnectProtocolVersion, Challenge: challenge,
	}); err != nil {
		return ReconnectAccepted{}, err
	}
	var request ReconnectProofEnvelope
	if err := readReconnectFrameContext(ctx, stream, &request); err != nil {
		return ReconnectAccepted{}, err
	}
	response := RegisterResponse{Type: reconnectAcceptedType, Protocol: ReconnectProtocolVersion}
	deny := func(reason error) (ReconnectAccepted, error) {
		response.Error = reason.Error()
		_ = writeReconnectFrame(stream, response)
		return ReconnectAccepted{}, reason
	}
	if request.Type != reconnectProofType || request.Protocol != ReconnectProtocolVersion {
		return deny(ErrReconnectProtocol)
	}
	verifiedIdentity, services, err := VerifyReconnectProof(
		challenge, request.Identity, request.Proof, config.AuthorityPublicKey,
		config.MaxIdentityTTL, config.ReplayCache, reconnectNow(config.Now),
	)
	if err != nil {
		return deny(err)
	}
	node, err := registry.RegisterVerified(verifiedIdentity.Context, services)
	if err != nil {
		return deny(err)
	}
	response.Node = node.ID
	response.Services = node.Services()
	if err := writeReconnectFrame(stream, response); err != nil {
		return ReconnectAccepted{}, err
	}
	return ReconnectAccepted{
		Node: node, Identity: verifiedIdentity, LinkID: challenge.LinkID,
		TransportID: challenge.TransportID, SessionBinding: challenge.SessionBinding,
		Services: append([]sessionmux.ServiceID(nil), services...),
	}, nil
}

func RegisterNodeReconnectStream(
	ctx context.Context,
	stream io.ReadWriteCloser,
	config ReconnectClientConfig,
) (RegisterResponse, ReconnectChallenge, error) {
	if stream == nil {
		return RegisterResponse{}, ReconnectChallenge{}, ErrReconnectProtocol
	}
	var envelope ReconnectChallengeEnvelope
	if err := readReconnectFrameContext(ctx, stream, &envelope); err != nil {
		return RegisterResponse{}, ReconnectChallenge{}, err
	}
	if envelope.Type != reconnectChallengeType || envelope.Protocol != ReconnectProtocolVersion {
		return RegisterResponse{}, ReconnectChallenge{}, ErrReconnectProtocol
	}
	challenge := envelope.Challenge.Normalized()
	now := reconnectNow(config.Now)
	if err := challenge.Validate(now); err != nil {
		return RegisterResponse{}, challenge, err
	}
	identity := config.Identity.Identity.Normalized()
	if strings.TrimSpace(config.ExpectedAcceptorNode) != "" && challenge.AcceptorNode != strings.TrimSpace(config.ExpectedAcceptorNode) {
		return RegisterResponse{}, challenge, ErrReconnectChallenge
	}
	if strings.TrimSpace(config.ExpectedSessionBinding) != "" && challenge.SessionBinding != strings.TrimSpace(config.ExpectedSessionBinding) {
		return RegisterResponse{}, challenge, ErrWrongBinding
	}
	if config.ExpectedTransportID != "" && challenge.TransportID != config.ExpectedTransportID {
		return RegisterResponse{}, challenge, ErrReconnectChallenge
	}
	if challenge.ProverNode != identity.Context.CurrentNode || challenge.ChainSHA256 != identity.Context.ChainSHA256 {
		return RegisterResponse{}, challenge, ErrReconnectChallenge
	}
	proof, err := BuildReconnectProof(challenge, config.Identity, config.NodePrivateKey, config.Services, now)
	if err != nil {
		return RegisterResponse{}, challenge, err
	}
	if err := writeReconnectFrame(stream, ReconnectProofEnvelope{
		Type: reconnectProofType, Protocol: ReconnectProtocolVersion, Identity: config.Identity, Proof: proof,
	}); err != nil {
		return RegisterResponse{}, challenge, err
	}
	var response RegisterResponse
	if err := readReconnectFrameContext(ctx, stream, &response); err != nil {
		return RegisterResponse{}, challenge, err
	}
	if response.Protocol != ReconnectProtocolVersion || response.Type != reconnectAcceptedType {
		return response, challenge, ErrReconnectProtocol
	}
	if response.Error != "" {
		return response, challenge, fmt.Errorf("%w: %s", ErrControlDenied, response.Error)
	}
	return response, challenge, nil
}

func writeReconnectFrame(writer io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > maxReconnectMessageBytes {
		return ErrReconnectProtocol
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if err := writeReconnectAll(writer, header); err != nil {
		return err
	}
	return writeReconnectAll(writer, payload)
}

func readReconnectFrameContext(ctx context.Context, reader io.Reader, target any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	result := make(chan error, 1)
	go func() { result <- readReconnectFrame(reader, target) }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func readReconnectFrame(reader io.Reader, target any) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > maxReconnectMessageBytes {
		return ErrReconnectProtocol
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrReconnectProtocol
	}
	return nil
}

func writeReconnectAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		count, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		payload = payload[count:]
	}
	return nil
}

func reconnectNow(now func() time.Time) time.Time {
	if now == nil {
		return time.Now()
	}
	return now()
}
