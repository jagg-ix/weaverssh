package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"weaverssh/socksproof"
)

const maxProofUDPPayloadBytes = 48 << 10

func cmdSocksBind(args []string) int {
	fs := flag.NewFlagSet("socks-bind", flag.ContinueOnError)
	proxy, principal, serverID, policySHA, node, privateKey, signerProvider, agentSocket, identity, identityFile, proofTTL, timeout := socksProofClientFlags(fs)
	jsonOut := fs.Bool("json", false, "emit bound and accepted addresses as JSON lines")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv socks-bind --proxy HOST:PORT --server-id ID --policy-sha256 HEX --node NODE --principal ID [signer options] EXPECTED_PEER:PORT")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || missingProofClientFlags(*proxy, *principal, *serverID, *policySHA, *node) {
		fs.Usage()
		return 2
	}
	signer, code := buildSocksProofSigner(*signerProvider, *privateKey, *agentSocket, *identity, *identityFile)
	if code != 0 {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	dialCtx, cancel := context.WithTimeout(ctx, *timeout)
	client, err := socksproof.DialBind(dialCtx, *proxy, fs.Arg(0), proofClientConfig(*principal, *serverID, *policySHA, *node, signer, *proofTTL))
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socks-bind: %v\n", err)
		return 1
	}
	defer client.Close()
	if *jsonOut {
		_ = json.NewEncoder(os.Stderr).Encode(map[string]any{"event": "bound", "address": client.Addr().String()})
	} else {
		fmt.Fprintf(os.Stderr, "bound: %s\n", client.Addr())
	}
	peer, err := client.Accept(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socks-bind: accept: %v\n", err)
		return 1
	}
	peerAddress := client.PeerAddr()
	if peerAddress == nil {
		fmt.Fprintln(os.Stderr, "wv socks-bind: accepted peer address is unavailable")
		return 1
	}
	if *jsonOut {
		_ = json.NewEncoder(os.Stderr).Encode(map[string]any{"event": "accepted", "peer": peerAddress.String()})
	} else {
		fmt.Fprintf(os.Stderr, "accepted: %s\n", peerAddress)
	}
	return relayConsole(ctx, peer, "wv socks-bind")
}

func cmdSocksUDP(args []string) int {
	fs := flag.NewFlagSet("socks-udp", flag.ContinueOnError)
	proxy, principal, serverID, policySHA, node, privateKey, signerProvider, agentSocket, identity, identityFile, proofTTL, timeout := socksProofClientFlags(fs)
	input := fs.String("input", "-", "datagram payload file or - for stdin")
	jsonOut := fs.Bool("json", false, "emit response metadata and base64 payload")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv socks-udp --proxy HOST:PORT --server-id ID --policy-sha256 HEX --node NODE --principal ID [signer options] DEST:PORT")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || missingProofClientFlags(*proxy, *principal, *serverID, *policySHA, *node) {
		fs.Usage()
		return 2
	}
	payload, err := readBoundedDatagramInput(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socks-udp: input: %v\n", err)
		return 1
	}
	signer, code := buildSocksProofSigner(*signerProvider, *privateKey, *agentSocket, *identity, *identityFile)
	if code != 0 {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	dialCtx, cancel := context.WithTimeout(ctx, *timeout)
	client, err := socksproof.DialUDP(dialCtx, *proxy, proofClientConfig(*principal, *serverID, *policySHA, *node, signer, *proofTTL))
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socks-udp: %v\n", err)
		return 1
	}
	defer client.Close()
	if err := client.Send(fs.Arg(0), payload); err != nil {
		fmt.Fprintf(os.Stderr, "wv socks-udp: send: %v\n", err)
		return 1
	}
	receiveCtx, receiveCancel := context.WithTimeout(ctx, *timeout)
	defer receiveCancel()
	response, err := client.Receive(receiveCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socks-udp: receive: %v\n", err)
		return 1
	}
	if *jsonOut {
		return printJSON(map[string]any{
			"address":        response.Address,
			"payload_base64": base64.StdEncoding.EncodeToString(response.Data),
			"bytes":          len(response.Data),
		})
	}
	if _, err = os.Stdout.Write(response.Data); err != nil {
		fmt.Fprintf(os.Stderr, "wv socks-udp: output: %v\n", err)
		return 1
	}
	return 0
}

func socksProofClientFlags(fs *flag.FlagSet) (*string, *string, *string, *string, *string, *string, *string, *string, *string, *string, *time.Duration, *time.Duration) {
	proxy := fs.String("proxy", "", "proof-enabled SOCKS5 proxy HOST:PORT")
	principal := fs.String("principal", "", "client principal from policy")
	serverID := fs.String("server-id", "", "expected proof-policy server ID")
	policySHA := fs.String("policy-sha256", "", "expected canonical policy SHA-256")
	node := fs.String("node", "", "expected selected final node")
	privateKey := fs.String("private-key", "", "Ed25519 private key file")
	signerProvider := fs.String("signer", "ssh-agent", "signer: ssh-agent, gpg-agent, or key")
	agentSocket := fs.String("agent-socket", "", "SSH-compatible agent socket")
	identity := fs.String("identity", "", "agent identity selector")
	identityFile := fs.String("identity-file", "", "agent identity/public-key selector file")
	proofTTL := fs.Duration("proof-ttl", 30*time.Second, "proof lifetime")
	timeout := fs.Duration("timeout", 30*time.Second, "handshake and operation timeout")
	return proxy, principal, serverID, policySHA, node, privateKey, signerProvider, agentSocket, identity, identityFile, proofTTL, timeout
}

func missingProofClientFlags(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}

func proofClientConfig(principal, serverID, policySHA, node string, signer socksproof.Signer, ttl time.Duration) socksproof.ClientConfig {
	return socksproof.ClientConfig{
		Principal:            strings.TrimSpace(principal),
		Signer:               signer,
		ProofTTL:             ttl,
		ExpectedServerID:     strings.TrimSpace(serverID),
		ExpectedPolicySHA256: strings.ToLower(strings.TrimSpace(policySHA)),
		ExpectedNode:         strings.TrimSpace(node),
	}
}

func readBoundedDatagramInput(path string) ([]byte, error) {
	var reader io.Reader = os.Stdin
	if strings.TrimSpace(path) != "" && path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		reader = file
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maxProofUDPPayloadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > maxProofUDPPayloadBytes {
		return nil, fmt.Errorf("payload must contain 1..%d bytes", maxProofUDPPayloadBytes)
	}
	return payload, nil
}
