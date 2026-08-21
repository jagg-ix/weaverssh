package main

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"weaverssh/containerstream"
	"weaverssh/terminalsession"
)

func TestBuildTerminalTargetURI(t *testing.T) {
	raw, err := buildTerminalTargetURI("node-a", "pod-a", "podman", "jobs", "worker", "", []string{"user=1000"})
	if err != nil {
		t.Fatal(err)
	}
	request, err := containerstream.ParseURI(raw)
	if err != nil {
		t.Fatal(err)
	}
	if request.Endpoint != "node-a" || request.TargetID != "pod-a" || request.ProviderHint != "podman" || request.Options["namespace"] != "jobs" || request.Options["container"] != "worker" || request.Options["user"] != "1000" {
		t.Fatalf("request=%+v", request)
	}
	nomadURI, err := buildTerminalTargetURI("node-a", "alloc-a", "nomad", "jobs", "", "api", nil)
	if err != nil {
		t.Fatal(err)
	}
	nomad, err := containerstream.ParseURI(nomadURI)
	if err != nil || nomad.Options["task"] != "api" || nomad.Options["container"] != "" {
		t.Fatalf("nomad request=%+v err=%v", nomad, err)
	}
	if _, err := buildTerminalTargetURI("", "pod-a", "", "", "", "", nil); err == nil {
		t.Fatal("empty node accepted")
	}
	if _, err := buildTerminalTargetURI("node-a", "pod-a", "", "jobs", "", "", []string{"namespace=other"}); err == nil {
		t.Fatal("duplicate option accepted")
	}
}

func TestTerminateTerminalClientDrainsReplayBeforeAcknowledgement(t *testing.T) {
	clientStream, serverStream := net.Pipe()
	codec := terminalsession.Codec{}
	client, err := terminalsession.NewClient(clientStream, codec)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	serverDone := make(chan error, 1)
	go func() {
		defer serverStream.Close()
		for sequence := uint64(1); sequence <= 128; sequence++ {
			if err := codec.WriteFrame(serverStream, terminalsession.Frame{Type: terminalsession.FrameOutput, Sequence: sequence, Payload: []byte("replay")}); err != nil {
				serverDone <- err
				return
			}
		}
		frame, err := codec.ReadFrame(serverStream)
		if err != nil {
			serverDone <- err
			return
		}
		if frame.Type != terminalsession.FrameTerminate {
			serverDone <- context.Canceled
			return
		}
		payload, _ := json.Marshal(terminalsession.Exit{Protocol: terminalsession.ProtocolVersion, ExitCode: -1, Reason: "client-terminate"})
		serverDone <- codec.WriteFrame(serverStream, terminalsession.Frame{Type: terminalsession.FrameExit, Payload: payload})
	}()
	exit, err := terminateTerminalClient(client, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if exit.ExitCode != -1 || exit.Reason != "client-terminate" {
		t.Fatalf("exit=%+v", exit)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestDetachKeyParsing(t *testing.T) {
	key, err := parseDetachKey("^]")
	if err != nil || key == nil || *key != defaultTerminalDetachByte {
		t.Fatalf("key=%v error=%v", key, err)
	}
	key, err = parseDetachKey("none")
	if err != nil || key != nil {
		t.Fatalf("key=%v error=%v", key, err)
	}
	if _, err := parseDetachKey("ctrl-c"); err == nil || !strings.Contains(err.Error(), "detach-key") {
		t.Fatalf("error=%v", err)
	}
}
