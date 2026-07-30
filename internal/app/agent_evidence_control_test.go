package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"weaverssh/evidencebinding"
	"weaverssh/socketcontrol"
)

func TestAgentEvidenceControlStatusVerifyAndExport(t *testing.T) {
	root := t.TempDir()
	runtime, err := NewAgentRuntimeWithEmbeddedImmuDB(AgentConfig{
		InterfaceMode: string(AgentInterfaceLibrary),
		ListenNetwork: string(AgentInterfaceLibrary),
		X11Network: "unix",
		X11Target: filepath.Join(root, "x11.sock"),
		AuthTimeout: time.Second,
	}, "cookie", AgentEmbeddedImmuDBConfig{Path: filepath.Join(root, "evidence"), ProviderName: "node-test", StreamID: "agent/node-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	socketPath := filepath.Join(root, "control.sock")
	tokenPath := filepath.Join(root, "control.token")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	control, err := StartAgentEvidenceControl(ctx, runtime, AgentEvidenceControlConfig{Network: "unix", Address: socketPath, TokenFile: tokenPath})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	token, err := socketcontrol.DecodeToken(string(data))
	if err != nil {
		t.Fatal(err)
	}
	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	response, err := socketcontrol.Call(callCtx, "unix", socketPath, token, socketcontrol.ActionEvidenceStatus, "")
	if err != nil {
		t.Fatal(err)
	}
	var status evidencebinding.AgentJournalStatus
	if err := socketcontrol.DecodePayload(response, &status); err != nil {
		t.Fatal(err)
	}
	if status.Records == 0 || status.StreamID != "agent/node-test" {
		t.Fatalf("status=%+v", status)
	}
	response, err = socketcontrol.Call(callCtx, "unix", socketPath, token, socketcontrol.ActionEvidenceVerify, "")
	if err != nil {
		t.Fatal(err)
	}
	var report evidencebinding.VerificationReport
	if err := socketcontrol.DecodePayload(response, &report); err != nil {
		t.Fatal(err)
	}
	if !report.Authentic || !report.CompletenessBound {
		t.Fatalf("report=%+v", report)
	}
	response, err = socketcontrol.Call(callCtx, "unix", socketPath, token, socketcontrol.ActionEvidenceExport, "10")
	if err != nil {
		t.Fatal(err)
	}
	var exported evidencebinding.AgentJournalExport
	if err := socketcontrol.DecodePayload(response, &exported); err != nil {
		t.Fatal(err)
	}
	if len(exported.Records) == 0 {
		t.Fatal("expected exported records")
	}
}
