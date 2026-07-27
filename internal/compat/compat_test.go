package compat

import "testing"

func TestPlansForSupportedCompatibilityKinds(t *testing.T) {
	cases := []Profile{
		{Kind: "s3", Endpoint: "s3://bucket/prefix", Region: "us-east-1"},
		{Kind: "https", Endpoint: "https://api.example.com/hook"},
		{Kind: "mqtt", Endpoint: "mqtts://broker.example.com:8883"},
		{Kind: "hadoop", Endpoint: "hdfs://namenode.example.com:8020/data"},
	}
	for _, tc := range cases {
		plan, err := tc.Plan()
		if err != nil {
			t.Fatalf("Plan(%s): %v", tc.Kind, err)
		}
		if plan.DataPlaneOwner != DataPlaneOwnerWeaverssh {
			t.Fatalf("%s data plane owner=%q", tc.Kind, plan.DataPlaneOwner)
		}
		if len(plan.Capabilities) == 0 || len(plan.Notes) == 0 {
			t.Fatalf("%s missing plan details: %+v", tc.Kind, plan)
		}
	}
}

func TestCompatibilityRejectsInsecureRemoteMQTT(t *testing.T) {
	_, err := (Profile{Kind: "mqtt", Endpoint: "mqtt://broker.example.com:1883"}).Plan()
	if err == nil {
		t.Fatal("expected non-loopback mqtt:// to be rejected")
	}
	if _, err := (Profile{Kind: "mqtt", Endpoint: "mqtt://127.0.0.1:1883"}).Plan(); err != nil {
		t.Fatalf("loopback mqtt should be accepted: %v", err)
	}
}

func TestCompatibilityRejectsWrongScheme(t *testing.T) {
	if _, err := (Profile{Kind: "https", Endpoint: "http://example.com"}).Plan(); err == nil {
		t.Fatal("https compatibility must reject http")
	}
	if _, err := (Profile{Kind: "s3", Endpoint: "http://s3.example.com/bucket"}).Plan(); err == nil {
		t.Fatal("s3 compatibility must reject http endpoint")
	}
}
