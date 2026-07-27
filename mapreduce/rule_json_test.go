package mapreduce

import "testing"

func TestParsePolicyRejectsAnyInvalidSourceRole(t *testing.T) {
	_, err := ParsePolicy([]byte(`{
		"version":"weaverssh.mapreduce-policy.v1",
		"default":"deny",
		"rules":[{
			"name":"bad-role",
			"effect":"allow",
			"source_nodes":["*"],
			"source_roles":["origin","root"],
			"target_nodes":["*"],
			"plugins":["identity"],
			"operations":["map"]
		}]
	}`))
	if err == nil {
		t.Fatal("expected invalid source role rejection")
	}
}

func TestParsePolicyRejectsUnknownRuleFields(t *testing.T) {
	_, err := ParsePolicy([]byte(`{
		"version":"weaverssh.mapreduce-policy.v1",
		"default":"deny",
		"rules":[{
			"name":"unknown-field",
			"effect":"deny",
			"source_nodes":["*"],
			"target_nodes":["*"],
			"plugins":["*"],
			"operations":["map"],
			"shell":"/bin/sh"
		}]
	}`))
	if err == nil {
		t.Fatal("expected unknown rule field rejection")
	}
}
