package mapreduce

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// UnmarshalJSON validates rule selectors before policy normalization. In
// particular, an unknown source role must not be silently removed because an
// empty normalized role set means "all roles".
func (r *Rule) UnmarshalJSON(payload []byte) error {
	type ruleAlias Rule
	var decoded ruleAlias
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("mapreduce: trailing rule JSON data")
	}
	for _, rawRole := range decoded.SourceRoles {
		role := strings.TrimSpace(rawRole)
		switch role {
		case "origin", "intermediate", "endpoint", "single":
		default:
			return fmt.Errorf("mapreduce: invalid source role %q", rawRole)
		}
	}
	*r = Rule(decoded)
	return nil
}
