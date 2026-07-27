package storageadapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	defaultMaxKeyBytes   = 4 << 10
	defaultMaxValueBytes = 16 << 20
	maximumKeyBytes      = 64 << 10
	maximumValueBytes    = 128 << 20
)

type Config struct {
	Version       string            `json:"version"`
	Engine        string            `json:"engine"`
	Namespace     string            `json:"namespace,omitempty"`
	Path          string            `json:"path,omitempty"`
	DSN           string            `json:"dsn,omitempty"`
	ReadOnly      bool              `json:"read_only,omitempty"`
	MaxKeyBytes   int               `json:"max_key_bytes,omitempty"`
	MaxValueBytes int               `json:"max_value_bytes,omitempty"`
	Options       map[string]string `json:"options,omitempty"`
}

func LoadConfigFile(path string) (Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Config{}, errors.New("storageadapter: configuration path is required")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	config, err := LoadConfig(bytes.NewReader(payload))
	if err != nil {
		return Config{}, err
	}
	base := filepath.Dir(path)
	if config.Path != "" && !filepath.IsAbs(config.Path) {
		config.Path = filepath.Clean(filepath.Join(base, config.Path))
	}
	return config.Normalize()
}

func LoadConfig(reader io.Reader) (Config, error) {
	if reader == nil {
		return Config{}, errors.New("storageadapter: nil configuration reader")
	}
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("storageadapter: trailing configuration data")
	}
	return config.Normalize()
}

func (config Config) Normalize() (Config, error) {
	config.Version = strings.TrimSpace(config.Version)
	if config.Version == "" {
		config.Version = ConfigVersion
	}
	if config.Version != ConfigVersion {
		return Config{}, fmt.Errorf("storageadapter: unsupported version %q", config.Version)
	}
	config.Engine = strings.ToLower(strings.TrimSpace(config.Engine))
	if config.Engine == "" {
		return Config{}, errors.New("storageadapter: engine is required")
	}
	if !validToken(config.Engine, 64) {
		return Config{}, fmt.Errorf("storageadapter: invalid engine %q", config.Engine)
	}
	config.Namespace = strings.Trim(strings.TrimSpace(config.Namespace), "/")
	if config.Namespace != "" && !validNamespace(config.Namespace) {
		return Config{}, errors.New("storageadapter: invalid namespace")
	}
	config.Path = strings.TrimSpace(config.Path)
	config.DSN = strings.TrimSpace(config.DSN)
	if strings.ContainsAny(config.Path, "\x00\r\n") || strings.ContainsAny(config.DSN, "\x00\r\n") {
		return Config{}, errors.New("storageadapter: invalid path or DSN")
	}
	if config.MaxKeyBytes == 0 {
		config.MaxKeyBytes = defaultMaxKeyBytes
	}
	if config.MaxValueBytes == 0 {
		config.MaxValueBytes = defaultMaxValueBytes
	}
	if config.MaxKeyBytes < 1 || config.MaxKeyBytes > maximumKeyBytes {
		return Config{}, fmt.Errorf("storageadapter: max_key_bytes must be 1..%d", maximumKeyBytes)
	}
	if config.MaxValueBytes < 1 || config.MaxValueBytes > maximumValueBytes {
		return Config{}, fmt.Errorf("storageadapter: max_value_bytes must be 1..%d", maximumValueBytes)
	}
	config.Options = cleanOptions(config.Options)
	return config, nil
}

func cleanOptions(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	output := map[string]string{}
	for _, key := range keys {
		value := input[key]
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if validToken(key, 128) && len(value) <= 4096 && !strings.ContainsAny(value, "\x00\r\n") {
			output[key] = value
		}
	}
	if len(output) == 0 {
		return nil
	}
	return output
}

func validToken(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, r := range value {
		if !(r == '-' || r == '_' || r == '.' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validNamespace(value string) bool {
	if len(value) > 512 || strings.Contains(value, "//") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if !validToken(strings.ToLower(part), 128) {
			return false
		}
	}
	return true
}
