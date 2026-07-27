package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"weaverssh/authproof"
)

// Config represents the complete server configuration
type Config struct {
	Server     ServerSection     `json:"server"`
	Security   SecuritySection   `json:"security"`
	Extensions ExtensionsSection `json:"extensions"`
	Network    NetworkSection    `json:"network"`
	Logging    LoggingSection    `json:"logging"`
	Monitoring MonitoringSection `json:"monitoring"`
}

// ServerSection contains basic server settings
type ServerSection struct {
	Port           int      `json:"port"`
	DisplayNumber  int      `json:"display_number"`
	BindAddress    string   `json:"bind_address"`
	MaxConnections int      `json:"max_connections"`
	Timeout        Duration `json:"timeout"`
	BufferSize     int      `json:"buffer_size"`
}

// SecuritySection contains security settings
type SecuritySection struct {
	AuthCookie          string   `json:"auth_cookie"`
	AuthCookieFile      string   `json:"auth_cookie_file"`
	AllowNoAuth         bool     `json:"allow_no_auth"`
	AllowedHosts        []string `json:"allowed_hosts"`
	DeniedHosts         []string `json:"denied_hosts"`
	RequireAuth         bool     `json:"require_auth"`
	TrustedByDefault    bool     `json:"trusted_by_default"`
	AuthTimeout         Duration `json:"auth_timeout"`
	MaxAuthAttempts     int      `json:"max_auth_attempts"`
	ProofMode           string   `json:"proof_mode"`
	ProofSecurityLevel  string   `json:"proof_security_level"`
	ProofPeerID         string   `json:"proof_peer_id"`
	ProofIssuerPeerID   string   `json:"proof_issuer_peer_id"`
	ProofPublicKey      string   `json:"proof_public_key"`
	ProofPublicKeyFile  string   `json:"proof_public_key_file"`
	ProofPrivateKey     string   `json:"proof_private_key"`
	ProofPrivateKeyFile string   `json:"proof_private_key_file"`
	ProofSignerProvider string   `json:"proof_signer_provider"`
	ProofIdentity       string   `json:"proof_identity"`
	ProofIdentityFile   string   `json:"proof_identity_file"`
	ProofAgentSocket    string   `json:"proof_agent_socket"`
	ProofChainSHA256    string   `json:"proof_chain_sha256"`
	ProofTTL            Duration `json:"proof_ttl"`
}

// ExtensionsSection contains extension configuration
type ExtensionsSection struct {
	EnableSecurity   bool     `json:"enable_security"`
	EnableWebSocket  bool     `json:"enable_websocket"`
	EnabledList      []string `json:"enabled_list"`
	DisabledList     []string `json:"disabled_list"`
	SecurityTimeout  Duration `json:"security_timeout"`
	WebSocketPath    string   `json:"websocket_path"`
	WebSocketOrigins []string `json:"websocket_origins"`
}

// NetworkSection contains network settings
type NetworkSection struct {
	TCPKeepAlive      bool     `json:"tcp_keepalive"`
	KeepAliveInterval Duration `json:"keepalive_interval"`
	ReadTimeout       Duration `json:"read_timeout"`
	WriteTimeout      Duration `json:"write_timeout"`
	MaxRequestSize    int      `json:"max_request_size"`
	EnableIPv6        bool     `json:"enable_ipv6"`
}

// LoggingSection contains logging configuration
type LoggingSection struct {
	Level      string `json:"level"`
	Format     string `json:"format"`
	Output     string `json:"output"`
	File       string `json:"file"`
	MaxSize    int    `json:"max_size_mb"`
	MaxBackups int    `json:"max_backups"`
	MaxAge     int    `json:"max_age_days"`
	Compress   bool   `json:"compress"`
}

// MonitoringSection contains monitoring settings
type MonitoringSection struct {
	Enabled         bool     `json:"enabled"`
	MetricsInterval Duration `json:"metrics_interval"`
	HealthCheckPort int      `json:"healthcheck_port"`
	PrometheusPort  int      `json:"prometheus_port"`
	EnableProfiling bool     `json:"enable_profiling"`
	ProfilingPort   int      `json:"profiling_port"`
}

// Duration wraps time.Duration for JSON marshaling
type Duration struct {
	time.Duration
}

// MarshalJSON implements json.Marshaler
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON implements json.Unmarshaler
func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}

	switch value := v.(type) {
	case float64:
		d.Duration = time.Duration(value)
		return nil
	case string:
		var err error
		d.Duration, err = time.ParseDuration(value)
		return err
	default:
		return fmt.Errorf("invalid duration: %v", v)
	}
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Server: ServerSection{
			Port:           6000,
			DisplayNumber:  0,
			BindAddress:    "0.0.0.0",
			MaxConnections: 100,
			Timeout:        Duration{5 * time.Minute},
			BufferSize:     4096,
		},
		Security: SecuritySection{
			AuthCookie:         "",
			AuthCookieFile:     "",
			AllowNoAuth:        false,
			AllowedHosts:       []string{"127.0.0.1", "::1"},
			DeniedHosts:        []string{},
			RequireAuth:        true,
			TrustedByDefault:   false,
			AuthTimeout:        Duration{1 * time.Hour},
			MaxAuthAttempts:    3,
			ProofMode:          authproof.ProofModeOff,
			ProofSecurityLevel: authproof.SecurityLevelCompat,
			ProofPeerID:        "wv-agent",
			ProofTTL:           Duration{authproof.DefaultProofTTL},
		},
		Extensions: ExtensionsSection{
			EnableSecurity:   true,
			EnableWebSocket:  false,
			EnabledList:      []string{"SECURITY"},
			DisabledList:     []string{},
			SecurityTimeout:  Duration{1 * time.Hour},
			WebSocketPath:    "/ws",
			WebSocketOrigins: []string{"*"},
		},
		Network: NetworkSection{
			TCPKeepAlive:      true,
			KeepAliveInterval: Duration{30 * time.Second},
			ReadTimeout:       Duration{30 * time.Second},
			WriteTimeout:      Duration{30 * time.Second},
			MaxRequestSize:    1024 * 1024, // 1MB
			EnableIPv6:        true,
		},
		Logging: LoggingSection{
			Level:      "info",
			Format:     "text",
			Output:     "stdout",
			File:       "/var/log/x11server.log",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     7,
			Compress:   true,
		},
		Monitoring: MonitoringSection{
			Enabled:         false,
			MetricsInterval: Duration{30 * time.Second},
			HealthCheckPort: 8080,
			PrometheusPort:  9090,
			EnableProfiling: false,
			ProfilingPort:   6060,
		},
	}
}

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	config := DefaultConfig()

	// Determine format by extension
	ext := filepath.Ext(path)
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("parsing JSON config: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config format: %s", ext)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return config, nil
}

// SaveConfig saves configuration to a file
func (c *Config) SaveConfig(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating config file: %w", err)
	}
	defer file.Close()

	ext := filepath.Ext(path)
	switch ext {
	case ".json":
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(c); err != nil {
			return fmt.Errorf("encoding JSON config: %w", err)
		}
	default:
		return fmt.Errorf("unsupported config format: %s", ext)
	}

	return nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate server section
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Server.Port)
	}

	if c.Server.MaxConnections < 1 {
		return fmt.Errorf("max_connections must be positive")
	}

	// Validate security section
	if c.Security.RequireAuth && c.Security.AuthCookie == "" && c.Security.AuthCookieFile == "" {
		return fmt.Errorf("auth_cookie or auth_cookie_file required when require_auth is true")
	}

	proofConfig := authproof.RuntimeConfig{
		Mode:           c.Security.ProofMode,
		SecurityLevel:  c.Security.ProofSecurityLevel,
		IssuerPeerID:   c.Security.ProofIssuerPeerID,
		SubjectPeerID:  c.Security.ProofPeerID,
		Audience:       authproof.AudienceAgent,
		PublicKey:      c.Security.ProofPublicKey,
		PublicKeyFile:  c.Security.ProofPublicKeyFile,
		PrivateKey:     c.Security.ProofPrivateKey,
		PrivateKeyFile: c.Security.ProofPrivateKeyFile,
		SignerProvider: c.Security.ProofSignerProvider,
		Identity:       c.Security.ProofIdentity,
		IdentityFile:   c.Security.ProofIdentityFile,
		AgentSocket:    c.Security.ProofAgentSocket,
		ChainSHA256:    c.Security.ProofChainSHA256,
		TTL:            c.Security.ProofTTL.Duration,
	}
	if err := proofConfig.ValidateMode(); err != nil {
		return err
	}
	if proofConfig.Required() {
		if c.Security.ProofChainSHA256 == "" {
			return fmt.Errorf("proof_chain_sha256 is required when proof mode or proof security level requires signed proof")
		}
		if c.Security.ProofPublicKey == "" && c.Security.ProofPublicKeyFile == "" && c.Security.ProofPrivateKey == "" && c.Security.ProofPrivateKeyFile == "" && c.Security.ProofSignerProvider == "" && c.Security.ProofAgentSocket == "" {
			return fmt.Errorf("proof key material or signer provider is required when proof mode or proof security level requires signed proof")
		}
	}

	// Validate logging section
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.Logging.Level] {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	return nil
}

// LoadAuthCookie loads auth cookie from file if specified
func (c *Config) LoadAuthCookie() error {
	if c.Security.AuthCookieFile != "" {
		data, err := os.ReadFile(c.Security.AuthCookieFile)
		if err != nil {
			return fmt.Errorf("reading auth cookie file: %w", err)
		}
		c.Security.AuthCookie = string(data)
	}
	return nil
}

// ToServerConfig converts to ServerConfig
func (c *Config) ToServerConfig() ServerConfig {
	return ServerConfig{
		Port:               c.Server.Port,
		AuthCookie:         c.Security.AuthCookie,
		EnableWebSocket:    c.Extensions.EnableWebSocket,
		LogLevel:           c.Logging.Level,
		MaxConnections:     c.Server.MaxConnections,
		ConnectionTimeout:  c.Server.Timeout.Duration,
		AuthTimeout:        c.Security.AuthTimeout.Duration,
		EnableMetrics:      c.Monitoring.Enabled,
		ProofMode:          c.Security.ProofMode,
		ProofSecurityLevel: c.Security.ProofSecurityLevel,
		ProofPeerID:        c.Security.ProofPeerID,
		ProofIssuerPeerID:  c.Security.ProofIssuerPeerID,
		ProofPublicKey:     c.Security.ProofPublicKey,
		ProofPublicKeyFile: c.Security.ProofPublicKeyFile,
		ProofChainSHA256:   c.Security.ProofChainSHA256,
		ProofTTL:           c.Security.ProofTTL.Duration,
	}
}

// ConfigManager manages configuration loading and reloading
type ConfigManager struct {
	config     *Config
	configPath string
	watchers   []func(*Config)
	mu         sync.RWMutex
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(path string) (*ConfigManager, error) {
	config, err := LoadConfig(path)
	if err != nil {
		return nil, err
	}

	return &ConfigManager{
		config:     config,
		configPath: path,
		watchers:   make([]func(*Config), 0),
	}, nil
}

// GetConfig returns the current configuration
func (cm *ConfigManager) GetConfig() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config
}

// Reload reloads the configuration from file
func (cm *ConfigManager) Reload() error {
	config, err := LoadConfig(cm.configPath)
	if err != nil {
		return err
	}

	cm.mu.Lock()
	oldConfig := cm.config
	cm.config = config
	watchers := cm.watchers
	cm.mu.Unlock()

	// Notify watchers
	for _, watcher := range watchers {
		go watcher(oldConfig)
	}

	return nil
}

// Watch registers a function to be called when config changes
func (cm *ConfigManager) Watch(fn func(*Config)) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.watchers = append(cm.watchers, fn)
}

// GenerateExampleConfig generates an example configuration file
func GenerateExampleConfig(path string) error {
	config := DefaultConfig()

	// Add comments (would need custom marshaling for proper comments)
	return config.SaveConfig(path)
}

// Example usage
func ExampleConfigUsage() {
	// Create default config
	config := DefaultConfig()

	// Modify settings
	config.Server.Port = 6001
	config.Security.AuthCookie = "your-cookie-here"
	config.Extensions.EnableWebSocket = true
	config.Monitoring.Enabled = true

	// Save to file
	if err := config.SaveConfig("config.json"); err != nil {
		fmt.Printf("Error saving config: %v\n", err)
		return
	}

	// Load from file
	loadedConfig, err := LoadConfig("config.json")
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		return
	}

	fmt.Printf("Loaded config: Port=%d, WebSocket=%v\n",
		loadedConfig.Server.Port,
		loadedConfig.Extensions.EnableWebSocket)
}
