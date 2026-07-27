package socketengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const ConfigVersion = "weaverssh.socket-engine.v1"

const (
	maximumConnections = 1 << 20
	maximumQueueDepth   = 4096
	maximumEventLoops   = 10000
)

// Route maps one local stream listener to one routed TCP destination.
type Route struct {
	Name           string `json:"name"`
	Listen         string `json:"listen"`
	Node           string `json:"node"`
	Network        string `json:"network,omitempty"`
	Address        string `json:"address"`
	MaxConnections int    `json:"max_connections,omitempty"`
}

// Config controls the gnet event-loop engine and its bounded bridge queues.
type Config struct {
	Version          string  `json:"version"`
	Routes           []Route `json:"routes"`
	LoadBalance      string  `json:"load_balance,omitempty"`
	EventLoops       int     `json:"event_loops,omitempty"`
	MaxConnections   int     `json:"max_connections,omitempty"`
	QueueDepth       int     `json:"queue_depth,omitempty"`
	ErrorQueueDepth  int     `json:"error_queue_depth,omitempty"`
	ReadBufferBytes  int     `json:"read_buffer_bytes,omitempty"`
	DialTimeout      string  `json:"dial_timeout,omitempty"`
	IdleTimeout      string  `json:"idle_timeout,omitempty"`
	TCPKeepAlive     string  `json:"tcp_keepalive,omitempty"`
	ReusePort        bool    `json:"reuse_port,omitempty"`
	AllowNonLoopback bool    `json:"allow_non_loopback,omitempty"`
	RemoveStaleUnix  bool    `json:"remove_stale_unix,omitempty"`
	UnixMode         string  `json:"unix_mode,omitempty"`
	ShutdownTimeout  string  `json:"shutdown_timeout,omitempty"`
}

type normalizedConfig struct {
	Config
	routes          []*routeRuntime
	addresses       []string
	dialTimeout     time.Duration
	idleTimeout     time.Duration
	tcpKeepAlive    time.Duration
	shutdownTimeout time.Duration
	unixMode        os.FileMode
}

type routeRuntime struct {
	Route
	address  string
	key      string
	unixPath string
}

func LoadConfig(reader io.Reader) (Config, error) {
	if reader == nil {
		return Config{}, errors.New("socketengine: nil config reader")
	}
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("socketengine: decode config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Config{}, errors.New("socketengine: trailing JSON value")
		}
		return Config{}, fmt.Errorf("socketengine: trailing data: %w", err)
	}
	return config, nil
}

func LoadConfigFile(path string) (Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Config{}, errors.New("socketengine: config path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	return LoadConfig(file)
}

func normalizeConfig(config Config) (normalizedConfig, error) {
	config.Version = strings.TrimSpace(config.Version)
	if config.Version == "" {
		config.Version = ConfigVersion
	}
	if config.Version != ConfigVersion {
		return normalizedConfig{}, fmt.Errorf("socketengine: unsupported config version %q", config.Version)
	}
	if len(config.Routes) == 0 {
		return normalizedConfig{}, errors.New("socketengine: at least one route is required")
	}
	if config.MaxConnections <= 0 {
		config.MaxConnections = 1024
	}
	if config.QueueDepth <= 0 {
		config.QueueDepth = 32
	}
	if config.ErrorQueueDepth <= 0 {
		config.ErrorQueueDepth = 128
	}
	if config.ReadBufferBytes <= 0 {
		config.ReadBufferBytes = 64 << 10
	}
	if config.EventLoops < 0 || config.EventLoops > maximumEventLoops {
		return normalizedConfig{}, fmt.Errorf("socketengine: event_loops must be between 0 and %d", maximumEventLoops)
	}
	if config.MaxConnections < 1 || config.MaxConnections > maximumConnections {
		return normalizedConfig{}, fmt.Errorf("socketengine: max_connections must be between 1 and %d", maximumConnections)
	}
	if config.QueueDepth < 1 || config.QueueDepth > maximumQueueDepth {
		return normalizedConfig{}, fmt.Errorf("socketengine: queue_depth must be between 1 and %d", maximumQueueDepth)
	}
	if config.ErrorQueueDepth < 1 || config.ErrorQueueDepth > maximumQueueDepth {
		return normalizedConfig{}, fmt.Errorf("socketengine: error_queue_depth must be between 1 and %d", maximumQueueDepth)
	}
	if config.ReadBufferBytes < 1024 || config.ReadBufferBytes > 4<<20 {
		return normalizedConfig{}, errors.New("socketengine: read_buffer_bytes must be between 1 KiB and 4 MiB")
	}

	loadBalance := strings.ToLower(strings.TrimSpace(config.LoadBalance))
	if loadBalance == "" {
		loadBalance = "least-connections"
	}
	switch loadBalance {
	case "least-connections", "round-robin", "source-hash":
		config.LoadBalance = loadBalance
	default:
		return normalizedConfig{}, fmt.Errorf("socketengine: unsupported load_balance %q", config.LoadBalance)
	}

	dialTimeout, err := parseDuration(config.DialTimeout, 30*time.Second, "dial_timeout")
	if err != nil {
		return normalizedConfig{}, err
	}
	if dialTimeout <= 0 {
		return normalizedConfig{}, errors.New("socketengine: dial_timeout must be positive")
	}
	idleTimeout, err := parseDuration(config.IdleTimeout, 0, "idle_timeout")
	if err != nil {
		return normalizedConfig{}, err
	}
	tcpKeepAlive, err := parseDuration(config.TCPKeepAlive, 30*time.Second, "tcp_keepalive")
	if err != nil {
		return normalizedConfig{}, err
	}
	shutdownTimeout, err := parseDuration(config.ShutdownTimeout, 10*time.Second, "shutdown_timeout")
	if err != nil {
		return normalizedConfig{}, err
	}
	if shutdownTimeout <= 0 {
		return normalizedConfig{}, errors.New("socketengine: shutdown_timeout must be positive")
	}
	unixMode, err := parseUnixMode(config.UnixMode)
	if err != nil {
		return normalizedConfig{}, err
	}

	seenName := map[string]bool{}
	seenListener := map[string]bool{}
	routes := make([]*routeRuntime, 0, len(config.Routes))
	addresses := make([]string, 0, len(config.Routes))
	for index, raw := range config.Routes {
		route, err := normalizeRoute(raw, config.AllowNonLoopback, config.MaxConnections)
		if err != nil {
			return normalizedConfig{}, fmt.Errorf("socketengine: route %d: %w", index, err)
		}
		if seenName[route.Name] {
			return normalizedConfig{}, fmt.Errorf("socketengine: duplicate route name %q", route.Name)
		}
		if seenListener[route.key] {
			return normalizedConfig{}, fmt.Errorf("socketengine: duplicate listener %q", route.Listen)
		}
		seenName[route.Name] = true
		seenListener[route.key] = true
		routes = append(routes, route)
		addresses = append(addresses, route.address)
	}
	sort.Strings(addresses)
	return normalizedConfig{
		Config:          config,
		routes:          routes,
		addresses:       addresses,
		dialTimeout:     dialTimeout,
		idleTimeout:     idleTimeout,
		tcpKeepAlive:    tcpKeepAlive,
		shutdownTimeout: shutdownTimeout,
		unixMode:        unixMode,
	}, nil
}

func normalizeRoute(route Route, allowNonLoopback bool, globalMax int) (*routeRuntime, error) {
	route.Name = strings.TrimSpace(route.Name)
	route.Listen = strings.TrimSpace(route.Listen)
	route.Node = strings.TrimSpace(route.Node)
	route.Network = strings.ToLower(strings.TrimSpace(route.Network))
	route.Address = strings.TrimSpace(route.Address)
	if route.Name == "" || route.Listen == "" || route.Node == "" || route.Address == "" {
		return nil, errors.New("name, listen, node, and address are required")
	}
	if strings.ContainsAny(route.Name+route.Node, "\x00\r\n") {
		return nil, errors.New("name and node must not contain NUL or line breaks")
	}
	if route.Network == "" {
		route.Network = "tcp"
	}
	if route.Network != "tcp" && route.Network != "tcp4" && route.Network != "tcp6" {
		return nil, fmt.Errorf("unsupported destination network %q", route.Network)
	}
	host, portText, err := net.SplitHostPort(route.Address)
	if err != nil || strings.TrimSpace(host) == "" {
		return nil, fmt.Errorf("destination must be HOST:PORT: %q", route.Address)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("destination port must be between 1 and 65535: %q", portText)
	}
	if strings.ContainsRune(host, '\x00') {
		return nil, errors.New("destination host contains NUL")
	}
	route.Address = net.JoinHostPort(host, strconv.Itoa(port))
	if route.MaxConnections <= 0 {
		route.MaxConnections = globalMax
	}
	if route.MaxConnections > globalMax {
		return nil, fmt.Errorf("max_connections %d exceeds global limit %d", route.MaxConnections, globalMax)
	}

	address, key, unixPath, err := normalizeListener(route.Listen, allowNonLoopback)
	if err != nil {
		return nil, err
	}
	return &routeRuntime{Route: route, address: address, key: key, unixPath: unixPath}, nil
}

func normalizeListener(raw string, allowNonLoopback bool) (address, key, unixPath string, err error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", "", err
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", "", fmt.Errorf("listener must not contain credentials, query, or fragment: %q", raw)
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	switch scheme {
	case "tcp", "tcp4", "tcp6":
		if parsed.Path != "" || parsed.Opaque != "" {
			return "", "", "", fmt.Errorf("TCP listener must not contain a path: %q", raw)
		}
		host, portText, splitErr := net.SplitHostPort(parsed.Host)
		if splitErr != nil {
			return "", "", "", fmt.Errorf("invalid TCP listener %q: %w", raw, splitErr)
		}
		port, convErr := strconv.Atoi(portText)
		if convErr != nil || port < 1 || port > 65535 {
			return "", "", "", fmt.Errorf("listener port must be between 1 and 65535: %q", portText)
		}
		host = strings.Trim(strings.TrimSpace(host), "[]")
		if strings.EqualFold(host, "localhost") {
			if scheme == "tcp6" {
				host = "::1"
			} else {
				host = "127.0.0.1"
			}
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return "", "", "", fmt.Errorf("listener host must be an IP literal or localhost: %q", host)
		}
		if scheme == "tcp4" && ip.To4() == nil {
			return "", "", "", fmt.Errorf("tcp4 listener requires an IPv4 address: %q", host)
		}
		if scheme == "tcp6" && (ip.To16() == nil || ip.To4() != nil) {
			return "", "", "", fmt.Errorf("tcp6 listener requires an IPv6 address: %q", host)
		}
		if !allowNonLoopback && !ip.IsLoopback() {
			return "", "", "", fmt.Errorf("non-loopback listener %s requires allow_non_loopback=true", ip)
		}
		normalized := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		return scheme + "://" + normalized, "tcp://" + normalized, "", nil
	case "unix":
		if parsed.Host != "" || parsed.Opaque != "" {
			return "", "", "", fmt.Errorf("Unix listener must use unix:///absolute/path form: %q", raw)
		}
		path := filepath.Clean(strings.TrimSpace(parsed.Path))
		if !filepath.IsAbs(path) || path == string(os.PathSeparator) {
			return "", "", "", fmt.Errorf("Unix listener must use an absolute socket path: %q", raw)
		}
		return "unix://" + path, "unix://" + path, path, nil
	default:
		return "", "", "", fmt.Errorf("listener scheme must be tcp, tcp4, tcp6, or unix: %q", scheme)
	}
}

func parseDuration(raw string, fallback time.Duration, field string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("socketengine: invalid %s %q", field, raw)
	}
	return value, nil
}

func parseUnixMode(raw string) (os.FileMode, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0o600, nil
	}
	value, err := strconv.ParseUint(raw, 8, 32)
	if err != nil || value > 0o777 {
		return 0, fmt.Errorf("socketengine: invalid unix_mode %q", raw)
	}
	return os.FileMode(value), nil
}
