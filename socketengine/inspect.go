package socketengine

// Plan is the normalized, non-secret configuration summary shown by tooling.
type Plan struct {
	Version          string      `json:"version"`
	LoadBalance      string      `json:"load_balance"`
	EventLoops       int         `json:"event_loops"`
	MaxConnections   int         `json:"max_connections"`
	QueueDepth       int         `json:"queue_depth"`
	ErrorQueueDepth  int         `json:"error_queue_depth"`
	ReadBufferBytes  int         `json:"read_buffer_bytes"`
	DialTimeout      string      `json:"dial_timeout"`
	IdleTimeout      string      `json:"idle_timeout"`
	TCPKeepAlive     string      `json:"tcp_keepalive"`
	ShutdownTimeout  string      `json:"shutdown_timeout"`
	ReusePort        bool        `json:"reuse_port"`
	AllowNonLoopback bool        `json:"allow_non_loopback"`
	RemoveStaleUnix  bool        `json:"remove_stale_unix"`
	UnixMode         string      `json:"unix_mode"`
	Addresses        []string    `json:"addresses"`
	Routes           []RoutePlan `json:"routes"`
}

// RoutePlan is one normalized listener-to-target mapping.
type RoutePlan struct {
	Name           string `json:"name"`
	Listen         string `json:"listen"`
	Node           string `json:"node"`
	Network        string `json:"network"`
	Address        string `json:"address"`
	MaxConnections int    `json:"max_connections"`
}

func Inspect(config Config) (Plan, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{
		Version:          normalized.Version,
		LoadBalance:      normalized.LoadBalance,
		EventLoops:       normalized.EventLoops,
		MaxConnections:   normalized.MaxConnections,
		QueueDepth:       normalized.QueueDepth,
		ErrorQueueDepth:  normalized.ErrorQueueDepth,
		ReadBufferBytes:  normalized.ReadBufferBytes,
		DialTimeout:      normalized.dialTimeout.String(),
		IdleTimeout:      normalized.idleTimeout.String(),
		TCPKeepAlive:     normalized.tcpKeepAlive.String(),
		ShutdownTimeout:  normalized.shutdownTimeout.String(),
		ReusePort:        normalized.ReusePort,
		AllowNonLoopback: normalized.AllowNonLoopback,
		RemoveStaleUnix:  normalized.RemoveStaleUnix,
		UnixMode:         formatUnixMode(uint32(normalized.unixMode.Perm())),
		Addresses:        append([]string(nil), normalized.addresses...),
	}
	for _, route := range normalized.routes {
		plan.Routes = append(plan.Routes, RoutePlan{
			Name:           route.Name,
			Listen:         route.address,
			Node:           route.Node,
			Network:        route.Network,
			Address:        route.Address,
			MaxConnections: route.MaxConnections,
		})
	}
	return plan, nil
}

func formatUnixMode(mode uint32) string {
	const digits = "01234567"
	buffer := []byte{'0', '0', '0', '0'}
	for index := len(buffer) - 1; index >= 0; index-- {
		buffer[index] = digits[mode&7]
		mode >>= 3
	}
	return string(buffer)
}
