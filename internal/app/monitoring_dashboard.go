package app

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"runtime"
	"sync/atomic"
	"time"
)

// MonitoringDashboard provides HTTP endpoints for monitoring
type MonitoringDashboard struct {
	server     *InstrumentedX11Server
	httpServer *http.Server
	startTime  time.Time

	// Request counters
	dashboardViews int64
	apiRequests    int64
	healthChecks   int64
}

// NewMonitoringDashboard creates a new monitoring dashboard
func NewMonitoringDashboard(server *InstrumentedX11Server, port int) *MonitoringDashboard {
	dashboard := &MonitoringDashboard{
		server:    server,
		startTime: time.Now(),
	}

	mux := http.NewServeMux()

	// Register routes
	mux.HandleFunc("/", dashboard.handleDashboard)
	mux.HandleFunc("/api/stats", dashboard.handleStats)
	mux.HandleFunc("/api/health", dashboard.handleHealth)
	mux.HandleFunc("/api/connections", dashboard.handleConnections)
	mux.HandleFunc("/api/authorizations", dashboard.handleAuthorizations)
	mux.HandleFunc("/api/metrics", dashboard.handleMetrics)

	dashboard.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	return dashboard
}

// Start starts the monitoring dashboard
func (md *MonitoringDashboard) Start() error {
	log.Printf("Starting monitoring dashboard on %s", md.httpServer.Addr)
	return md.httpServer.ListenAndServe()
}

// Close closes the monitoring dashboard
func (md *MonitoringDashboard) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return md.httpServer.Shutdown(ctx)
}

// handleDashboard serves the main dashboard HTML
func (md *MonitoringDashboard) handleDashboard(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&md.dashboardViews, 1)
	// Read dashboard template from file
	htmlBytes, err := os.ReadFile("dashboard.html")
	if err != nil {
		// Fallback to minimal HTML if file not found
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body><h1>X11 Server Dashboard</h1><p>dashboard.html not found</p></body></html>"))
		log.Printf("Warning: dashboard.html not found: %v", err)
		return
	}

	dashboardHTML := string(htmlBytes)
	tmpl := template.Must(template.New("dashboard").Parse(dashboardHTML))

	data := struct {
		ServerName string
		Uptime     string
		Views      int64
	}{
		ServerName: "X11 Server with SECURITY Extension",
		Uptime:     time.Since(md.startTime).Round(time.Second).String(),
		Views:      atomic.LoadInt64(&md.dashboardViews),
	}

	w.Header().Set("Content-Type", "text/html")
	tmpl.Execute(w, data)
}

// StatsResponse contains server statistics
type StatsResponse struct {
	Uptime         string          `json:"uptime"`
	Connections    ConnectionStats `json:"connections"`
	Authorizations AuthStats       `json:"authorizations"`
	Extensions     ExtensionStats  `json:"extensions"`
	System         SystemStats     `json:"system"`
	Timestamp      time.Time       `json:"timestamp"`
}

// ConnectionStats contains connection statistics
type ConnectionStats struct {
	Total  int64 `json:"total"`
	Active int64 `json:"active"`
	Failed int64 `json:"failed"`
}

// AuthStats contains authorization statistics
type AuthStats struct {
	Generated int64 `json:"generated"`
	Revoked   int64 `json:"revoked"`
	Active    int   `json:"active"`
}

// ExtensionStats contains extension statistics
type ExtensionStats struct {
	Queries   int64    `json:"queries"`
	Supported []string `json:"supported"`
}

// SystemStats contains system statistics
type SystemStats struct {
	Goroutines int    `json:"goroutines"`
	MemoryMB   uint64 `json:"memory_mb"`
	CPUCount   int    `json:"cpu_count"`
}

// handleStats returns JSON statistics
func (md *MonitoringDashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&md.apiRequests, 1)

	stats := md.server.metrics.GetStats()
	auths := md.server.GetAuthorizations()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	response := StatsResponse{
		Uptime: time.Since(md.startTime).Round(time.Second).String(),
		Connections: ConnectionStats{
			Total:  stats["total_connections"],
			Active: stats["active_connections"],
			Failed: stats["failed_auth"],
		},
		Authorizations: AuthStats{
			Generated: stats["generated_auths"],
			Revoked:   stats["revoked_auths"],
			Active:    len(auths),
		},
		Extensions: ExtensionStats{
			Queries:   stats["extension_queries"],
			Supported: []string{"SECURITY"},
		},
		System: SystemStats{
			Goroutines: runtime.NumGoroutine(),
			MemoryMB:   m.Alloc / 1024 / 1024,
			CPUCount:   runtime.NumCPU(),
		},
		Timestamp: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HealthResponse contains health check information
type HealthResponse struct {
	Status    string    `json:"status"`
	Uptime    string    `json:"uptime"`
	Timestamp time.Time `json:"timestamp"`
}

// handleHealth returns health check status
func (md *MonitoringDashboard) handleHealth(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&md.healthChecks, 1)

	response := HealthResponse{
		Status:    "healthy",
		Uptime:    time.Since(md.startTime).Round(time.Second).String(),
		Timestamp: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// ConnectionInfo contains information about a connection
type ConnectionInfo struct {
	Address       string    `json:"address"`
	State         string    `json:"state"`
	Authenticated bool      `json:"authenticated"`
	ConnectedAt   time.Time `json:"connected_at,omitempty"`
}

// handleConnections returns active connections
func (md *MonitoringDashboard) handleConnections(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&md.apiRequests, 1)

	md.server.clientMutex.RLock()
	connections := make([]ConnectionInfo, 0, len(md.server.clients))

	for addr, client := range md.server.clients {
		connections = append(connections, ConnectionInfo{
			Address:       addr,
			State:         string(client.state),
			Authenticated: client.authenticated,
		})
	}
	md.server.clientMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(connections)
}

// AuthorizationInfo contains authorization information
type AuthorizationInfo struct {
	ID         uint32     `json:"id"`
	TrustLevel uint8      `json:"trust_level"`
	Timeout    uint32     `json:"timeout"`
	Group      uint32     `json:"group"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// handleAuthorizations returns active authorizations
func (md *MonitoringDashboard) handleAuthorizations(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&md.apiRequests, 1)

	auths := md.server.GetAuthorizations()
	authInfos := make([]AuthorizationInfo, 0, len(auths))

	for _, auth := range auths {
		info := AuthorizationInfo{
			ID:         auth.ID,
			TrustLevel: auth.TrustLevel,
			Timeout:    auth.Timeout,
			Group:      auth.Group,
			CreatedAt:  auth.CreatedAt,
		}

		if auth.Timeout > 0 {
			expiresAt := auth.CreatedAt.Add(time.Duration(auth.Timeout) * time.Second)
			info.ExpiresAt = &expiresAt
		}

		authInfos = append(authInfos, info)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(authInfos)
}

// MetricsResponse contains Prometheus-style metrics
type MetricsResponse struct {
	Metrics []Metric `json:"metrics"`
}

// Metric represents a single metric
type Metric struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
	Type  string  `json:"type"`
	Help  string  `json:"help"`
}

// handleMetrics returns Prometheus-style metrics
func (md *MonitoringDashboard) handleMetrics(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&md.apiRequests, 1)

	stats := md.server.metrics.GetStats()

	metrics := []Metric{
		{
			Name:  "x11_connections_total",
			Value: float64(stats["total_connections"]),
			Type:  "counter",
			Help:  "Total number of connections",
		},
		{
			Name:  "x11_connections_active",
			Value: float64(stats["active_connections"]),
			Type:  "gauge",
			Help:  "Number of active connections",
		},
		{
			Name:  "x11_auth_failures_total",
			Value: float64(stats["failed_auth"]),
			Type:  "counter",
			Help:  "Total authentication failures",
		},
		{
			Name:  "x11_authorizations_generated_total",
			Value: float64(stats["generated_auths"]),
			Type:  "counter",
			Help:  "Total authorizations generated",
		},
		{
			Name:  "x11_authorizations_revoked_total",
			Value: float64(stats["revoked_auths"]),
			Type:  "counter",
			Help:  "Total authorizations revoked",
		},
		{
			Name:  "x11_extension_queries_total",
			Value: float64(stats["extension_queries"]),
			Type:  "counter",
			Help:  "Total extension queries",
		},
		{
			Name:  "x11_uptime_seconds",
			Value: time.Since(md.startTime).Seconds(),
			Type:  "gauge",
			Help:  "Server uptime in seconds",
		},
	}

	response := MetricsResponse{Metrics: metrics}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
