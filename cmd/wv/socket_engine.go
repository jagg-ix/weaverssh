package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"

	"weaverssh/sessionbroker"
	"weaverssh/sessiontcp"
	"weaverssh/socketengine"
)

type socketEngineErrorEvent struct {
	Route  socketengine.Route
	Remote string
	Err    error
}

func cmdSocketEngine(args []string) int {
	if len(args) > 0 && args[0] == "validate" {
		return cmdSocketEngineValidate(args[1:])
	}
	if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		printSocketEngineUsage()
		return 0
	}
	return cmdSocketEngineRun(args)
}

func cmdSocketEngineValidate(args []string) int {
	fs := flag.NewFlagSet("socket-engine validate", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit normalized JSON plan")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: wv socket-engine validate [--json] CONFIG.json")
		return 2
	}
	config, err := socketengine.LoadConfigFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socket-engine validate: %v\n", err)
		return 1
	}
	plan, err := socketengine.Inspect(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socket-engine validate: %v\n", err)
		return 1
	}
	if *jsonOut {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(plan); err != nil {
			fmt.Fprintf(os.Stderr, "wv socket-engine validate: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Printf("valid socket engine config\nlisteners: %d\nload_balance: %s\nmax_connections: %d\n", len(plan.Addresses), plan.LoadBalance, plan.MaxConnections)
	for _, route := range plan.Routes {
		fmt.Printf("- %s %s -> %s %s/%s max=%d\n", route.Name, route.Listen, route.Node, route.Network, route.Address, route.MaxConnections)
	}
	return 0
}

func cmdSocketEngineRun(args []string) int {
	fs := flag.NewFlagSet("socket-engine", flag.ContinueOnError)
	configPath := fs.String("config", "", "socket engine JSON configuration")
	jsonOut := fs.Bool("json", false, "emit startup and periodic statistics as JSON")
	statsInterval := fs.Duration("stats-interval", 0, "periodically emit engine statistics; zero disables")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv socket-engine --config CONFIG.json [--stats-interval 30s]")
		fmt.Fprintln(os.Stderr, "       wv socket-engine validate CONFIG.json")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(*configPath) == "" {
		fs.Usage()
		return 2
	}
	config, err := socketengine.LoadConfigFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socket-engine: load config: %v\n", err)
		return 1
	}
	plan, err := socketengine.Inspect(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socket-engine: config: %v\n", err)
		return 1
	}
	state, err := sessionbroker.ActiveState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socket-engine: active session: %v\n", err)
		return 1
	}
	baseline := state
	dial := func(ctx context.Context, route socketengine.Route) (net.Conn, error) {
		current, err := sessionbroker.ActiveState()
		if err != nil {
			return nil, err
		}
		if current.Binding != baseline.Binding || current.Socket != baseline.Socket || current.Node != baseline.Node {
			return nil, fmt.Errorf("active session changed from binding %s to %s", baseline.Binding, current.Binding)
		}
		return sessiontcp.DialBroker(ctx, baseline.Socket, route.Node, route.Network, route.Address)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	errorDepth := config.ErrorQueueDepth
	if errorDepth <= 0 {
		errorDepth = 128
	}
	errorEvents := make(chan socketEngineErrorEvent, errorDepth)
	var droppedErrors atomic.Uint64
	go consumeSocketEngineErrors(ctx, errorEvents, *jsonOut)

	engine, err := socketengine.New(config, dial, func(route socketengine.Route, remote string, err error) {
		select {
		case errorEvents <- socketEngineErrorEvent{Route: route, Remote: remote, Err: err}:
		default:
			droppedErrors.Add(1)
		}
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socket-engine: %v\n", err)
		return 1
	}

	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"event":         "starting",
			"binding":       baseline.Binding,
			"broker_socket":  baseline.Socket,
			"local_node":     baseline.Node,
			"engine":         "gnet",
			"engine_version": socketengine.DependencyVersion,
			"configuration":  plan,
		})
	} else {
		fmt.Printf("socket engine: gnet %s\nbinding: %s\nbroker: unix:%s\nlocal node: %s\n", socketengine.DependencyVersion, baseline.Binding, baseline.Socket, baseline.Node)
		for _, route := range plan.Routes {
			fmt.Printf("listen %s -> node=%s target=%s/%s max=%d\n", route.Listen, route.Node, route.Network, route.Address, route.MaxConnections)
		}
	}

	if *statsInterval > 0 {
		go emitSocketEngineStats(ctx, engine, &droppedErrors, *statsInterval, *jsonOut)
	}
	if err := engine.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "wv socket-engine: %v\n", err)
		return 1
	}
	return 0
}

func consumeSocketEngineErrors(ctx context.Context, events <-chan socketEngineErrorEvent, jsonOut bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-events:
			if jsonOut {
				_ = json.NewEncoder(os.Stderr).Encode(map[string]any{
					"event":  "route_error",
					"route":  event.Route.Name,
					"remote": event.Remote,
					"error":  event.Err.Error(),
				})
			} else {
				fmt.Fprintf(os.Stderr, "socket-engine route=%s remote=%s: %v\n", event.Route.Name, event.Remote, event.Err)
			}
		}
	}
}

func emitSocketEngineStats(ctx context.Context, engine *socketengine.Engine, droppedErrors *atomic.Uint64, interval time.Duration, jsonOut bool) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := engine.Snapshot()
			dropped := droppedErrors.Load()
			if jsonOut {
				_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"event": "stats", "stats": stats, "dropped_error_events": dropped})
			} else {
				fmt.Printf("socket-engine active=%d accepted=%d rejected=%d dial_failures=%d queue_drops=%d dropped_error_events=%d bytes_in=%d bytes_out=%d\n",
					stats.Active, stats.Accepted, stats.Rejected, stats.DialFailures, stats.QueueDrops, dropped, stats.BytesIn, stats.BytesOut)
			}
		}
	}
}

func printSocketEngineUsage() {
	fmt.Print(`usage: wv socket-engine --config CONFIG.json [options]
       wv socket-engine validate [--json] CONFIG.json

The engine binds multiple TCP/Unix stream listeners with gnet and opens one
independent routed ServiceTCP backend for every accepted local connection.
`)
}
