package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"weaverssh/fabricbridge"
)

type stringList []string
func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error { *s = append(*s, value); return nil }

func main() {
	listen := flag.String("listen", envOr("WEAVERSSH_FABRIC_BRIDGE_LISTEN", "127.0.0.1:8097"), "HTTP listen address")
	token := flag.String("token", os.Getenv("WEAVERSSH_FABRIC_BRIDGE_TOKEN"), "bearer token; empty disables HTTP authentication")
	peerBinary := flag.String("peer", envOr("WEAVERSSH_FABRIC_PEER", "peer"), "Fabric peer CLI executable")
	orderer := flag.String("orderer", os.Getenv("WEAVERSSH_FABRIC_ORDERER"), "orderer endpoint")
	ordererCA := flag.String("orderer-ca", os.Getenv("WEAVERSSH_FABRIC_ORDERER_CA"), "orderer TLS CA file")
	queryFunction := flag.String("query-function", envOr("WEAVERSSH_FABRIC_QUERY_FUNCTION", "ReadEvidenceAnchor"), "chaincode function used after commit to read the retained anchor")
	wait := flag.Duration("wait-for-event", 30*time.Second, "commit event timeout")
	commandTimeout := flag.Duration("command-timeout", 90*time.Second, "peer command timeout")
	var peerAddresses stringList
	var peerRoots stringList
	flag.Var(&peerAddresses, "peer-address", "endorsing/query peer address; repeatable")
	flag.Var(&peerRoots, "peer-tls-root", "peer TLS root certificate; repeatable")
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	server := fabricbridge.Server{Config: fabricbridge.Config{
		Token: *token, PeerBinary: *peerBinary, Orderer: *orderer, OrdererCA: *ordererCA,
		PeerAddresses: peerAddresses, PeerTLSRoots: peerRoots, QueryFunction: *queryFunction,
		WaitForEvent: *wait, CommandTimeout: *commandTimeout,
	}}
	httpServer := &http.Server{
		Addr: *listen, Handler: server.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 2 * time.Minute, IdleTimeout: 60 * time.Second,
	}
	fmt.Fprintf(os.Stderr, "wv-fabric-anchor-bridge listening on %s\n", *listen)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" { return value }
	return fallback
}
