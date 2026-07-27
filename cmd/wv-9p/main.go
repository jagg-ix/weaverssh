package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"weaverssh/internal/p9svc"
)

func main() {
	root := flag.String("root", ".", "Root directory to expose over 9P")
	listen := flag.String("listen", "127.0.0.1:5640", "TCP listen address")
	readWrite := flag.Bool("read-write", false, "Allow create/write/remove (default: read-only)")
	jsonStatus := flag.Bool("json", false, "Print startup status as JSON")
	flag.Parse()

	readOnly := !*readWrite
	logger := log.New(os.Stderr, "wv-9p ", log.LstdFlags)
	srv, err := p9svc.New(p9svc.Config{Root: *root, Addr: *listen, ReadOnly: readOnly, Logger: logger})
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv-9p config error: %v\n", err)
		os.Exit(2)
	}
	if *jsonStatus {
		fmt.Printf("{\"ok\":true,\"service\":\"wv-9p\",\"listen\":%q,\"root\":%q,\"read_only\":%t}\n", *listen, *root, readOnly)
	} else {
		mode := "read-only"
		if !readOnly {
			mode = "read-write"
		}
		logger.Printf("serving %s 9P root=%s listen=%s", mode, *root, *listen)
	}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "wv-9p serve error: %v\n", err)
		os.Exit(1)
	}
}
