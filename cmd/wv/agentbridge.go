package main

// wv agent-bridge lets a local (e.g. WSL2) ssh-agent use keys held by another
// ssh-agent, over the standard agent protocol. The upstream may be a normal
// ssh-agent socket, the Windows OpenSSH agent named pipe, PuTTY Pageant (just a
// different ssh-agent implementation), or a helper process. One wv binary is
// both ends, so no socat or extra helper is needed:
//
//	# forward to the local standard agent
//	wv agent-bridge --listen ~/.ssh/agent.sock --upstream unix:$SSH_AUTH_SOCK
//
//	# WSL2 -> a Windows agent (OpenSSH by default, or add --upstream pageant on the far side)
//	wv agent-bridge --listen ~/.ssh/agent.sock --upstream 'exec:wv.exe agent-bridge --stdio'
//	export SSH_AUTH_SOCK=~/.ssh/agent.sock

import (
	"flag"
	"fmt"
	"log"
	"os"

	"weaverssh/agentbridge"
)

func cmdAgentBridge(args []string) int {
	fs := flag.NewFlagSet("agent-bridge", flag.ContinueOnError)
	listen := fs.String("listen", "", "UNIX socket to serve (point $SSH_AUTH_SOCK at it)")
	stdio := fs.Bool("stdio", false, "forward stdin/stdout to the upstream (used by exec: on the far side)")
	upstreamFlag := fs.String("upstream", "", "upstream agent: unix:PATH | pipe:NAME | pageant | exec:CMD (default: platform standard agent)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv agent-bridge (--listen SOCK | --stdio) [--upstream TARGET]")
		fmt.Fprintln(os.Stderr, "  Forward the ssh-agent protocol to a standard ssh-agent (unix:PATH, or on Windows")
		fmt.Fprintln(os.Stderr, "  the OpenSSH agent pipe:), to PuTTY Pageant (pageant), or to a helper (exec:CMD).")
		fmt.Fprintln(os.Stderr, "  Default upstream: the OpenSSH agent pipe on Windows, else $SSH_AUTH_SOCK.")
		fmt.Fprintln(os.Stderr, "  WSL2 -> Windows agent:")
		fmt.Fprintln(os.Stderr, "    wv agent-bridge --listen ~/.ssh/agent.sock --upstream 'exec:wv.exe agent-bridge --stdio'")
		fmt.Fprintln(os.Stderr, "    export SSH_AUTH_SOCK=~/.ssh/agent.sock")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	if (*listen != "") == *stdio { // need exactly one of --listen / --stdio
		fmt.Fprintln(os.Stderr, "agent-bridge: specify exactly one of --listen or --stdio")
		fs.Usage()
		return 2
	}

	up, err := agentbridge.Resolve(*upstreamFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	if *stdio {
		if err := agentbridge.Stdio(up); err != nil {
			fmt.Fprintf(os.Stderr, "agent-bridge: %v\n", err)
			return 1
		}
		return 0
	}

	logf := func(format string, a ...any) { log.Printf(format, a...) }
	if err := agentbridge.Serve(*listen, up, logf); err != nil {
		fmt.Fprintf(os.Stderr, "agent-bridge: %v\n", err)
		return 1
	}
	return 0
}
