//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func watchTerminalResize(events chan<- struct{}) func() {
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(signals, syscall.SIGWINCH)
	go func() {
		for {
			select {
			case <-signals:
				select {
				case events <- struct{}{}:
				default:
				}
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(signals)
		close(done)
	}
}
