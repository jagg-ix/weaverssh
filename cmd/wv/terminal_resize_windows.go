//go:build windows

package main

func watchTerminalResize(chan<- struct{}) func() { return func() {} }
