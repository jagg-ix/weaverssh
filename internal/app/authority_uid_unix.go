//go:build !windows

package app

import (
	"fmt"
	"os"
)

func currentProcessUID() string {
	return fmt.Sprintf("%d", os.Getuid())
}
