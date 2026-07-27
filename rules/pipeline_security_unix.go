//go:build unix

package rules

import (
	"os"
	"syscall"
)

func systemPolicyOwnerOK(info os.FileInfo) (bool, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, false
	}
	return st.Uid == 0, true
}
