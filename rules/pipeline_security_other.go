//go:build !unix

package rules

import "os"

func systemPolicyOwnerOK(info os.FileInfo) (bool, bool) {
	return true, false
}
