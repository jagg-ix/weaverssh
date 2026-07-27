package apicontract

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

func sha256Hex(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

// compareVersion implements deterministic semantic-version-style ordering for
// numeric dot-separated versions while retaining lexical fallback for custom
// version tokens allowed by the catalog format.
func compareVersion(left, right string) int {
	leftCore, leftPre := splitVersion(left)
	rightCore, rightPre := splitVersion(right)
	maximum := len(leftCore)
	if len(rightCore) > maximum {
		maximum = len(rightCore)
	}
	for index := 0; index < maximum; index++ {
		leftPart, rightPart := "0", "0"
		if index < len(leftCore) {
			leftPart = leftCore[index]
		}
		if index < len(rightCore) {
			rightPart = rightCore[index]
		}
		leftNumber, leftNumeric := numericPart(leftPart)
		rightNumber, rightNumeric := numericPart(rightPart)
		switch {
		case leftNumeric && rightNumeric:
			if leftNumber < rightNumber {
				return -1
			}
			if leftNumber > rightNumber {
				return 1
			}
		default:
			if leftPart < rightPart {
				return -1
			}
			if leftPart > rightPart {
				return 1
			}
		}
	}
	if leftPre == rightPre {
		return 0
	}
	if leftPre == "" {
		return 1
	}
	if rightPre == "" {
		return -1
	}
	if leftPre < rightPre {
		return -1
	}
	return 1
}

func splitVersion(value string) ([]string, string) {
	value = strings.TrimSpace(value)
	if build := strings.IndexByte(value, '+'); build >= 0 {
		value = value[:build]
	}
	prerelease := ""
	if separator := strings.IndexByte(value, '-'); separator >= 0 {
		prerelease = value[separator+1:]
		value = value[:separator]
	}
	return strings.Split(value, "."), prerelease
}

func numericPart(value string) (uint64, bool) {
	if value == "" {
		return 0, false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	number, err := strconv.ParseUint(value, 10, 64)
	return number, err == nil
}
