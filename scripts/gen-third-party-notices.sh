#!/bin/sh
# Generate third-party attribution dynamically — nothing is vendored. go-licenses
# is fetched on demand via `go run` and reports the modules linked into wv.
# Output lines are: import-path, license-url, license-type.
set -e
{
	echo "# Third-Party Notices"
	echo
	echo "weaverssh links the following Go modules, fetched dynamically at build time."
	echo "Each line lists the import path, license URL, and license type."
	echo
	go run github.com/google/go-licenses@v1.6.0 report ./cmd/wv 2>/dev/null \
		|| echo "(license report unavailable in this build environment)"
} > THIRD_PARTY_NOTICES.md
