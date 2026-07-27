package originruntime

const (
	// EnvConfig points to the trusted origin runtime configuration on the origin host.
	EnvConfig = "WEAVERSSH_ORIGIN_RUNTIME_CONFIG"
	// EnvKind identifies the runtime class without changing WVORIGIN node identity.
	EnvKind = "WVORIGIN_RUNTIME"
	// EnvID identifies the resolved runtime instance using a bounded deterministic token.
	EnvID = "WVORIGIN_RUNTIME_ID"
)
