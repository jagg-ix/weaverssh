package wverrors

import (
	"errors"
	"fmt"
)

type Code string

type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
	SeverityFatal   Severity = "fatal"
)

type Kind string

const (
	KindError     Kind = "error"
	KindFault     Kind = "fault"
	KindException Kind = "exception"
)

const (
	CodeAdapterDataPlaneOwner         Code = "WV-ADP-001"
	CodeAuthproofMissingOrInvalid     Code = "WV-AUT-001"
	CodeAuthorityRemoteRootDomain     Code = "WV-AUT-002"
	CodeNoActiveConnectionProfile     Code = "WV-CFG-001"
	CodeCapabilityVersionMismatch     Code = "WV-CFG-002"
	CodeRequiredDependencyMissing     Code = "WV-DEP-001"
	CodePackageManagerOperationDenied Code = "WV-DEP-002"
	CodeFuseUnavailable               Code = "WV-FUS-001"
	CodeMCPListenerDown               Code = "WV-MCP-001"
	CodeArtifactSignatureMismatch     Code = "WV-PKG-001"
	CodeHomebrewFormulaInvalid        Code = "WV-PKG-002"
	CodeSnapcraftUnavailable          Code = "WV-PKG-003"
	CodeRelayPumpTerminatedEarly      Code = "WV-RLY-001"
	CodeUnsafeNonLoopbackBindRejected Code = "WV-RLY-002"
	CodeSocketBridgeCommandRejected   Code = "WV-SOC-001"
	CodeSSHLoginFailed                Code = "WV-SSH-001"
	CodeAgentForwardingUnavailable    Code = "WV-SSH-002"
	CodeValidationGateMissing         Code = "WV-VAL-001"
	CodeVFSEndpointUnavailable        Code = "WV-VFS-001"
	CodeWebSocketSecondPhaseRejected  Code = "WV-WSS-001"
	CodeDisplayCouldNotBeResolved     Code = "WV-X11-001"
	CodeXAuthorityCookieMismatch      Code = "WV-X11-002"
	CodeX11SetupFailedClosed          Code = "WV-X11-003"
)

// Definition is the stable component-facing metadata for a weaverssh error code.
type Definition struct {
	Code      Code     `json:"code"`
	Subsystem string   `json:"subsystem"`
	Severity  Severity `json:"severity"`
	Kind      Kind     `json:"kind"`
	Title     string   `json:"title"`
	Retryable bool     `json:"retryable"`
}

var Registry = map[Code]Definition{
	CodeAdapterDataPlaneOwner:         {CodeAdapterDataPlaneOwner, "adapter", SeverityFatal, KindFault, "External adapter attempted to own data plane", false},
	CodeAuthproofMissingOrInvalid:     {CodeAuthproofMissingOrInvalid, "authproof", SeverityFatal, KindFault, "Authproof missing or invalid", false},
	CodeAuthorityRemoteRootDomain:     {CodeAuthorityRemoteRootDomain, "authproof", SeverityFatal, KindFault, "Authority material is in remote-root domain", false},
	CodeNoActiveConnectionProfile:     {CodeNoActiveConnectionProfile, "configuration", SeverityError, KindError, "No active connection profile", true},
	CodeCapabilityVersionMismatch:     {CodeCapabilityVersionMismatch, "configuration", SeverityWarning, KindError, "Connection capability version mismatch", true},
	CodeRequiredDependencyMissing:     {CodeRequiredDependencyMissing, "dependencies", SeverityError, KindError, "Required dependency is missing", true},
	CodePackageManagerOperationDenied: {CodePackageManagerOperationDenied, "dependencies", SeverityWarning, KindError, "Package-manager operation denied", true},
	CodeFuseUnavailable:               {CodeFuseUnavailable, "vfs", SeverityWarning, KindError, "FUSE or macFUSE unavailable", true},
	CodeMCPListenerDown:               {CodeMCPListenerDown, "mcp", SeverityError, KindError, "MCP listener down", true},
	CodeArtifactSignatureMismatch:     {CodeArtifactSignatureMismatch, "packaging", SeverityFatal, KindFault, "Artifact checksum or signature mismatch", false},
	CodeHomebrewFormulaInvalid:        {CodeHomebrewFormulaInvalid, "packaging", SeverityError, KindError, "Homebrew Formula archive invalid", false},
	CodeSnapcraftUnavailable:          {CodeSnapcraftUnavailable, "packaging", SeverityWarning, KindError, "Snapcraft unavailable for package build", true},
	CodeRelayPumpTerminatedEarly:      {CodeRelayPumpTerminatedEarly, "relay", SeverityError, KindError, "Relay pump terminated early", true},
	CodeUnsafeNonLoopbackBindRejected: {CodeUnsafeNonLoopbackBindRejected, "relay", SeverityError, KindError, "Unsafe non-loopback bind rejected", false},
	CodeSocketBridgeCommandRejected:   {CodeSocketBridgeCommandRejected, "adapter", SeverityError, KindError, "Socket bridge command rejected", false},
	CodeSSHLoginFailed:                {CodeSSHLoginFailed, "ssh", SeverityError, KindError, "SSH login failed", true},
	CodeAgentForwardingUnavailable:    {CodeAgentForwardingUnavailable, "ssh", SeverityWarning, KindError, "Agent forwarding unavailable", true},
	CodeValidationGateMissing:         {CodeValidationGateMissing, "validation", SeverityWarning, KindError, "Destructive validation gate missing", false},
	CodeVFSEndpointUnavailable:        {CodeVFSEndpointUnavailable, "vfs", SeverityError, KindError, "9P VFS endpoint unavailable", true},
	CodeWebSocketSecondPhaseRejected:  {CodeWebSocketSecondPhaseRejected, "websocket", SeverityError, KindError, "WebSocket second phase rejected", false},
	CodeDisplayCouldNotBeResolved:     {CodeDisplayCouldNotBeResolved, "x11", SeverityError, KindError, "DISPLAY could not be resolved", true},
	CodeXAuthorityCookieMismatch:      {CodeXAuthorityCookieMismatch, "x11", SeverityError, KindError, "XAUTHORITY cookie missing or mismatched", false},
	CodeX11SetupFailedClosed:          {CodeX11SetupFailedClosed, "x11", SeverityFatal, KindFault, "X11 setup failed closed", false},
}

// Error is the common component error envelope for Go runtime code.
type Error struct {
	Code      Code              `json:"code"`
	Component string            `json:"component"`
	Operation string            `json:"operation"`
	Message   string            `json:"message"`
	Severity  Severity          `json:"severity"`
	Kind      Kind              `json:"kind"`
	Retryable bool              `json:"retryable"`
	Fault     bool              `json:"fault"`
	Fields    map[string]string `json:"fields,omitempty"`
	Cause     error             `json:"-"`
}

func New(code Code, component, operation, message string) *Error {
	return Wrap(code, component, operation, message, nil)
}

func Wrap(code Code, component, operation, message string, cause error) *Error {
	definition, ok := Registry[code]
	severity := SeverityError
	kind := KindError
	retryable := false
	if ok {
		severity = definition.Severity
		kind = definition.Kind
		retryable = definition.Retryable
	}
	return &Error{
		Code:      code,
		Component: component,
		Operation: operation,
		Message:   message,
		Severity:  severity,
		Kind:      kind,
		Retryable: retryable,
		Fault:     kind == KindFault,
		Cause:     cause,
	}
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	scope := e.Component
	if scope == "" {
		scope = "weaverssh"
	}
	if e.Operation != "" {
		scope = scope + "." + e.Operation
	}
	message := e.Message
	if message == "" {
		message = "weaverssh component error"
	}
	out := fmt.Sprintf("[%s] %s: %s", e.Code, scope, message)
	if e.Cause != nil {
		out += ": " + e.Cause.Error()
	}
	return out
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *Error) WithField(key, value string) *Error {
	if e == nil {
		return nil
	}
	if e.Fields == nil {
		e.Fields = map[string]string{}
	}
	e.Fields[key] = value
	return e
}

func (e *Error) WithSeverity(severity Severity) *Error {
	if e == nil {
		return nil
	}
	e.Severity = severity
	return e
}

func (e *Error) AsFault() *Error {
	if e == nil {
		return nil
	}
	e.Kind = KindFault
	e.Fault = true
	return e
}

func (e *Error) AsException() *Error {
	if e == nil {
		return nil
	}
	e.Kind = KindException
	e.Fault = false
	return e
}

func KnownCode(code Code) bool {
	_, ok := Registry[code]
	return ok
}

func DefinitionOf(code Code) (Definition, bool) {
	definition, ok := Registry[code]
	return definition, ok
}

func CodeOf(err error) (Code, bool) {
	var weaverErr *Error
	if errors.As(err, &weaverErr) && weaverErr != nil {
		return weaverErr.Code, true
	}
	return "", false
}

func IsCode(err error, code Code) bool {
	actual, ok := CodeOf(err)
	return ok && actual == code
}

func Event(err error) map[string]any {
	var weaverErr *Error
	if !errors.As(err, &weaverErr) || weaverErr == nil {
		return map[string]any{
			"kind":    string(KindException),
			"message": errString(err),
		}
	}
	event := map[string]any{
		"code":      string(weaverErr.Code),
		"component": weaverErr.Component,
		"operation": weaverErr.Operation,
		"message":   weaverErr.Message,
		"severity":  string(weaverErr.Severity),
		"kind":      string(weaverErr.Kind),
		"retryable": weaverErr.Retryable,
		"fault":     weaverErr.Fault,
	}
	if definition, ok := Registry[weaverErr.Code]; ok {
		event["title"] = definition.Title
		event["subsystem"] = definition.Subsystem
	}
	if len(weaverErr.Fields) > 0 {
		event["fields"] = weaverErr.Fields
	}
	if weaverErr.Cause != nil {
		event["cause"] = weaverErr.Cause.Error()
	}
	return event
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
