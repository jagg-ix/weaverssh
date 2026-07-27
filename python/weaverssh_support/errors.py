from __future__ import annotations

from dataclasses import dataclass, field
import json
from importlib import resources
from typing import Any

REGISTRY_RESOURCE = "weaverssh_error_registry.json"


def _load_registry() -> dict[str, Any]:
    try:
        with resources.files("weaverssh_support.resources").joinpath(REGISTRY_RESOURCE).open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, ModuleNotFoundError):
        return {"codes": [], "components": {}}
    return data


_ERROR_REGISTRY_DOC = _load_registry()
ERROR_REGISTRY: dict[str, dict[str, Any]] = {
    str(item["code"]): dict(item) for item in _ERROR_REGISTRY_DOC.get("codes", [])
}


@dataclass
class WeaversshError(Exception):
    code: str
    component: str
    operation: str
    message: str
    cause: BaseException | None = None
    kind: str | None = None
    severity: str | None = None
    retryable: bool | None = None
    fields: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        definition = ERROR_REGISTRY.get(self.code, {})
        if self.kind is None:
            self.kind = str(definition.get("kind", "error"))
        if self.severity is None:
            self.severity = str(definition.get("severity", "error"))
        if self.retryable is None:
            self.retryable = bool(definition.get("retryable", False))
        super().__init__(self.__str__())

    def __str__(self) -> str:
        scope = self.component or "weaverssh"
        if self.operation:
            scope = f"{scope}.{self.operation}"
        text = f"[{self.code}] {scope}: {self.message or 'weaverssh component error'}"
        if self.cause is not None:
            text = f"{text}: {self.cause}"
        return text

    def with_field(self, key: str, value: str) -> WeaversshError:
        self.fields[str(key)] = str(value)
        return self

    def as_event(self) -> dict[str, Any]:
        definition = ERROR_REGISTRY.get(self.code, {})
        event: dict[str, Any] = {
            "code": self.code,
            "component": self.component,
            "operation": self.operation,
            "message": self.message,
            "severity": self.severity,
            "kind": self.kind,
            "retryable": self.retryable,
            "fault": self.kind == "fault",
        }
        for key in ("title", "subsystem"):
            if key in definition:
                event[key] = definition[key]
        if self.fields:
            event["fields"] = dict(self.fields)
        if self.cause is not None:
            event["cause"] = str(self.cause)
        return event


def known_code(code: str) -> bool:
    return code in ERROR_REGISTRY


def code_of(exc: BaseException) -> str | None:
    if isinstance(exc, WeaversshError):
        return exc.code
    return None


def to_event(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, WeaversshError):
        return exc.as_event()
    return {"kind": "exception", "message": str(exc)}


def raise_weaverssh(
    code: str,
    component: str,
    operation: str,
    message: str,
    *,
    cause: BaseException | None = None,
    kind: str | None = None,
    severity: str | None = None,
    retryable: bool | None = None,
    **fields: str,
) -> None:
    err = WeaversshError(
        code=code,
        component=component,
        operation=operation,
        message=message,
        cause=cause,
        kind=kind,
        severity=severity,
        retryable=retryable,
    )
    for key, value in fields.items():
        err.with_field(key, value)
    raise err
