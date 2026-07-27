from __future__ import annotations

from dataclasses import dataclass
import json
from importlib import resources
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ToolSpec:
    name: str
    path: str
    profile: str
    description: str

    @property
    def module(self) -> str:
        if not self.path.endswith(".py"):
            raise ValueError(f"tool path is not a Python module: {self.path}")
        return self.path[:-3].replace("/", ".")


def _resource_manifest() -> dict[str, Any]:
    with resources.files("weaverssh_support.resources").joinpath("python_distribution_manifest.json").open(
        "r", encoding="utf-8"
    ) as f:
        return json.load(f)


def load_manifest(path: str | Path | None = None) -> dict[str, Any]:
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    return _resource_manifest()


def profiles(manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    return dict((manifest or load_manifest()).get("profiles", {}))


def tools(manifest: dict[str, Any] | None = None) -> list[ToolSpec]:
    data = manifest or load_manifest()
    out: list[ToolSpec] = []
    for item in data.get("tools", []):
        out.append(
            ToolSpec(
                name=str(item["name"]),
                path=str(item["path"]),
                profile=str(item.get("profile", "core")),
                description=str(item.get("description", "")),
            )
        )
    return out


def tool_map(manifest: dict[str, Any] | None = None) -> dict[str, ToolSpec]:
    return {tool.name: tool for tool in tools(manifest)}


def requirements_for_profile(profile: str, manifest: dict[str, Any] | None = None) -> list[str]:
    data = profiles(manifest)
    if profile not in data:
        raise KeyError(f"unknown profile: {profile}")
    return list(data[profile].get("requirements", []))
