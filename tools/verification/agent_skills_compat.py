#!/usr/bin/env python3
from __future__ import annotations

"""Agent Skills (SKILL.md) discovery and compatibility helpers.

Implements compatibility with the open Agent Skills format:
https://agentskills.io/what-are-skills
"""

import os
from pathlib import Path
import re
from typing import Any


SKILL_FILE_NAME = "SKILL.md"
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _split_csv_paths(raw: str) -> list[Path]:
    out: list[Path] = []
    for item in str(raw or "").split(","):
        s = str(item or "").strip()
        if not s:
            continue
        out.append(Path(s).expanduser())
    return out


def default_search_roots(*, repo_root: Path) -> list[Path]:
    """Return conventional skill roots with deduplicated order."""
    home = Path.home()
    codex_home = Path(str(os.environ.get("CODEX_HOME", str(home / ".codex")))).expanduser()
    env_paths = _split_csv_paths(str(os.environ.get("AGENT_SKILLS_PATHS", "")).strip())

    candidates = [
        repo_root / ".agents" / "skills",
        repo_root / ".claude" / "skills",
        home / ".agents" / "skills",
        home / ".claude" / "skills",
        codex_home / "skills",
        *env_paths,
    ]
    out: list[Path] = []
    seen: set[str] = set()
    for p in candidates:
        try:
            rp = p.resolve()
        except Exception:
            rp = p
        key = str(rp)
        if key in seen:
            continue
        seen.add(key)
        out.append(rp)
    return out


def _parse_frontmatter_fallback(block: str) -> dict[str, Any]:
    """Parse simple top-level YAML-like key/value pairs.

    This fallback intentionally handles the minimum required fields (`name`,
    `description`) plus scalar optional fields.
    """
    out: dict[str, Any] = {}
    for line in str(block or "").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith(" ") or line.startswith("\t"):
            # Ignore nested mappings/lists in fallback parser.
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = str(k or "").strip()
        if not key:
            continue
        value = str(v or "").strip()
        if len(value) >= 2 and ((value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'"))):
            value = value[1:-1]
        out[key] = value
    return out


def _parse_frontmatter_yaml(block: str) -> dict[str, Any]:
    try:
        import yaml  # type: ignore
    except Exception:
        return _parse_frontmatter_fallback(block)
    try:
        parsed = yaml.safe_load(block)
    except Exception:
        return _parse_frontmatter_fallback(block)
    if isinstance(parsed, dict):
        return parsed
    return _parse_frontmatter_fallback(block)


def parse_skill_file(path: Path) -> dict[str, Any]:
    out: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "name": "",
        "description": "",
        "license": "",
        "compatibility": "",
        "allowed_tools": "",
        "metadata": {},
        "body": "",
        "issues": [],
    }
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as exc:
        out["ok"] = False
        out["issues"] = [f"read_error:{exc}"]
        return out

    text = str(raw or "")
    if not text.startswith("---"):
        out["ok"] = False
        out["issues"] = ["missing_frontmatter_open"]
        return out

    close_idx = text.find("\n---", 3)
    if close_idx < 0:
        out["ok"] = False
        out["issues"] = ["missing_frontmatter_close"]
        return out
    fm_block = text[3:close_idx]
    body_start = close_idx + 4
    # Skip one trailing newline after frontmatter delimiter.
    if body_start < len(text) and text[body_start] == "\n":
        body_start += 1
    body = text[body_start:].strip()
    fm = _parse_frontmatter_yaml(fm_block)

    name = str(fm.get("name", "")).strip()
    description = str(fm.get("description", "")).strip()
    out["name"] = name
    out["description"] = description
    out["license"] = str(fm.get("license", "")).strip()
    compat = fm.get("compatibility", "")
    if isinstance(compat, list):
        out["compatibility"] = ", ".join(str(x) for x in compat if str(x).strip())
    else:
        out["compatibility"] = str(compat or "").strip()
    allowed_tools = fm.get("allowed-tools", "")
    if isinstance(allowed_tools, list):
        out["allowed_tools"] = " ".join(str(x) for x in allowed_tools if str(x).strip())
    else:
        out["allowed_tools"] = str(allowed_tools or "").strip()
    metadata = fm.get("metadata", {})
    out["metadata"] = metadata if isinstance(metadata, dict) else {}
    out["body"] = body

    issues: list[str] = []
    if not name:
        issues.append("missing_name")
    elif len(name) > 64:
        issues.append("name_too_long")
    elif not NAME_RE.fullmatch(name):
        issues.append("name_invalid_format")
    if "--" in name:
        issues.append("name_contains_double_hyphen")
    if name.startswith("-") or name.endswith("-"):
        issues.append("name_invalid_hyphen_edges")

    if not description:
        issues.append("missing_description")
    elif len(description) > 1024:
        issues.append("description_too_long")

    compat_text = str(out.get("compatibility", "")).strip()
    if compat_text and len(compat_text) > 500:
        issues.append("compatibility_too_long")
    if metadata and not isinstance(metadata, dict):
        issues.append("metadata_not_mapping")

    parent = path.parent.name
    if name and parent and name != parent:
        issues.append("name_parent_mismatch")

    out["issues"] = issues
    out["ok"] = len(issues) == 0
    return out


def discover_skills(
    *,
    repo_root: Path,
    roots: list[Path] | None = None,
    include_body: bool = False,
    limit: int = 500,
) -> dict[str, Any]:
    search_roots = roots if roots is not None else default_search_roots(repo_root=repo_root)
    out_skills: list[dict[str, Any]] = []
    scanned_roots: list[str] = []

    for root in search_roots:
        rp = root.expanduser()
        if not rp.is_absolute():
            rp = (repo_root / rp).resolve()
        else:
            rp = rp.resolve()
        scanned_roots.append(str(rp))
        if not rp.exists() or not rp.is_dir():
            continue
        try:
            skill_files = sorted(
                [p for p in rp.rglob(SKILL_FILE_NAME) if p.is_file()],
                key=lambda p: str(p).lower(),
            )
        except Exception:
            continue
        seen_paths: set[str] = set()
        for skill_md in skill_files:
            key = str(skill_md.resolve())
            if key in seen_paths:
                continue
            seen_paths.add(key)
            child = skill_md.parent
            parsed = parse_skill_file(skill_md)
            try:
                rel = str(child.relative_to(rp))
            except Exception:
                rel = child.name
            skill = {
                "name": parsed.get("name", ""),
                "description": parsed.get("description", ""),
                "path": str(skill_md),
                "root": str(rp),
                "dir_name": child.name,
                "dir_relative": rel,
                "ok": bool(parsed.get("ok", False)),
                "issues": list(parsed.get("issues", [])),
                "license": str(parsed.get("license", "")),
                "compatibility": str(parsed.get("compatibility", "")),
                "allowed_tools": str(parsed.get("allowed_tools", "")),
                "metadata": parsed.get("metadata", {}) if isinstance(parsed.get("metadata", {}), dict) else {},
                "has_scripts": bool((child / "scripts").exists()),
                "has_references": bool((child / "references").exists()),
                "has_assets": bool((child / "assets").exists()),
            }
            if include_body:
                skill["body"] = str(parsed.get("body", ""))
            out_skills.append(skill)
            if len(out_skills) >= int(limit):
                break
        if len(out_skills) >= int(limit):
            break

    # Handle same-name collisions across roots with lenient warnings.
    by_name: dict[str, list[int]] = {}
    for idx, item in enumerate(out_skills):
        key = str(item.get("name", "")).strip().lower()
        if not key:
            continue
        by_name.setdefault(key, []).append(idx)
    collisions: dict[str, int] = {k: len(v) for k, v in by_name.items() if len(v) > 1}
    if collisions:
        for name_key, indices in by_name.items():
            if len(indices) <= 1:
                continue
            for idx in indices:
                issues = list(out_skills[idx].get("issues", []))
                if "name_collision" not in issues:
                    issues.append("name_collision")
                out_skills[idx]["issues"] = issues
                out_skills[idx]["ok"] = False

    return {
        "ok": True,
        "roots": scanned_roots,
        "count": len(out_skills),
        "skills": out_skills,
        "collisions": collisions,
    }


def open_skill(
    *,
    repo_root: Path,
    skill_name: str = "",
    skill_path: str = "",
    roots: list[Path] | None = None,
) -> dict[str, Any]:
    target_name = str(skill_name or "").strip()
    target_path = str(skill_path or "").strip()
    if target_path:
        p = Path(target_path).expanduser()
        if not p.is_absolute():
            p = (repo_root / p).resolve()
        if p.is_dir():
            p = p / SKILL_FILE_NAME
        parsed = parse_skill_file(p)
        return {
            "ok": bool(parsed.get("ok", False)),
            "skill": parsed,
        }

    discovered = discover_skills(repo_root=repo_root, roots=roots, include_body=True)
    skills = list(discovered.get("skills", []))
    if target_name:
        low = target_name.lower()
        skills = [s for s in skills if str(s.get("name", "")).lower() == low or str(s.get("dir_name", "")).lower() == low]
    if not skills:
        return {
            "ok": False,
            "error": "skill_not_found",
            "query": target_name,
            "count": 0,
            "skills": [],
        }
    if len(skills) > 1:
        return {
            "ok": False,
            "error": "skill_ambiguous",
            "query": target_name,
            "count": len(skills),
            "skills": skills,
        }
    skill = dict(skills[0])
    path = Path(str(skill.get("path", "")))
    parsed = parse_skill_file(path)
    skill["body"] = str(parsed.get("body", ""))
    skill["issues"] = list(parsed.get("issues", []))
    skill["ok"] = bool(parsed.get("ok", False))
    return {"ok": bool(skill.get("ok", False)), "skill": skill}
