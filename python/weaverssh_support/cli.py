from __future__ import annotations

import argparse
import json
import runpy
import sys
from typing import Sequence

from .profiles import load_manifest, profiles, requirements_for_profile, tool_map, tools


def _print_profiles(manifest: dict) -> None:
    print("weaverssh Python profiles")
    for name, data in sorted(profiles(manifest).items()):
        print(f"  {name:<10} {data.get('description', '')}")


def _print_tools(manifest: dict) -> None:
    print("weaverssh Python tools")
    for tool in sorted(tools(manifest), key=lambda item: item.name):
        print(f"  {tool.name:<24} profile={tool.profile:<8} module={tool.module:<56} {tool.description}")


def _run_tool(argv: Sequence[str], manifest: dict) -> int:
    if not argv:
        _print_tools(manifest)
        return 0
    selected, rest = argv[0], list(argv[1:])
    available = tool_map(manifest)
    tool = available.get(selected)
    if tool is None:
        print(f"unknown tool: {selected}", file=sys.stderr)
        _print_tools(manifest)
        return 2
    sys.argv = [tool.path, *rest]
    runpy.run_module(tool.module, run_name="__main__", alter_sys=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="weaverssh-py",
        description="Python support tooling for weaverssh production setup and coordination.",
    )
    parser.add_argument("--manifest", help="Use an explicit Python distribution manifest JSON file.")
    parser.add_argument("--json", action="store_true", help="Print manifest/profile output as JSON.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--profiles", action="store_true", help="List dependency profiles.")
    group.add_argument("--list", action="store_true", help="List packaged Python tools.")
    group.add_argument("--requirements", metavar="PROFILE", help="Print requirements files for a profile.")
    group.add_argument("--dump-manifest", action="store_true", help="Print the active manifest.")
    parser.add_argument("tool", nargs=argparse.REMAINDER, help="Run a packaged tool by name, followed by its arguments.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    manifest = load_manifest(args.manifest)

    if args.dump_manifest:
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0
    if args.profiles:
        if args.json:
            print(json.dumps(profiles(manifest), indent=2, sort_keys=True))
        else:
            _print_profiles(manifest)
        return 0
    if args.requirements:
        reqs = requirements_for_profile(args.requirements, manifest)
        if args.json:
            print(json.dumps(reqs, indent=2))
        else:
            for req in reqs:
                print(req)
        return 0
    if args.list or not args.tool:
        if args.json:
            print(json.dumps([tool.__dict__ | {"module": tool.module} for tool in tools(manifest)], indent=2, sort_keys=True))
        else:
            _print_tools(manifest)
        return 0
    return _run_tool(args.tool, manifest)


if __name__ == "__main__":
    raise SystemExit(main())
