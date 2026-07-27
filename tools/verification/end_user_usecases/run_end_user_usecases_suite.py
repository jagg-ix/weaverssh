#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = Path(__file__).resolve().parent


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=False,
    )


def _case_specs(output_dir: Path, live_ssh: bool, live_chain: bool) -> list[dict[str, object]]:
    specs: list[dict[str, object]] = [
        {
            "id": "UC01",
            "script": "uc01_probe_vhs.py",
            "args": ["--probe-output", str(output_dir / "sshx11_probe.json")],
        },
        {
            "id": "UC02",
            "script": "uc02_render_user_service.py",
            "args": [
                "--platform",
                "linux",
                "--label",
                "io.github.jaggix.weaverssh",
                "--state-dir",
                str(output_dir / "sshx11d-state"),
            ],
        },
        {
            "id": "UC03",
            "script": "uc03_print_windows_task.py",
            "args": [
                "--label",
                "io.github.jaggix.weaverssh",
                "--state-dir",
                str(output_dir / "sshx11d-state"),
            ],
        },
        {
            "id": "UC04",
            "script": "uc04_verify_ssh_login.py",
            "args": [
                "--hosts",
                "203.0.113.10,203.0.113.20",
                "--users",
                "root,kb",
            ]
            + ([] if live_ssh else ["--dry-run"]),
        },
        {
            "id": "UC05",
            "script": "uc05_ci_gate_dry_run.py",
            "args": ["--tier", "fast", "--gate-output", str(output_dir / "sshx11_ci_gate_fast.json")],
        },
        {
            "id": "UC06",
            "script": "uc06_9p_over_socks_dry_run.py",
            "args": [
                "--interop-profile",
                "auto",
                "--plan-output",
                str(output_dir / "sshx11_9p_over_socks.json"),
            ],
        },
        {
            "id": "UC07",
            "script": "uc07_benchmark_socks5_dry_run.py",
            "args": [
                "--mode",
                "mock",
                "--scenario",
                "smoke",
                "--plan-output",
                str(output_dir / "sshx11_socks5_perf.json"),
            ],
        },
        {
            "id": "UC08",
            "script": "uc08_remote_execution_tla_plan.py",
            "args": [
                "--host",
                "203.0.113.10",
                "--user",
                "root",
                "--port",
                "22",
                "--report-output",
                str(output_dir / "sshx11_remote_execution_tla.json"),
            ],
        },
        {
            "id": "UC09",
            "script": "uc09_extension_set_tla_report.py",
            "args": [
                "--report-output",
                str(output_dir / "sshx11_extension_set_tla.json"),
                "--markdown-output",
                str(output_dir / "sshx11_extension_set_tla.md"),
            ],
        },
        {
            "id": "UC10",
            "script": "uc10_crypto_crosslayer_report.py",
            "args": [
                "--report-output",
                str(output_dir / "sshx11_crypto_crosslayer_reverse.json"),
                "--markdown-output",
                str(output_dir / "sshx11_crypto_crosslayer_reverse.md"),
                "--interaction-json",
                str(output_dir / "sshx11_crypto_interaction.json"),
                "--interaction-md",
                str(output_dir / "sshx11_crypto_interaction.md"),
            ],
        },
        {
            "id": "UC11",
            "script": "uc11_multihop_chain_unit_test.py",
            "args": [
                "--junit-output",
                str(output_dir / "sshx11_multihop_chain_unit.junit.xml"),
            ],
        },
        {
            "id": "UC13",
            "script": "uc13_scp_sftp_backhaul_unit_test.py",
            "args": [
                "--x-port",
                "6017",
                "--remote-bind-port",
                "22022",
                "--remote-host",
                "203.0.113.20",
                "--remote-user",
                "root",
                "--remote-port",
                "22",
                "--jumps",
                "root@203.0.113.10",
                "--state-dir",
                str(output_dir / "uc13_state"),
                "--junit-output",
                str(output_dir / "sshx11_scp_sftp_backhaul_unit.junit.xml"),
            ],
        },
    ]
    if live_chain:
        specs.append(
            {
                "id": "UC12",
                "script": "uc12_multihop_chain_system_test.py",
                "args": [
                    "--junit-output",
                    str(output_dir / "sshx11_multihop_chain_system.junit.xml"),
                ],
            }
        )
    return specs


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the full no-build end-user use-case suite.")
    parser.add_argument("--output-dir", default="/tmp/sshx11_end_user_usecases")
    parser.add_argument("--summary-output", default=None)
    parser.add_argument("--live-ssh", action="store_true", help="Run UC04 as live SSH checks instead of dry-run.")
    parser.add_argument(
        "--live-chain",
        action="store_true",
        help="Run UC12 live multi-hop chain system test against discovered hosts.",
    )
    parser.add_argument("--stop-on-failure", action="store_true")
    args = parser.parse_args()

    output_dir = Path(args.output_dir).expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_output = (
        Path(args.summary_output).expanduser()
        if args.summary_output
        else output_dir / "suite_summary.json"
    )

    cases = _case_specs(output_dir, args.live_ssh, args.live_chain)
    results: list[dict[str, object]] = []
    started = time.time()
    for case in cases:
        case_id = str(case["id"])
        script = SCRIPT_DIR / str(case["script"])
        case_output = output_dir / f"{case_id}.json"
        cmd = ["python3", str(script), *list(case["args"]), "--output", str(case_output)]
        proc = _run(cmd)
        parsed: dict[str, object] = {}
        if case_output.exists():
            try:
                parsed = json.loads(case_output.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                parsed = {}
        result = {
            "case_id": case_id,
            "script": str(script),
            "ok": bool(parsed.get("ok", False)),
            "returncode": proc.returncode,
            "output_path": str(case_output),
            "stderr": proc.stderr,
        }
        results.append(result)
        if args.stop_on_failure and (proc.returncode != 0 or not result["ok"]):
            break

    success_count = sum(1 for item in results if bool(item.get("ok")))
    summary = {
        "ok": success_count == len(cases),
        "repo_root": str(REPO_ROOT),
        "output_dir": str(output_dir),
        "summary_output": str(summary_output),
        "live_ssh": args.live_ssh,
        "live_chain": args.live_chain,
        "case_total": len(cases),
        "case_run": len(results),
        "case_ok": success_count,
        "case_failed": len(results) - success_count,
        "duration_s": round(time.time() - started, 3),
        "results": results,
    }
    summary_output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
