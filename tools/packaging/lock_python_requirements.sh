#!/bin/sh
# Compile hash-locked Python requirements for release artifacts.
# This script intentionally does not run during normal builds because it may
# need network access. Run it in a controlled release environment.
set -eu

usage() {
  cat <<'USAGE'
usage: lock_python_requirements.sh [options]

Options:
  --profile NAME       core, mcp, webterm, tray, vision, or all. Default: all.
  --python PYTHON      Python interpreter. Default: python3.
  --output FILE        Output lock file. Default: requirements/python/<profile>.lock.txt.
  --no-hashes          Do not generate pip hashes.
  -h, --help           Show help.
USAGE
}

profile=all
python_bin=${PYTHON:-python3}
output=
with_hashes=true
while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile) profile=${2:?missing --profile value}; shift 2 ;;
    --python) python_bin=${2:?missing --python value}; shift 2 ;;
    --output) output=${2:?missing --output value}; shift 2 ;;
    --no-hashes) with_hashes=false; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
req_dir="$repo_root/requirements/python"
case "$profile" in
  core|mcp|webterm|tray|vision|all) ;;
  *) echo "unsupported profile: $profile" >&2; exit 2 ;;
esac
[ -n "$output" ] || output="$req_dir/$profile.lock.txt"
input="$req_dir/$profile.txt"
if [ "$profile" = all ]; then input="$req_dir/production.txt"; fi
[ -f "$input" ] || { echo "requirements file not found: $input" >&2; exit 1; }

if ! "$python_bin" -m piptools --version >/dev/null 2>&1; then
  "$python_bin" -m pip install --user pip-tools
fi
args=""
if [ "$with_hashes" = true ]; then args="--generate-hashes"; fi
"$python_bin" -m piptools compile $args --resolver=backtracking --output-file "$output" "$input"
printf 'locked requirements: %s\n' "$output"
