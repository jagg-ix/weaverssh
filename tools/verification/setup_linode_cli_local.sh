#!/usr/bin/env bash
set -euo pipefail

# Local setup helper for Linode CLI on macOS/Linux user environments.
# - Installs linode-cli with user scope (PEP 668 compatible)
# - Ensures user Python bin path is in ~/.zshrc
# - Verifies binary is runnable
# - Launches `linode-cli configure` when interactive or token-backed
# - Optionally syncs local ssh-agent keys into Linode account sshkeys

PYTHON_BIN="${PYTHON_BIN:-python3}"
ZSHRC_PATH="${ZSHRC_PATH:-$HOME/.zshrc}"
APPLY_ZSHRC="${APPLY_ZSHRC:-1}"
RUN_CONFIGURE="${RUN_CONFIGURE:-1}"
SYNC_AGENT_KEYS="${SYNC_AGENT_KEYS:-1}"
SYNC_AGENT_KEYS_DRY_RUN="${SYNC_AGENT_KEYS_DRY_RUN:-0}"
LINODE_KEY_LABEL_PREFIX="${LINODE_KEY_LABEL_PREFIX:-agent-key}"
SYNC_AGENT_KEYS_FALLBACK_SSH_DIR="${SYNC_AGENT_KEYS_FALLBACK_SSH_DIR:-1}"
LINODE_TEST_HOST="${LINODE_TEST_HOST:-}"
LINODE_TEST_USER="${LINODE_TEST_USER:-root}"

USER_BASE="$("$PYTHON_BIN" -c 'import site; print(site.USER_BASE)')"
BIN_DIR="${USER_BASE}/bin"

echo "[setup] python user base: ${USER_BASE}"
echo "[setup] python user bin:  ${BIN_DIR}"

echo "[setup] installing/updating linode-cli (user scope)"
"${PYTHON_BIN}" -m pip install --user --break-system-packages linode-cli

# Resolve actual install location, even when multiple Python versions exist.
LINODE_CLI_BIN=""
declare -a CANDIDATES=("${BIN_DIR}/linode-cli")
while IFS= read -r p; do
  CANDIDATES+=("${p}")
done < <(ls -1d "$HOME"/Library/Python/*/bin/linode-cli 2>/dev/null | sort -Vr || true)
if command -v linode-cli >/dev/null 2>&1; then
  CANDIDATES+=("$(command -v linode-cli)")
fi
for c in "${CANDIDATES[@]}"; do
  if [[ -x "${c}" ]]; then
    LINODE_CLI_BIN="${c}"
    break
  fi
done
if [[ -z "${LINODE_CLI_BIN}" ]]; then
  echo "[error] linode-cli binary not found after install"
  exit 1
fi
BIN_DIR="$(dirname "${LINODE_CLI_BIN}")"
BIN_DIR_PORTABLE="${BIN_DIR/#$HOME/\$HOME}"
PATH_LINE="export PATH=\"${BIN_DIR_PORTABLE}:\$PATH\""
echo "[setup] using linode-cli binary: ${LINODE_CLI_BIN}"

if [[ "${APPLY_ZSHRC}" == "1" ]]; then
  touch "${ZSHRC_PATH}"
  if ! grep -Fq "${PATH_LINE}" "${ZSHRC_PATH}"; then
    {
      echo ""
      echo "# Linode CLI user-bin path"
      echo "${PATH_LINE}"
    } >> "${ZSHRC_PATH}"
    echo "[setup] appended PATH line to ${ZSHRC_PATH}"
  else
    echo "[setup] PATH line already present in ${ZSHRC_PATH}"
  fi
fi

export PATH="${BIN_DIR}:${PATH}"
echo "[verify] linode-cli version:"
"${LINODE_CLI_BIN}" --version

if [[ "${RUN_CONFIGURE}" != "1" ]]; then
  echo "[setup] RUN_CONFIGURE=0, skipping configure"
else
  if [[ -n "${LINODE_CLI_TOKEN:-}" ]]; then
    echo "[setup] configuring linode-cli with LINODE_CLI_TOKEN"
    "${LINODE_CLI_BIN}" configure --token "${LINODE_CLI_TOKEN}"
    echo "[done] token-based configuration complete"
  elif [[ -t 0 && -t 1 ]]; then
    echo "[setup] launching interactive configure"
    "${LINODE_CLI_BIN}" configure
    echo "[done] interactive configuration complete"
  else
    echo "[warn] non-interactive shell; skipping interactive configure"
    echo "[next] run this manually in your terminal:"
    echo "       source \"${ZSHRC_PATH}\" && linode-cli configure"
  fi
fi

if [[ "${SYNC_AGENT_KEYS}" == "1" ]]; then
  SYNC_ARGS=(
    "${PYTHON_BIN}"
    "tools/verification/sync_linode_sshkeys_from_agent.py"
    "--linode-cli"
    "${LINODE_CLI_BIN}"
    "--label-prefix"
    "${LINODE_KEY_LABEL_PREFIX}"
  )
  if [[ "${SYNC_AGENT_KEYS_DRY_RUN}" == "1" ]]; then
    SYNC_ARGS+=("--dry-run")
  fi
  if [[ "${SYNC_AGENT_KEYS_FALLBACK_SSH_DIR}" == "1" ]]; then
    SYNC_ARGS+=("--fallback-ssh-dir")
  fi
  echo "[setup] syncing ssh-agent keys to Linode account sshkeys"
  if ! "${SYNC_ARGS[@]}"; then
    echo "[warn] ssh-agent key sync failed (likely missing Linode auth)"
    echo "[next] ensure linode-cli is configured, then rerun:"
    echo "       SYNC_AGENT_KEYS=1 tools/verification/setup_linode_cli_local.sh"
  fi
else
  echo "[setup] SYNC_AGENT_KEYS=0, skipping ssh-agent key sync"
fi

if [[ -n "${LINODE_TEST_HOST}" ]]; then
  echo "[setup] testing SSH login using local agent keys: ${LINODE_TEST_USER}@${LINODE_TEST_HOST}"
  if ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "${LINODE_TEST_USER}@${LINODE_TEST_HOST}" "echo linode_key_login_ok"; then
    echo "[done] SSH key login test passed"
  else
    echo "[warn] SSH key login test failed for ${LINODE_TEST_USER}@${LINODE_TEST_HOST}"
    echo "[note] Linode account sshkeys do not always retrofit existing instance authorized_keys."
    echo "[next] via LISH on the instance, append your public key to ~/.ssh/authorized_keys for this user."
  fi
fi
