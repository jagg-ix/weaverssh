# weaverssh Jepsen Workbench

This is the Jepsen-based system-test layer for weaverssh. It is intentionally
separate from the normal Go/Python unit tests because Jepsen tests can mutate or
break SSH-accessible SUT nodes while injecting faults.

## Dependency

The project pins the published Jepsen library from Clojars:

```clojure
jepsen/jepsen {:mvn/version "0.3.11"}
```

## Safe plan

Generate a non-mutating dry-run plan from the repo root:

```bash
python3 tools/verification/run_weaverssh_jepsen.py --dry-run \
  --nodes 203.0.113.10,203.0.113.20 \
  --username kb \
  --identity-file ~/.ssh/id_ed25519 \
  --output artifacts/jepsen/plan.json
```


## Ansible install workload

The `ansible-install` workload installs Ansible on each disposable SUT node and
runs the checked-in weaverssh Ansible playbook locally on that node. It is useful
for validating that a source-free binary archive can become a working
`~/.weaverssh/bin/wv` installation under Jepsen control.

Plan only:

```bash
python3 tools/verification/run_weaverssh_jepsen.py --dry-run \
  --nodes 203.0.113.10,203.0.113.20 \
  --username kb \
  --identity-file ~/.ssh/id_ed25519 \
  --workload ansible-install \
  --nemesis none \
  --ansible-archive dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz \
  --ansible-checksum <sha256>
```

Execute only on disposable nodes:

```bash
python3 tools/verification/run_weaverssh_jepsen.py --execute --allow-destructive \
  --nodes 203.0.113.10,203.0.113.20 \
  --username kb \
  --identity-file ~/.ssh/id_ed25519 \
  --workload ansible-install \
  --nemesis none \
  --ansible-archive dist/binary/weaverssh-0.1.0-1-linux-amd64.tar.gz \
  --ansible-checksum <sha256>
```

## Destructive execution

Only run against disposable SUT nodes. The Python wrapper requires both
`--execute` and `--allow-destructive` before it will invoke Clojure/Jepsen:

```bash
python3 tools/verification/run_weaverssh_jepsen.py --execute --allow-destructive \
  --nodes 203.0.113.10,203.0.113.20 \
  --username kb \
  --identity-file ~/.ssh/id_ed25519 \
  --nemesis process-kill
```

Jepsen writes histories and checker output under the Clojure project's `store/`
directory. Copy or archive those artifacts with the rest of the workbench report.
