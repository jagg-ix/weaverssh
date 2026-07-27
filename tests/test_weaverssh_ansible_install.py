from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ROLE = REPO_ROOT / "ansible" / "roles" / "weaverssh_wv"
PLAYBOOKS = [
    "ansible/playbooks/install_wv.yml",
    "ansible/playbooks/install_wv_docker.yml",
    "ansible/playbooks/install_wv_kubernetes.yml",
]


def read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


def test_ansible_role_has_user_home_container_and_checksum_controls() -> None:
    defaults = read("ansible/roles/weaverssh_wv/defaults/main.yml")
    assert 'weaverssh_target_type: "posix"' in defaults
    assert 'weaverssh_install_dir: "{{ ansible_env.HOME }}/.weaverssh/bin"' in defaults
    assert 'weaverssh_cache_dir: "{{ ansible_env.HOME }}/.weaverssh/cache"' in defaults
    assert 'weaverssh_container_install_dir: "/tmp/.weaverssh/bin"' in defaults
    assert 'weaverssh_docker_runtime: "docker"' in defaults
    assert 'weaverssh_docker_container: ""' in defaults
    assert 'weaverssh_kubectl: "kubectl"' in defaults
    assert 'weaverssh_kubernetes_pod: ""' in defaults
    assert 'weaverssh_archive_path: ""' in defaults
    assert 'weaverssh_archive_checksum: ""' in defaults
    assert 'weaverssh_run_smoke_test: true' in defaults


def test_ansible_dispatches_to_posix_docker_and_kubernetes_install_paths() -> None:
    tasks = read("ansible/roles/weaverssh_wv/tasks/main.yml")
    assert "weaverssh_target_type in ['posix', 'docker', 'kubernetes']" in tasks
    assert "include_tasks: install_posix.yml" in tasks
    assert "include_tasks: prepare_controller_binary.yml" in tasks
    assert "include_tasks: install_docker.yml" in tasks
    assert "include_tasks: install_kubernetes.yml" in tasks
    assert "Detect Docker container architecture" in tasks
    assert "Detect Kubernetes pod architecture" in tasks
    assert "uname -m" in tasks
    assert "weaverssh_arch_source" in tasks
    assert "weaverssh_target_type == 'posix'" in tasks
    assert "weaverssh_target_type == 'docker'" in tasks
    assert "weaverssh_target_type == 'kubernetes'" in tasks


def test_posix_install_uses_binary_archive_without_become() -> None:
    playbook = read("ansible/playbooks/install_wv.yml")
    posix = read("ansible/roles/weaverssh_wv/tasks/install_posix.yml")
    assert "become: false" in playbook
    assert "ansible.builtin.copy:" in posix
    assert "ansible.builtin.get_url:" in posix
    assert "ansible.builtin.unarchive:" in posix
    assert "checksum_algorithm: sha256" in posix
    assert "{{ weaverssh_install_dir }}/wv version" in posix
    assert "{{ weaverssh_install_dir }}/wv help" in posix
    assert "win_get_url" in read("ansible/README.md")


def test_container_install_paths_copy_controller_binary_and_smoke_test() -> None:
    prepare = read("ansible/roles/weaverssh_wv/tasks/prepare_controller_binary.yml")
    docker = read("ansible/roles/weaverssh_wv/tasks/install_docker.yml")
    kubernetes = read("ansible/roles/weaverssh_wv/tasks/install_kubernetes.yml")

    assert "delegate_to: localhost" in prepare
    assert "weaverssh_controller_wv_path" in prepare
    assert "weaverssh_controller_cache_dir" in prepare

    assert "weaverssh_docker_container" in read("ansible/roles/weaverssh_wv/tasks/main.yml")
    assert "{{ weaverssh_docker_runtime }} cp" in docker
    assert "{{ weaverssh_docker_runtime }} exec" in docker
    assert "{{ weaverssh_container_install_dir }}/wv version" in docker
    assert "{{ weaverssh_container_install_dir }}/wv help" in docker

    assert "weaverssh_kubernetes_pod" in read("ansible/roles/weaverssh_wv/tasks/main.yml")
    assert "{{ weaverssh_kubectl }} -n {{ weaverssh_kubernetes_namespace }} cp" in kubernetes
    assert "{{ weaverssh_kubectl }} -n {{ weaverssh_kubernetes_namespace }} exec" in kubernetes
    assert "weaverssh_kubectl_container_arg" in kubernetes
    assert "{{ weaverssh_container_install_dir }}/wv version" in kubernetes
    assert "{{ weaverssh_container_install_dir }}/wv help" in kubernetes


def test_makefile_exposes_ansible_install_targets() -> None:
    makefile = read("Makefile")
    assert "ansible-install-plan:" in makefile
    assert "ansible-install-wv:" in makefile
    assert "ansible-install-docker-plan:" in makefile
    assert "ansible-install-docker:" in makefile
    assert "ansible-install-k8s-plan:" in makefile
    assert "ansible-install-k8s:" in makefile
    assert "ansible-syntax-check:" in makefile
    assert "ANSIBLE_DOCKER_CONTAINER" in makefile
    assert "ANSIBLE_K8S_NAMESPACE" in makefile
    assert "ANSIBLE_K8S_POD" in makefile
    assert "ANSIBLE_WV_ARCHIVE" in makefile
    assert "ANSIBLE_WV_CHECKSUM" in makefile
    assert "ANSIBLE_SYNTAX_INVENTORY" in makefile


def test_ansible_playbooks_are_present_and_documented() -> None:
    docs = read("ansible/README.md")
    for playbook in PLAYBOOKS:
        assert (REPO_ROOT / playbook).exists()
    assert "Install Into A Docker Container" in docs
    assert "Install Into A Kubernetes Pod" in docs
    assert "ANSIBLE_DOCKER_CONTAINER" in docs
    assert "ANSIBLE_K8S_NAMESPACE" in docs
    assert "ANSIBLE_K8S_POD" in docs


def test_ansible_syntax_check_when_available() -> None:
    if not shutil.which("ansible-playbook"):
        pytest.skip("ansible-playbook not installed")
    env = os.environ.copy()
    env.update({"LC_ALL": "en_US.UTF-8", "LANG": "en_US.UTF-8"})
    for playbook in PLAYBOOKS:
        subprocess.run(
            [
                "ansible-playbook",
                "-i",
                str(REPO_ROOT / "ansible" / "inventory.syntax.ini"),
                str(REPO_ROOT / playbook),
                "--syntax-check",
            ],
            cwd=REPO_ROOT,
            check=True,
            env=env,
        )
