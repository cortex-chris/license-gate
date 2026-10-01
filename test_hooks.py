"""The global hooks, end to end: real git, a real push to a local remote.

Each test points git at hooks/ for one command (``-c core.hooksPath``), which is
exactly what install.sh sets globally.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

HOOKS = Path(__file__).resolve().parent / "hooks"


def git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-c", f"core.hooksPath={HOOKS}", *args], cwd=cwd,
                          check=check, capture_output=True, text=True)


def _lock(license_text: str) -> str:
    return json.dumps({"packages": {"": {"name": "root"},
                                    "node_modules/somepkg": {"version": "1", "license": license_text}}})


@pytest.fixture
def work(tmp_path):
    subprocess.run(["git", "init", "-q", "--bare", str(tmp_path / "remote.git")], check=True)
    repo = tmp_path / "work"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    for key, value in (("user.email", "t@example.com"), ("user.name", "t")):
        subprocess.run(["git", "config", key, value], cwd=repo, check=True)
    subprocess.run(["git", "remote", "add", "origin", str(tmp_path / "remote.git")], cwd=repo, check=True)
    return repo


def commit(repo: Path, license_text: str) -> str:
    (repo / "package-lock.json").write_text(_lock(license_text))
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", license_text)
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def remote_main(repo: Path) -> str:
    return subprocess.run(["git", "rev-parse", "--verify", "-q", "main"], cwd=repo.parent / "remote.git",
                          capture_output=True, text=True).stdout.strip()


def own_hook(repo: Path, name: str, body: str) -> Path:
    path = repo / ".git" / "hooks" / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return path


def test_a_gpl_push_is_refused_and_a_clean_one_allowed(work):
    good = commit(work, "MIT")
    assert git(work, "push", "-q", "origin", "HEAD:main", check=False).returncode == 0
    assert remote_main(work) == good
    commit(work, "GPL-3.0-only")
    refused = git(work, "push", "-q", "origin", "HEAD:main", check=False)
    assert refused.returncode != 0 and "LICENSE GATE" in refused.stderr
    assert remote_main(work) == good


def test_the_repositorys_own_pre_push_gets_the_same_refs(work):
    marker = work.parent / "own.txt"
    own_hook(work, "pre-push", f'cat > "{marker}"\n')
    good = commit(work, "MIT")
    git(work, "push", "-q", "origin", "HEAD:main")
    assert good in marker.read_text()


def test_the_repositorys_own_pre_push_can_still_refuse(work):
    own_hook(work, "pre-push", "exit 1\n")
    commit(work, "MIT")
    assert git(work, "push", "-q", "origin", "HEAD:main", check=False).returncode != 0
    assert remote_main(work) == ""


def test_a_repository_that_gates_itself_is_not_checked_twice(work):
    # Its own hook runs license_audit already; here it lets everything through.
    own_hook(work, "pre-push", "# runs tools/license_audit/license_audit.py\ncat >/dev/null\nexit 0\n")
    bad = commit(work, "GPL-3.0-only")
    assert git(work, "push", "-q", "origin", "HEAD:main", check=False).returncode == 0
    assert remote_main(work) == bad


def test_other_hooks_are_handed_to_the_repository(work):
    marker = work.parent / "post-commit.txt"
    own_hook(work, "post-commit", f'echo ran > "{marker}"\n')
    commit(work, "MIT")
    assert marker.read_text().strip() == "ran"
