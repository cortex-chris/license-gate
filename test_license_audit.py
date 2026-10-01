"""Unit tests for tools/license_audit/license_audit.py.

Covers the license classifier (single + dual expressions), the dependency
manifest parsers, and the pure gate-decision logic. No network access — the
PyPI-fetch path is exercised separately by the CI job that runs the real audit.
"""
from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import license_audit as la


# --- classify_atom: single license strings ----------------------------------
@pytest.mark.parametrize("text,expected", [
    ("MIT", la.PERMISSIVE),
    ("MIT License", la.PERMISSIVE),
    ("BSD-3-Clause", la.PERMISSIVE),
    ("Apache Software License", la.PERMISSIVE),
    ("Apache-2.0", la.PERMISSIVE),
    ("ISC", la.PERMISSIVE),
    ("Python Software Foundation License", la.PERMISSIVE),
    ("CC0-1.0", la.PUBLIC_DOMAIN),
    ("The Unlicense", la.PUBLIC_DOMAIN),
    ("LGPL-3.0-only", la.WEAK_COPYLEFT),
    ("GNU Library or Lesser General Public License (LGPL)", la.WEAK_COPYLEFT),
    ("MPL-2.0", la.WEAK_COPYLEFT),
    ("Mozilla Public License 2.0", la.WEAK_COPYLEFT),
    ("EPL-2.0", la.WEAK_COPYLEFT),
    ("CC-BY-SA-4.0", la.WEAK_COPYLEFT),
    ("GPL-3.0-or-later", la.STRONG_COPYLEFT),
    ("GNU General Public License (GPL)", la.STRONG_COPYLEFT),
    ("SSPL-1.0", la.NETWORK_COPYLEFT),
    ("AGPL-3.0", la.NETWORK_COPYLEFT),
    ("GNU Affero General Public License v3", la.NETWORK_COPYLEFT),
    ("Commercial", la.PROPRIETARY),
    ("All Rights Reserved", la.PROPRIETARY),
    ("", la.UNKNOWN),
    ("Some Bespoke License 1.2", la.UNKNOWN),
])
def test_classify_atom(text, expected):
    assert la.classify_atom(text) == expected


def test_lgpl_not_misread_as_gpl():
    # "LESSER" must win over the bare "GPL" substring.
    assert la.classify_atom("LGPL-2.1-or-later") == la.WEAK_COPYLEFT


def test_agpl_not_misread_as_gpl():
    assert la.classify_atom("AGPL-3.0-or-later") == la.NETWORK_COPYLEFT


# --- classify_license: dual / disjunctive expressions ------------------------
def test_dual_with_permissive_option_is_safe():
    tier, meta = la.classify_license("(MIT OR GPL-3.0-or-later)")
    assert tier == la.PERMISSIVE
    assert not meta.get("commercial_option")


def test_tri_license_with_apache_option_is_safe():
    # odfpy ships Apache OR GPL OR LGPL -> elect Apache.
    tier, _ = la.classify_license("Apache-2.0 OR GPL-2.0 OR LGPL-2.1")
    assert tier == la.PERMISSIVE


def test_agpl_or_commercial_stays_network_copyleft():
    # An Artifex dual license: no free permissive escape, only a paid commercial one.
    tier, meta = la.classify_license(
        "Dual Licensed - GNU AFFERO GPL 3.0 or Artifex Commercial License")
    assert tier == la.NETWORK_COPYLEFT
    assert meta.get("commercial_option") is True


def test_gpl_or_lgpl_keeps_strongest_free_option():
    tier, _ = la.classify_license("GPL-2.0 OR LGPL-2.1")
    assert tier == la.STRONG_COPYLEFT


def test_slash_separated_expression():
    assert la.classify_license("MIT / X11")[0] == la.PERMISSIVE


def test_semicolon_multilicense_classifier_list_elects_permissive():
    # odfpy's PyPI classifiers join with "; " and include Apache -> safe.
    odfpy = ("Apache Software License ; GNU General Public License (GPL) ; "
             "GNU Library or Lesser General Public License (LGPL)")
    assert la.classify_license(odfpy)[0] == la.PERMISSIVE


def test_lowercase_or_in_license_name_is_not_split():
    # "GNU Library or Lesser..." must classify as weak copyleft (LGPL), not be
    # split on the lowercase "or".
    assert la.classify_license(
        "GNU Library or Lesser General Public License (LGPL)")[0] == la.WEAK_COPYLEFT


def test_cc_by_non_sharealike_is_permissive():
    assert la.classify_atom("CC-BY-4.0") == la.PERMISSIVE


def test_cc_by_sharealike_is_weak_copyleft():
    assert la.classify_atom("CC-BY-SA-4.0") == la.WEAK_COPYLEFT
    assert la.classify_atom("Creative Commons Attribution-ShareAlike") == la.WEAK_COPYLEFT


def test_python_license_is_permissive():
    assert la.classify_atom("Python-2.0") == la.PERMISSIVE


# --- requirements parsing ----------------------------------------------------
def test_parse_requirements(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "\n".join([
            "# a comment",
            "fastapi>=0.115.0",
            "pyjwt[crypto]>=2.8.0  # inline comment",
            "agpl-lib>=1.24.0",
            "easyeda2kicad==1.0.1",
            "-r other.txt",
            "",
            "Torch>=2.4.0",
        ]),
        encoding="utf-8",
    )
    names = la.parse_requirements(req)
    assert "fastapi" in names
    assert "pyjwt" in names  # extras stripped
    assert "agpl-lib" in names
    assert "torch" in names  # lower-cased
    assert "other.txt" not in names  # -r include skipped


# --- manifest discovery -----------------------------------------------------
def test_requirements_file_names():
    assert la.is_requirements_file(Path("requirements.txt"))
    assert la.is_requirements_file(Path("readback-requirements.txt"))
    assert la.is_requirements_file(Path("readback-test-requirements.txt"))
    assert not la.is_requirements_file(Path("requirements.in"))
    assert not la.is_requirements_file(Path("requirements.json"))


def test_parse_pyproject(tmp_path):
    py = tmp_path / "pyproject.toml"
    py.write_text('[project]\nname = "x"\ndependencies = ["Typer>=0.12", '
                  '"mcp>=1.0"]\n', encoding="utf-8")
    assert la.parse_pyproject(py) == ["typer", "mcp"]


def test_python_dev_only_needs_every_manifest_to_be_dev(tmp_path, monkeypatch):
    monkeypatch.setattr(la, "ROOT", tmp_path)
    (tmp_path / "readback-requirements.txt").write_text("fastapi\n")
    (tmp_path / "readback-test-requirements.txt").write_text("fastapi\npytest\n")
    deps = la.discover_python_deps(sorted(tmp_path.iterdir()))
    assert deps["fastapi"].dev_only is False
    assert deps["pytest"].dev_only is True


def test_tracked_files_skip_datasets_and_fixtures(tmp_path, monkeypatch):
    monkeypatch.setattr(la, "ROOT", tmp_path)
    for rel in ("requirements.txt", "datasets/x/requirements.txt",
                "a/fixtures/package-lock.json", "web/package-lock.json"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("{}")
    rels = {str(p.relative_to(tmp_path)) for p in la.tracked_files()}
    assert rels == {"requirements.txt", "web/package-lock.json"}


# --- npm lockfile parsing ----------------------------------------------------
def test_discover_npm_deps(tmp_path, monkeypatch):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({
        "packages": {
            "": {"name": "root"},
            "node_modules/react": {"version": "18", "license": "MIT"},
            "node_modules/eslint": {"version": "8", "license": "MIT", "dev": True},
            "node_modules/@resvg/resvg-js": {"version": "2", "license": "MPL-2.0"},
            "node_modules/weirdpkg": {"license": {"type": "BSD-3-Clause"}},
            "node_modules/listpkg": {"license": ["MIT", "Apache-2.0"]},
        }
    }), encoding="utf-8")
    monkeypatch.setattr(la, "ROOT", tmp_path)
    deps = la.discover_npm_deps(lock)
    assert deps["react"].dev_only is False
    assert deps["eslint"].dev_only is True
    assert deps["@resvg/resvg-js"].license_text == "MPL-2.0"
    assert deps["weirdpkg"].license_text == "BSD-3-Clause"  # dict form
    assert "OR" in deps["listpkg"].license_text  # list form joined


# --- gate decision logic -----------------------------------------------------
def _dep(name, tier, eco="pypi", dev=False):
    d = la.Dep(name=name, ecosystem=eco, tier=tier, dev_only=dev)
    return d


def test_blocking_when_network_copyleft_not_allowlisted():
    f = la.decide_status(_dep("agpl-lib", la.NETWORK_COPYLEFT), {}, {})
    assert f.status == "blocking"


def test_acknowledged_copyleft_is_tracked_not_blocking():
    ack = {("agpl-lib", "pypi"): {"remediation": "buy commercial license"}}
    f = la.decide_status(_dep("agpl-lib", la.NETWORK_COPYLEFT), {}, ack)
    assert f.status == "acknowledged"
    assert "commercial" in f.note


def test_accepted_exception_for_copyleft():
    acc = {("rollup-plugin-dts", "npm"): {"reason": "dev tool"}}
    f = la.decide_status(
        _dep("rollup-plugin-dts", la.WEAK_COPYLEFT, eco="npm"), acc, {})
    assert f.status == "accepted"


def test_dev_only_strong_copyleft_downgraded_to_review():
    f = la.decide_status(
        _dep("some-build-tool", la.STRONG_COPYLEFT, eco="npm", dev=True), {}, {})
    assert f.status == "review"


def test_weak_copyleft_is_review_by_default():
    f = la.decide_status(_dep("resvg", la.WEAK_COPYLEFT, eco="npm"), {}, {})
    assert f.status == "review"


def test_permissive_is_ok():
    f = la.decide_status(_dep("fastapi", la.PERMISSIVE), {}, {})
    assert f.status == "ok"


def test_unknown_blocks_only_in_strict_mode():
    assert la.decide_status(_dep("mystery", la.UNKNOWN), {}, {}).status == "review"
    assert la.decide_status(
        _dep("mystery", la.UNKNOWN), {}, {}, strict=True).status == "blocking"


def test_accepted_overrides_unknown_when_manually_reviewed():
    # Packages whose SPDX field is missing/legacy auto-resolve to UNKNOWN, but if
    # we manually confirmed the real (permissive) license and recorded it in the
    # allowlist, the gate must honour that — even in strict mode.
    acc = {("webgl-constants", "npm"): {"reason": "MIT confirmed from tarball LICENSE"}}
    f = la.decide_status(_dep("webgl-constants", la.UNKNOWN, eco="npm"), acc, {})
    assert f.status == "accepted"
    assert "MIT" in f.note
    f_strict = la.decide_status(
        _dep("webgl-constants", la.UNKNOWN, eco="npm"), acc, {}, strict=True)
    assert f_strict.status == "accepted"


# --- repo allowlist sanity ---------------------------------------------------
def test_repo_allowlist_is_valid():
    allow = la.load_allowlist()
    assert "accepted" in allow
    assert "acknowledged_copyleft" in allow
    # Every exception says what it is and why it is allowed.
    for e in allow["accepted"]:
        assert e["name"] and e.get("ecosystem") in ("pypi", "npm") and e["reason"]
    for e in allow["acknowledged_copyleft"]:
        assert e["name"] and e.get("ecosystem") in ("pypi", "npm") and e["remediation"]


# --- the push gate: audit what a commit holds, never the working tree ----------
ZERO = "0" * 40


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True,
                          capture_output=True, text=True).stdout.strip()


def _lock(license_text: str) -> str:
    return json.dumps({"packages": {
        "": {"name": "root"},
        "node_modules/somepkg": {"version": "1.0.0", "license": license_text},
    }})


@pytest.fixture
def repo(tmp_path, monkeypatch):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "test")
    (tmp_path / "web").mkdir()
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _commit(repo: Path, license_text: str) -> str:
    (repo / "web" / "package-lock.json").write_text(_lock(license_text))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", license_text)
    return _git(repo, "rev-parse", "HEAD")


def test_a_commit_that_carries_agpl_fails_the_gate(repo):
    bad = _commit(repo, "AGPL-3.0-only")
    assert la.main(["--commit", bad, "--no-network"]) == 1


def test_a_permissive_commit_passes_the_gate(repo):
    good = _commit(repo, "MIT")
    assert la.main(["--commit", good, "--no-network"]) == 0


def test_the_gate_reads_the_commit_not_the_working_tree(repo):
    good = _commit(repo, "MIT")
    # Somebody else's uncommitted edit in a shared checkout is not being pushed.
    (repo / "web" / "package-lock.json").write_text(_lock("AGPL-3.0-only"))
    assert la.main(["--commit", good, "--no-network"]) == 0


def test_a_push_is_refused_when_any_pushed_commit_fails(repo, monkeypatch, capsys):
    good = _commit(repo, "MIT")
    bad = _commit(repo, "GPL-3.0-only")
    monkeypatch.setattr(sys, "stdin", io.StringIO(
        f"refs/heads/a {good} refs/heads/a {ZERO}\n"
        f"refs/heads/b {bad} refs/heads/b {ZERO}\n"))
    assert la.main(["--pre-push", "--no-network"]) == 1
    err = capsys.readouterr().err
    assert "somepkg" in err and bad[:9] in err and "web/package-lock.json" in err


def test_a_clean_push_is_allowed(repo, monkeypatch):
    good = _commit(repo, "MIT")
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"refs/heads/a {good} refs/heads/a {ZERO}\n"))
    assert la.main(["--pre-push", "--no-network"]) == 0


def test_deleting_a_branch_is_not_checked(repo, monkeypatch):
    bad = _commit(repo, "GPL-3.0-only")
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"(delete) {ZERO} refs/heads/old {bad}\n"))
    assert la.main(["--pre-push", "--no-network"]) == 0


def test_an_exception_recorded_in_the_pushed_commit_is_honoured(repo):
    (repo / "tools" / "license_audit").mkdir(parents=True)
    (repo / "tools" / "license_audit" / "license_allowlist.json").write_text(json.dumps({
        "accepted": [{"name": "somepkg", "ecosystem": "npm", "license": "GPL-3.0-only",
                      "reason": "reviewed"}],
        "acknowledged_copyleft": []}))
    bad = _commit(repo, "GPL-3.0-only")
    assert la.main(["--commit", bad, "--no-network"]) == 0


# --- PyPI lookups ---------------------------------------------------------------
class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def _pypi_returns(monkeypatch, info=None, error=None):
    def urlopen(url, timeout):
        if error:
            raise error
        return _FakeResponse(json.dumps({"info": info}).encode())
    monkeypatch.setattr(la.urllib.request, "urlopen", urlopen)


def test_a_vague_declared_license_gives_way_to_the_classifiers(monkeypatch):
    # python-dateutil declares "Dual License"; its classifiers name Apache and BSD.
    _pypi_returns(monkeypatch, {"license": "Dual License", "classifiers": [
        "License :: OSI Approved :: Apache Software License",
        "License :: OSI Approved :: BSD License"]})
    text = la._pypi_license("python-dateutil", {})
    assert la.classify_license(text)[0] == la.PERMISSIVE


def test_a_declared_copyleft_license_is_never_overridden(monkeypatch):
    _pypi_returns(monkeypatch, {"license": "GPL-3.0", "classifiers": [
        "License :: OSI Approved :: MIT License"]})
    assert la.classify_license(la._pypi_license("x", {}))[0] == la.STRONG_COPYLEFT


def test_a_failed_lookup_is_not_cached(monkeypatch):
    cache: dict = {}
    _pypi_returns(monkeypatch, error=la.urllib.error.URLError("offline"))
    assert la._pypi_license("somepkg", cache) == ""
    assert "somepkg" not in cache


# --- more ecosystems ----------------------------------------------------------
UV_LOCK = '''version = 1
[[package]]
name = "myapp"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests" }]
[package.optional-dependencies]
pdf = [{ name = "pypdf" }]
[package.dev-dependencies]
dev = [{ name = "pylint" }]

[[package]]
name = "requests"
version = "2.32.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "certifi" }]

[[package]]
name = "certifi"
version = "2024.1.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pypdf"
version = "4.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pylint"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "astroid" }]

[[package]]
name = "astroid"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }
'''


def test_uv_lock_marks_packages_only_dev_groups_reach(tmp_path):
    lock = tmp_path / "uv.lock"
    lock.write_text(UV_LOCK)
    got = {name: (version, dev) for name, version, dev in la.parse_uv_lock(lock)}
    assert "myapp" not in got                                  # the project itself
    assert got["requests"] == ("2.32.0", False)
    assert got["certifi"] == ("2024.1.1", False)               # transitive, runtime
    assert got["pypdf"] == ("4.0.0", False)                    # an optional extra ships
    assert got["pylint"] == ("3.0.0", True)
    assert got["astroid"] == ("3.0.0", True)                   # reached only via dev


def test_poetry_lock_reads_category_and_groups(tmp_path):
    lock = tmp_path / "poetry.lock"
    lock.write_text('[[package]]\nname = "Flask"\nversion = "3.0.0"\ncategory = "main"\n\n'
                    '[[package]]\nname = "pytest"\nversion = "8.0.0"\ncategory = "dev"\n\n'
                    '[[package]]\nname = "black"\nversion = "24.0.0"\ngroups = ["dev"]\n')
    got = {name: dev for name, _version, dev in la.parse_poetry_lock(lock)}
    assert got == {"flask": False, "pytest": True, "black": True}


def test_yarn_lock_v1_and_berry_names(tmp_path):
    v1 = tmp_path / "v1" / "yarn.lock"
    v1.parent.mkdir()
    v1.write_text('# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n'
                  '  version "7.24.0"\n  resolved "x"\n\nleft-pad@^1.3.0:\n  version "1.3.0"\n')
    berry = tmp_path / "berry" / "yarn.lock"
    berry.parent.mkdir()
    berry.write_text('__metadata:\n  version: 6\n\n"react@npm:^18.0.0":\n  version: 18.2.0\n'
                     '  resolution: "react@npm:18.2.0"\n\n"myapp@workspace:.":\n  version: 0.0.0-use.local\n')
    assert sorted(la.parse_yarn_lock(v1)) == [("@babel/core", "7.24.0"), ("left-pad", "1.3.0")]
    assert la.parse_yarn_lock(berry) == [("react", "18.2.0")]


def test_package_json_without_a_lockfile_is_read(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"dependencies": {"react": "^18.2.0"},
                               "devDependencies": {"eslint": "^8.0.0"}}))
    assert sorted(la.parse_package_json(pkg)) == [("eslint", "^8.0.0", True), ("react", "^18.2.0", False)]


def test_package_json_beside_a_lockfile_is_left_to_the_lockfile(tmp_path, monkeypatch):
    monkeypatch.setattr(la, "ROOT", tmp_path)
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"gpl-thing": "1"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"": {}}}))
    files = sorted(tmp_path.iterdir())
    assert la.audit(use_network=False, root=tmp_path, files=files) == []


def test_pom_reads_scope_and_property_versions(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text('''<project xmlns="http://maven.apache.org/POM/4.0.0">
      <properties><guava.version>33.0.0-jre</guava.version></properties>
      <dependencies>
        <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId>
          <version>${guava.version}</version></dependency>
        <dependency><groupId>junit</groupId><artifactId>junit</artifactId>
          <version>4.13.2</version><scope>test</scope></dependency>
        <dependency><groupId>org.x</groupId><artifactId>y</artifactId></dependency>
      </dependencies></project>''')
    assert sorted(la.parse_pom(pom)) == [("com.google.guava:guava", "33.0.0-jre", False),
                                         ("junit:junit", "4.13.2", True),
                                         ("org.x:y", "", False)]


def test_go_mod_reads_both_require_forms(tmp_path):
    mod = tmp_path / "go.mod"
    mod.write_text("module example.com/app\n\ngo 1.22\n\nrequire github.com/a/b v1.2.3\n\n"
                   "require (\n\tgolang.org/x/text v0.14.0 // indirect\n\tgithub.com/c/d v0.1.0\n)\n")
    assert sorted(la.parse_go_mod(mod)) == [("github.com/a/b", "v1.2.3"), ("github.com/c/d", "v0.1.0"),
                                            ("golang.org/x/text", "v0.14.0")]


def test_cargo_lock_skips_the_crate_itself(tmp_path):
    lock = tmp_path / "Cargo.lock"
    lock.write_text('version = 3\n[[package]]\nname = "myapp"\nversion = "0.1.0"\n\n'
                    '[[package]]\nname = "serde"\nversion = "1.0.0"\n'
                    'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
    assert la.parse_cargo_lock(lock) == [("serde", "1.0.0")]


def _depsdev_serves(monkeypatch, versions: dict, default: dict, calls: list):
    """versions: (system, name, version) -> licenses; default: (system, name) -> version."""
    from urllib.parse import unquote

    def urlopen(url, timeout):
        calls.append(url)
        parts = [unquote(p) for p in url.split("/v3/systems/")[1].split("/")]
        if len(parts) == 5:                                   # .../packages/N/versions/V
            licenses = versions.get((parts[0], parts[2], parts[4]))
            if licenses is None:
                raise la.urllib.error.HTTPError(url, 404, "nf", {}, None)
            return _FakeResponse(json.dumps({"licenses": licenses}).encode())
        version = default.get((parts[0], parts[2]))
        if version is None:
            raise la.urllib.error.HTTPError(url, 404, "nf", {}, None)
        return _FakeResponse(json.dumps({"versions": [
            {"versionKey": {"version": "0.0.1"}, "isDefault": False},
            {"versionKey": {"version": version}, "isDefault": True}]}).encode())
    monkeypatch.setattr(la.urllib.request, "urlopen", urlopen)


def test_depsdev_reads_the_named_version(monkeypatch):
    calls: list = []
    _depsdev_serves(monkeypatch, {("go", "github.com/a/b", "v1.2.3"): ["GPL-3.0-only"]}, {}, calls)
    cache: dict = {}
    assert la.depsdev_license("go", "github.com/a/b", "v1.2.3", cache) == "GPL-3.0-only"
    assert la.depsdev_license("go", "github.com/a/b", "v1.2.3", cache) == "GPL-3.0-only"
    assert len(calls) == 1                                    # the second answer came from the cache


def test_depsdev_falls_back_to_the_default_version_for_a_range(monkeypatch):
    calls: list = []
    _depsdev_serves(monkeypatch, {("npm", "@scope/pkg", "2.0.0"): ["MIT", "Apache-2.0"]},
                    {("npm", "@scope/pkg"): "2.0.0"}, calls)
    text = la.depsdev_license("npm", "@scope/pkg", "^2.0.0", {})
    assert la.classify_license(text)[0] == la.PERMISSIVE
    assert any("%40scope%2Fpkg" in url for url in calls)      # the name is one path segment


def test_depsdev_failure_is_unknown_and_not_cached(monkeypatch):
    _depsdev_serves(monkeypatch, {}, {}, [])
    cache: dict = {}
    assert la.depsdev_license("maven", "org.x:y", "", cache) == ""
    assert cache == {}


def test_a_gpl_go_module_blocks(tmp_path, monkeypatch):
    _depsdev_serves(monkeypatch, {("go", "github.com/a/b", "v1.2.3"): ["GPL-3.0-only"]}, {}, [])
    monkeypatch.setattr(la, "CACHE_PATH", tmp_path / "cache.json")
    (tmp_path / "go.mod").write_text("module m\n\nrequire github.com/a/b v1.2.3\n")
    found = la.audit(use_network=True, root=tmp_path, files=[tmp_path / "go.mod"])
    assert [(f.dep.name, f.dep.ecosystem, f.status) for f in found] == [("github.com/a/b", "go", "blocking")]


def test_files_it_cannot_read_are_named(tmp_path):
    files = [tmp_path / "app" / "build.gradle", tmp_path / "requirements.txt", tmp_path / "pnpm-lock.yaml"]
    assert la.unread_manifests(files, tmp_path) == ["app/build.gradle", "pnpm-lock.yaml"]


def test_a_repo_wide_exception_file_is_honoured(repo):
    (repo / ".github").mkdir()
    (repo / ".github" / "license-allowlist.json").write_text(json.dumps({
        "accepted": [{"name": "somepkg", "ecosystem": "npm", "license": "GPL-3.0-only",
                      "reason": "reviewed"}], "acknowledged_copyleft": []}))
    bad = _commit(repo, "GPL-3.0-only")
    assert la.main(["--commit", bad, "--no-network"]) == 0


def test_the_root_defaults_to_the_repository_being_run_in(repo):
    _commit(repo, "AGPL-3.0-only")
    (repo / "web").joinpath("deeper").mkdir()
    import os
    os.chdir(repo / "web" / "deeper")
    assert la.main(["--no-network", "--report", str(repo / "r.md")]) == 1


# --- classifier edge cases found on real repositories ---------------------------
@pytest.mark.parametrize("text,expected", [
    ("MIT AND (GPL-2.0-or-later OR AFL-2.1)", la.PERMISSIVE),      # dbus-python: elect AFL
    ("OFL-1.1", la.WEAK_COPYLEFT),                                  # fonts
    ("SEE LICENSE AT https://gsap.com/standard-license", la.PROPRIETARY),
    ("Standard 'no charge' license: https://gsap.com/standard-license", la.PROPRIETARY),
    ("PolyForm-Shield-1.0.0", la.PROPRIETARY),
    ("BUSL-1.1", la.PROPRIETARY),
    ("Apache-2.0 with Commons Clause", la.PROPRIETARY),
    ("LicenseRef-NVIDIA-Proprietary", la.PROPRIETARY),
    ("Use is permitted for evaluation only", la.UNKNOWN),           # "permitted" is not "MIT"
])
def test_real_world_license_strings(text, expected):
    assert la.classify_license(text)[0] == expected


def test_an_unresolved_pypi_license_falls_back_to_depsdev(monkeypatch, tmp_path):
    monkeypatch.setattr(la, "CACHE_PATH", tmp_path / "cache.json")
    monkeypatch.setattr(la, "_installed_license", lambda name: "")
    monkeypatch.setattr(la, "_pypi_license", lambda name, cache, timeout=12.0: "UNKNOWN")
    _depsdev_serves(monkeypatch, {("pypi", "peewee", "3.17.0"): ["MIT"]}, {}, [])
    (tmp_path / "requirements.txt").write_text("peewee==3.17.0\n")
    found = la.audit(use_network=True, root=tmp_path, files=[tmp_path / "requirements.txt"])
    assert [(f.dep.name, f.dep.tier) for f in found] == [("peewee", la.PERMISSIVE)]


def test_a_pasted_license_text_gives_way_to_the_classifiers():
    # scipy's PyPI "license" is its whole LICENSE.txt, bundled-library notices included.
    text = ("Copyright (c) 2001-2002 Enthought, Inc. All rights reserved.\n"
            "Redistribution and use in source and binary forms ...\n"
            "libgfortran is licensed under the GNU General Public License v3 with the "
            "GCC Runtime Library Exception; see https://gcc.gnu.org/\n")
    picked = la._pick_license("", text, ["BSD License"])
    assert la.classify_license(picked)[0] == la.PERMISSIVE


def test_a_pasted_license_text_without_classifiers_is_read_by_its_title():
    text = ("GNU LESSER GENERAL PUBLIC LICENSE\n         Version 2.1, February 1999\n"
            "... a modified version of the GNU General Public License ...\n")
    assert la.classify_license(la._pick_license("", text, []))[0] == la.WEAK_COPYLEFT


def test_all_rights_reserved_in_a_permissive_notice_stays_permissive():
    assert la.classify_license(
        "MIT License. Copyright © 2020-2021 Apple Inc. All rights reserved.")[0] == la.PERMISSIVE
