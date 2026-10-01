#!/usr/bin/env python3
"""Open-source license audit: the license-gate checker.

Finds dependencies whose license could force disclosure of our own source:
strong copyleft (GPL, OSL, EUPL...) and network copyleft (AGPL, SSPL).
Standard library only, so it runs anywhere Python 3.11+ does.

What it does
------------
1. Finds the dependency files git tracks in the repository it is run in,
   skipping datasets, fixtures and installed-package trees:
   - Python: ``*requirements*.txt`` (files named test/dev count as dev-only),
     ``pyproject.toml``, ``uv.lock`` and ``poetry.lock`` (dev groups traced).
   - npm: ``package-lock.json``, ``yarn.lock``, and ``package.json`` where
     neither lockfile sits beside it.
   - Maven ``pom.xml``, Go ``go.mod``, Rust ``Cargo.lock``.
   Files it cannot read yet (Gradle, pnpm, Bundler, Composer...) are named in
   the report rather than passed over silently.
2. Resolves each dependency's declared license:
   - npm lockfiles record it; read it straight from there.
   - Python: installed distribution metadata, else the PyPI JSON API.
   - Everything else, and anything still unknown: deps.dev, Google's Open
     Source Insights API. Lookups are parallel and cached on disk.
3. Classifies each license into a risk tier (permissive / weak-copyleft /
   strong-copyleft / network-copyleft / public-domain / proprietary / unknown),
   resolving dual ("A OR B") expressions to the option you would actually elect.
4. Emits a Markdown report and exits non-zero when a *blocking* dependency
   (strong or network copyleft, runtime, not a reviewed exception) is found,
   so it can gate CI and refuse a push.

``--commit`` and ``--pre-push`` audit what a COMMIT tracks, read straight from
git, never the working tree: in a checkout several people edit at once, the
files on disk are not what is being pushed.

A repository records reviewed exceptions in ``.github/license-allowlist.json``
(see :data:`ALLOWLIST_LOCATIONS`); a commit is judged by its own copy.

Usage
-----
    python3 license_audit.py                  # audit this repository, Markdown report
    python3 license_audit.py --root PATH      # audit another checkout
    python3 license_audit.py --report out.md --json out.json
    python3 license_audit.py --no-network     # offline (installed metadata only)
    python3 license_audit.py --strict         # also fail on unresolved licenses
    python3 license_audit.py --commit HEAD    # audit one commit
    python3 license_audit.py --pre-push       # git pre-push hook mode (refs on stdin)
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

#: The repository being audited; None means the one the tool is run in.
ROOT: Path | None = None
ALLOWLIST_PATH = Path(__file__).resolve().parent / "license_allowlist.json"
CACHE_PATH = Path(__file__).resolve().parent / ".license-cache.json"

# --- Risk tiers, least to most restrictive for "Company Code" -----------------
PERMISSIVE = "permissive"
PUBLIC_DOMAIN = "public-domain"
WEAK_COPYLEFT = "weak-copyleft"
STRONG_COPYLEFT = "strong-copyleft"
NETWORK_COPYLEFT = "network-copyleft"
PROPRIETARY = "proprietary"
UNKNOWN = "unknown"

# Tiers that can force disclosure / licensing of proprietary source.
BLOCKING_TIERS = {STRONG_COPYLEFT, NETWORK_COPYLEFT}
# Tiers that warrant human review but do not, by themselves, infect your code.
REVIEW_TIERS = {WEAK_COPYLEFT, PROPRIETARY, UNKNOWN}

_SEVERITY = {
    PUBLIC_DOMAIN: 0,
    PERMISSIVE: 1,
    WEAK_COPYLEFT: 2,
    PROPRIETARY: 3,
    UNKNOWN: 4,
    STRONG_COPYLEFT: 5,
    NETWORK_COPYLEFT: 6,
}


def _norm(text: str) -> str:
    return re.sub(r"[\s_]+", " ", (text or "")).strip().upper()


def classify_atom(license_text: str) -> str:
    """Classify a single (non-disjunctive) license string into a risk tier."""
    t = _norm(license_text)
    if not t:
        return UNKNOWN
    # Order matters: check the most specific / most restrictive markers first.
    if "AFFERO" in t or re.search(r"\bAGPL", t):
        return NETWORK_COPYLEFT
    if "SSPL" in t or "SERVER SIDE PUBLIC LICENSE" in t:
        return NETWORK_COPYLEFT
    if "LGPL" in t or "LESSER GENERAL PUBLIC" in t or "LIBRARY GENERAL PUBLIC" in t:
        return WEAK_COPYLEFT
    if re.search(r"\bGPL", t) or "GENERAL PUBLIC LICENSE" in t:
        return STRONG_COPYLEFT
    if any(k in t for k in ("MOZILLA PUBLIC", "MPL", "ECLIPSE PUBLIC", "EPL",
                            "CDDL", "COMMON DEVELOPMENT", "CC BY SA", "CC-BY-SA",
                            "SHAREALIKE", "SHARE ALIKE", "OFL-", "OPEN FONT")):
        # OFL keeps a modified FONT under the OFL; it asks nothing of our code.
        return WEAK_COPYLEFT
    if any(k in t for k in ("OSL", "OPEN SOFTWARE LICENSE", "EUPL", "CPAL",
                            "RECIPROCAL", "RPL", "QUET")):
        return STRONG_COPYLEFT
    if any(k in t for k in ("CC0", "PUBLIC DOMAIN", "UNLICENSE", "WTFPL")):
        return PUBLIC_DOMAIN
    # Source-available and custom licenses, checked before the permissive names
    # so that "Apache-2.0 with Commons Clause" is not read as Apache.
    if any(k in t for k in ("PROPRIETARY", "SEE LICENSE", "NO CHARGE", "POLYFORM", "BUSL",
                            "BUSINESS SOURCE", "ELASTIC LICENSE", "COMMONS CLAUSE",
                            "LICENSEREF-")):
        return PROPRIETARY
    # Short names match whole words only: "permitted" is not MIT.
    if re.search(r"\b(MIT|BSD|ISC|PSF|ZPL|NCSA|0BSD)\b", t) or any(
            k in t for k in ("APACHE", "ZLIB", "PYTHON SOFTWARE FOUNDATION", "PYTHON",
                             "BOOST", "BLUEOAK", "POSTGRESQL", "CC BY", "CC-BY",
                             "AFL-", "ACADEMIC FREE")):
        # CC-BY (attribution-only, non-ShareAlike) imposes attribution, not
        # source disclosure — the ShareAlike variant is caught above as weak.
        return PERMISSIVE
    # Last, because "All rights reserved" ends many an ordinary BSD or MIT notice.
    if any(k in t for k in ("COMMERCIAL", "ALL RIGHTS RESERVED")):
        return PROPRIETARY
    return UNKNOWN


# Split disjunctive/multi-license expressions on explicit delimiters only.
# "OR" is matched case-SENSITIVELY (SPDX uses uppercase "OR") so we don't break
# license *names* that contain lowercase "or" — e.g. "GNU Library or Lesser
# General Public License". Semicolons join PyPI's multi-license classifier lists
# (treated as dual licensing you may elect between).
_SPLIT_RE = re.compile(r"\s+OR\s+|\s*[;/|]\s*")


def classify_license(license_text: str) -> tuple[str, dict]:
    """Classify a (possibly dual / multi-) license expression.

    For "A OR B" (or a semicolon-joined classifier list) you may elect whichever
    option you like, so the effective tier is the *least* restrictive
    freely-electable option. Exception: if the only non-copyleft alternative is a
    paid commercial/proprietary license (e.g. an Artifex "AGPL OR Artifex
    commercial"), there is no free permissive escape, so we keep the copyleft
    tier and flag that a commercial option exists.
    """
    # A URL names where a license lives, not which one; its slashes are not separators.
    text = re.sub(r"https?://\S+", "", license_text or "").strip()
    meta: dict = {}
    if not text:
        return UNKNOWN, meta

    # A paid commercial/proprietary alternative may sit beside copyleft even when
    # it is not split out (e.g. an Artifex library's lowercase "AGPL ... or Artifex
    # commercial"); detect it from the full text.
    norm = _norm(text)
    has_commercial = any(k in norm for k in ("COMMERCIAL", "PROPRIETARY", "ARTIFEX"))

    atoms = [a for a in _SPLIT_RE.split(text) if a.strip()]
    if len(atoms) <= 1:
        tier = classify_atom(text)
    else:
        tiers = [classify_atom(a) for a in atoms]
        if PROPRIETARY in tiers:
            has_commercial = True
        if any(t in (PERMISSIVE, PUBLIC_DOMAIN) for t in tiers):
            # A freely-electable permissive/public-domain option exists -> take it.
            electable = [t for t in tiers if t != PROPRIETARY] or tiers
            tier = min(electable, key=lambda t: _SEVERITY[t])
        else:
            # Keep the most restrictive *free* option (the real obligation).
            free_options = [t for t in tiers if t not in (PROPRIETARY, UNKNOWN)]
            tier = max(free_options or tiers, key=lambda t: _SEVERITY[t])

    if tier in BLOCKING_TIERS and has_commercial:
        meta["commercial_option"] = True
    return tier, meta


# --- Dependency discovery -----------------------------------------------------
@dataclass
class Dep:
    name: str
    ecosystem: str  # "pypi" | "npm" | "go" | "maven" | "cargo"
    license_text: str = ""
    tier: str = UNKNOWN
    dev_only: bool = False
    sources: set[str] = field(default_factory=set)
    meta: dict = field(default_factory=dict)
    version: str = ""


_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def parse_requirements(path: Path) -> list[str]:
    names: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-r", "-e", "--", "git+", "http")):
            continue
        m = _REQ_LINE.match(line)
        if m:
            names.append(m.group(1).lower())
    return names


_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;#,]+)")


def requirement_pins(path: Path) -> dict[str, str]:
    """``name -> version`` for every exactly pinned (``==``) line of a requirements file."""
    pins: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = _PIN.match(line)
        if m:
            pins[m.group(1).lower()] = m.group(2)
    return pins


# Datasets, fixtures and third-party trees whose manifests are not ours.
_SKIP_PARTS = {"data", "datasets", "fixtures", "node_modules", ".venv",
               "site-packages"}
_DEV_FILE = re.compile(r"(^|[-_.])(test|tests|dev)([-_.]|$)")

#: Files read here, by exact name (requirements files are matched by pattern).
MANIFEST_NAMES = {"pyproject.toml", "uv.lock", "poetry.lock", "package-lock.json",
                  "yarn.lock", "package.json", "pom.xml", "go.mod", "Cargo.lock"}
#: Dependency files this tool cannot read yet. Named in the report, never guessed at.
UNREAD_NAMES = {"build.gradle", "build.gradle.kts", "pnpm-lock.yaml", "Gemfile.lock",
                "composer.lock", "Pipfile.lock", "packages.lock.json", "mix.lock",
                "Podfile.lock", "Package.resolved"}
#: Where a repository keeps its reviewed exceptions; the first one present wins.
ALLOWLIST_LOCATIONS = (".github/license-allowlist.json", "license_allowlist.json",
                       "tools/license_audit/license_allowlist.json")
#: npm lockfiles this tool reads; a package.json beside one is left to it.
_NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock")


def default_root() -> Path:
    """The top of the git repository the tool is run in, else the current directory."""
    try:
        top = subprocess.run(["git", "rev-parse", "--show-toplevel"], check=True,
                             capture_output=True, text=True).stdout.strip()
        return Path(top)
    except (OSError, subprocess.CalledProcessError):
        return Path.cwd()


def _root(root: Path | None) -> Path:
    return root or ROOT or default_root()


def tracked_files(root: Path | None = None) -> list[Path]:
    """Every file git tracks under ``root`` (falls back to a walk outside git)."""
    root = _root(root)
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True,
                             capture_output=True).stdout.decode("utf-8")
        paths = [root / p for p in out.split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        paths = [p for p in root.rglob("*") if p.is_file()]
    return sorted(p for p in paths
                  if not _SKIP_PARTS.intersection(p.relative_to(root).parts))


def is_requirements_file(path: Path) -> bool:
    return path.suffix == ".txt" and "requirements" in path.name


def is_manifest(path: Path) -> bool:
    return is_requirements_file(path) or path.name in MANIFEST_NAMES


def unread_manifests(files: Iterable[Path], root: Path) -> list[str]:
    """The dependency files present that this tool cannot read, relative to ``root``."""
    return sorted(str(p.relative_to(root)) for p in files if p.name in UNREAD_NAMES)


def _git(*args: str) -> bytes:
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout


def extract_commit(commit: str, into: Path) -> list[Path]:
    """Write the dependency files ``commit`` tracks under ``into``, with its allowlist.

    Read from git's object store in the current repository, so the result is
    exactly what that commit holds whatever the working tree looks like.
    Returns the dependency files written, readable or not.
    """
    written: list[Path] = []
    names = _git("ls-tree", "-r", "-z", "--name-only", commit).decode("utf-8").split("\0")
    for name in names:
        path = Path(name)
        if not name or _SKIP_PARTS.intersection(path.parts):
            continue
        wanted = is_manifest(path) or path.name in UNREAD_NAMES
        if wanted or name in ALLOWLIST_LOCATIONS:
            target = into / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(_git("show", f"{commit}:{name}"))
            if wanted:
                written.append(target)
    return sorted(written)


def parse_pyproject(path: Path) -> list[str]:
    project = tomllib.loads(path.read_text(encoding="utf-8")).get("project", {})
    names: list[str] = []
    for spec in project.get("dependencies", []):
        m = _REQ_LINE.match(spec)
        if m:
            names.append(m.group(1).lower())
    return names


def _local_source(source) -> bool:
    """A uv.lock source that is this repository's own code rather than a published package."""
    return isinstance(source, dict) and bool({"editable", "virtual", "directory", "path"} & source.keys())


def parse_uv_lock(path: Path) -> list[tuple[str, str, bool]]:
    """``(name, version, dev_only)`` for every published package in a uv.lock.

    Dev-only means reachable only through the project's dev dependency groups.
    The project's own extras ship, so they count as runtime; so does anything
    the graph cannot place (a platform-specific branch, say), to stay on the
    side of checking too much.
    """
    packages = tomllib.loads(path.read_text(encoding="utf-8")).get("package", [])
    by_name = {p["name"].lower(): p for p in packages}

    def edges(entries) -> list[tuple[str, tuple]]:
        return [(d["name"].lower(), tuple(d.get("extra", ()))) for d in entries or () if "name" in d]

    runtime_start: list = []
    dev_start: list = []
    for root in (p for p in packages if _local_source(p.get("source"))):
        runtime_start += edges(root.get("dependencies"))
        for group in (root.get("optional-dependencies") or {}).values():
            runtime_start += edges(group)
        for group in (root.get("dev-dependencies") or {}).values():
            dev_start += edges(group)

    def reach(start: list) -> set[str]:
        seen: set[tuple[str, str]] = set()
        names: set[str] = set()
        stack = [(name, "", extras) for name, extras in start]
        while stack:
            name, extra, extras = stack.pop()
            package = by_name.get(name)
            if package is None or (name, extra) in seen:
                continue
            seen.add((name, extra))
            names.add(name)
            optional = package.get("optional-dependencies") or {}
            more = edges(package.get("dependencies")) if not extra else edges(optional.get(extra))
            stack += [(n, "", e) for n, e in more]
            stack += [(name, e, ()) for e in extras]
        return names

    runtime = reach(runtime_start)
    dev = reach(dev_start) - runtime
    return [(p["name"].lower(), str(p.get("version", "")), p["name"].lower() in dev)
            for p in packages if not _local_source(p.get("source"))]


def parse_poetry_lock(path: Path) -> list[tuple[str, str, bool]]:
    """``(name, version, dev_only)`` from a poetry.lock (``category`` or ``groups``)."""
    out = []
    for p in tomllib.loads(path.read_text(encoding="utf-8")).get("package", []):
        groups = p.get("groups")
        dev = p.get("category") == "dev" or (isinstance(groups, list) and "main" not in groups)
        out.append((p["name"].lower(), str(p.get("version", "")), dev))
    return out


_YARN_LOCAL = ("@workspace:", "@link:", "@portal:", "@file:", "@patch:")


def _npm_name(spec: str) -> str:
    spec = spec.strip().strip('"')
    if spec.startswith("@"):
        return "@" + spec[1:].split("@", 1)[0]
    return spec.split("@", 1)[0]


def parse_yarn_lock(path: Path) -> list[tuple[str, str]]:
    """``(name, version)`` for every package in a yarn.lock, classic or berry."""
    out: set[tuple[str, str]] = set()
    name = ""
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line and not line[0].isspace() and not line.startswith("#") and line.rstrip().endswith(":"):
            spec = line.rstrip()[:-1].split(",")[0].strip().strip('"')
            local = any(marker in spec for marker in _YARN_LOCAL) or spec == "__metadata"
            name = "" if local else _npm_name(spec)
            continue
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', line)
        if name and m:
            out.add((name, m.group(1)))
            name = ""
    return sorted(out)


def parse_package_json(path: Path) -> list[tuple[str, str, bool]]:
    """``(name, version range, dev_only)`` for a package.json read without a lockfile."""
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for key, dev in (("dependencies", False), ("optionalDependencies", False),
                     ("devDependencies", True)):
        for name, spec in (data.get(key) or {}).items():
            out.append((name, str(spec), dev))
    return out


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_pom(path: Path) -> list[tuple[str, str, bool]]:
    """``(group:artifact, version, dev_only)`` for a Maven pom.xml's direct dependencies."""
    import xml.etree.ElementTree as ET

    project = ET.parse(path).getroot()
    children = {_strip_ns(c.tag): c for c in project}
    props = {_strip_ns(c.tag): (c.text or "").strip() for c in children.get("properties", ())}
    props.setdefault("project.version", (children["version"].text or "").strip()
                     if "version" in children else "")

    def value(text: str) -> str:
        m = re.fullmatch(r"\$\{([^}]+)\}", text)
        return props.get(m.group(1), "") if m else text

    out = []
    for dep in children.get("dependencies", ()):
        fields = {_strip_ns(c.tag): (c.text or "").strip() for c in dep}
        if not fields.get("groupId") or not fields.get("artifactId"):
            continue
        dev = fields.get("scope") in ("test", "provided")
        out.append((f"{fields['groupId']}:{fields['artifactId']}", value(fields.get("version", "")), dev))
    return out


def parse_go_mod(path: Path) -> list[tuple[str, str]]:
    """``(module, version)`` for every requirement in a go.mod, indirect ones included."""
    out = []
    in_block = False
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
        elif in_block and line == ")":
            in_block = False
        elif in_block and line:
            parts = line.split()
            if len(parts) >= 2:
                out.append((parts[0], parts[1]))
        elif line.startswith("require "):
            parts = line.split()[1:]
            if len(parts) >= 2:
                out.append((parts[0], parts[1]))
    return out


def parse_cargo_lock(path: Path) -> list[tuple[str, str]]:
    """``(name, version)`` for every published crate in a Cargo.lock."""
    return [(p["name"], str(p.get("version", "")))
            for p in tomllib.loads(path.read_text(encoding="utf-8")).get("package", [])
            if p.get("source")]


def _lock_license(meta: dict) -> str:
    lic = meta.get("license", "")
    if isinstance(lic, dict):
        return str(lic.get("type", ""))
    if isinstance(lic, list):
        return " OR ".join(str(x) for x in lic)
    return str(lic or "")


def discover_npm_deps(lock_path: Path, root: Path | None = None) -> dict[str, Dep]:
    deps: dict[str, Dep] = {}
    data = json.loads(lock_path.read_text(encoding="utf-8"))
    rel = str(lock_path.relative_to(_root(root)))
    for pkg_path, meta in data.get("packages", {}).items():
        if not pkg_path or "node_modules" not in pkg_path:
            continue  # root project entry
        name = pkg_path.split("node_modules/")[-1]
        dep = deps.setdefault(name, Dep(name=name, ecosystem="npm", dev_only=True))
        dep.sources.add(rel)
        dep.license_text = dep.license_text or _lock_license(meta)
        dep.version = dep.version or str(meta.get("version", ""))
        # A package is runtime if ANY occurrence is non-dev.
        if not meta.get("dev", False):
            dep.dev_only = False
    return deps


def discover_python_deps(files: list[Path], root: Path | None = None) -> dict[str, Dep]:
    root = _root(root)
    deps: dict[str, Dep] = {}
    for path in files:
        if is_requirements_file(path):
            pins = requirement_pins(path)
            dev_file = bool(_DEV_FILE.search(path.stem))
            entries = [(name, pins.get(name, ""), dev_file) for name in parse_requirements(path)]
        elif path.name == "pyproject.toml":
            dev_file = bool(_DEV_FILE.search(path.stem))
            entries = [(name, "", dev_file) for name in parse_pyproject(path)]
        elif path.name == "uv.lock":
            entries = parse_uv_lock(path)
        elif path.name == "poetry.lock":
            entries = parse_poetry_lock(path)
        else:
            continue
        for name, version, dev in entries:
            dep = deps.setdefault(name, Dep(name=name, ecosystem="pypi", dev_only=True))
            dep.sources.add(str(path.relative_to(root)))
            dep.version = dep.version or version
            # A package is runtime if ANY manifest that lists it is runtime.
            if not dev:
                dep.dev_only = False
    return deps


def discover_other_deps(files: list[Path], root: Path | None = None) -> list[Dep]:
    """npm without package-lock.json, Maven, Go and Cargo: names and versions only.

    Their licenses are looked up afterwards (:func:`resolve_depsdev`), because
    none of these files records one.
    """
    root = _root(root)
    out: list[Dep] = []
    for path in files:
        rel = str(path.relative_to(root))
        if path.name == "yarn.lock":
            entries = [("npm", n, v, False) for n, v in parse_yarn_lock(path)]
        elif path.name == "package.json":
            if any((path.parent / lock).exists() for lock in _NPM_LOCKS):
                continue
            entries = [("npm", n, v, d) for n, v, d in parse_package_json(path)]
        elif path.name == "pom.xml":
            entries = [("maven", n, v, d) for n, v, d in parse_pom(path)]
        elif path.name == "go.mod":
            entries = [("go", n, v, False) for n, v in parse_go_mod(path)]
        elif path.name == "Cargo.lock":
            entries = [("cargo", n, v, False) for n, v in parse_cargo_lock(path)]
        else:
            continue
        out += [Dep(name=n, ecosystem=e, version=v, dev_only=d, sources={rel}) for e, n, v, d in entries]
    return out


# --- Python license resolution ------------------------------------------------
def _installed_license(name: str) -> str:
    try:
        from importlib import metadata
    except Exception:  # pragma: no cover - very old Python
        return ""
    try:
        md = metadata.metadata(name)
    except metadata.PackageNotFoundError:
        return ""
    classifiers = [c.split("::")[-1].strip()
                   for c in md.get_all("Classifier") or [] if c.startswith("License")]
    return _pick_license((md.get("License-Expression") or "").strip(),
                         (md.get("License") or "").strip(), classifiers)


def _load_cache() -> dict:
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text())
        except Exception:
            return {}
    return {}


def _pick_license(expression: str, declared: str, classifiers: list[str]) -> str:
    """The most informative of PyPI's three license fields.

    The SPDX expression if there is one. Otherwise the free-text field, unless
    it names no license the classifier knows ("Dual License"), when the
    classifiers win. A declared copyleft license is never overridden.
    """
    if expression:
        return expression
    joined = " ; ".join(classifiers)
    if "\n" in declared.strip() or len(declared) > 200:
        # A whole license text pasted into the field (scipy pastes its LICENSE.txt,
        # bundled-library notices and all). The classifiers say it better; failing
        # them, the text's own title line does.
        if joined:
            return joined
        declared = next((line.strip() for line in declared.splitlines() if line.strip()), "")
    if declared and (classify_license(declared)[0] != UNKNOWN or not joined):
        return declared
    return joined or declared


def _pypi_license(name: str, cache: dict, timeout: float = 12.0) -> str:
    fields = cache.get(name)
    if not isinstance(fields, dict):            # absent, or an old-format entry
        url = f"https://pypi.org/pypi/{name}/json"
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                info = json.loads(resp.read().decode("utf-8")).get("info", {})
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
            return ""                           # not cached: a network blip must not stick
        fields = {
            "expression": (info.get("license_expression") or "").strip(),
            "license": (info.get("license") or "").strip(),
            "classifiers": [c.split("::")[-1].strip()
                            for c in info.get("classifiers", []) if "License" in c],
        }
        cache[name] = fields
    return _pick_license(fields["expression"], fields["license"], fields["classifiers"])


#: Parallel lookups: a lockfile can name a thousand packages, and each is one request.
LOOKUP_THREADS = 16


def _save_cache(cache: dict) -> None:
    try:
        CACHE_PATH.write_text(json.dumps(cache, indent=2, sort_keys=True))
    except OSError:
        pass


def resolve_python_licenses(deps: dict[str, Dep], use_network: bool) -> None:
    for dep in deps.values():
        dep.license_text = _installed_license(dep.name)
    pending = [d for d in deps.values() if not d.license_text]
    if not pending or not use_network:
        return
    cache = _load_cache()
    before = json.dumps(cache, sort_keys=True)
    with ThreadPoolExecutor(LOOKUP_THREADS) as pool:
        texts = list(pool.map(lambda d: _pypi_license(d.name, cache), pending))
    for dep, text in zip(pending, texts):
        dep.license_text = text
    if json.dumps(cache, sort_keys=True) != before:
        _save_cache(cache)


# --- Other ecosystems: deps.dev ------------------------------------------------
#: Google's Open Source Insights API: one license record per published version,
#: for npm, Go, Maven, Cargo and more. Free, no key.
DEPSDEV = "https://api.deps.dev/v3/systems"
_EXACT_VERSION = re.compile(r"v?\d+(\.\d+)*([-+.][0-9A-Za-z.+-]*)?")


def _depsdev_get(path: str, timeout: float) -> dict:
    with urllib.request.urlopen(f"{DEPSDEV}/{path}", timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def depsdev_license(system: str, name: str, version: str, cache: dict,
                    timeout: float = 12.0) -> str:
    """The license deps.dev records for ``name`` in ``system``; ``""`` if unknown.

    Tries the exact version when there is one, else (or if deps.dev has never
    seen it) the version it marks as the package's default. Licenses are
    cached per package, as they are for PyPI; a failure is never cached.
    """
    key = f"{system}:{name}"
    if isinstance(cache.get(key), str):
        return cache[key]
    package = f"{system}/packages/{urllib.parse.quote(name, safe='')}"
    candidates = [version] if _EXACT_VERSION.fullmatch(version or "") else []
    try:
        data: dict = {}
        for candidate in candidates:
            try:
                data = _depsdev_get(f"{package}/versions/{urllib.parse.quote(candidate, safe='')}", timeout)
                break
            except urllib.error.HTTPError:
                data = {}
        if not data:
            versions = _depsdev_get(package, timeout).get("versions", [])
            default = next((v["versionKey"]["version"] for v in versions if v.get("isDefault")), "")
            if not default:
                return ""
            data = _depsdev_get(f"{package}/versions/{urllib.parse.quote(default, safe='')}", timeout)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError):
        return ""
    licenses = [lic for lic in data.get("licenses", []) if lic and lic.lower() != "non-standard"]
    text = " AND ".join(licenses)
    if text:
        cache[key] = text
    return text


def resolve_depsdev(deps: Iterable[Dep], use_network: bool) -> None:
    """Fill in licenses nothing else recorded: every ecosystem but PyPI, and any
    PyPI package whose metadata named no license the classifier knows."""
    pending = [d for d in deps if not d.license_text
               or (d.ecosystem == "pypi" and classify_license(d.license_text)[0] == UNKNOWN)]
    if not pending or not use_network:
        return
    cache = _load_cache()
    before = json.dumps(cache, sort_keys=True)
    with ThreadPoolExecutor(LOOKUP_THREADS) as pool:
        texts = list(pool.map(lambda d: depsdev_license(d.ecosystem, d.name, d.version, cache), pending))
    for dep, text in zip(pending, texts):
        dep.license_text = text or dep.license_text
    if json.dumps(cache, sort_keys=True) != before:
        _save_cache(cache)


# --- Allowlist ----------------------------------------------------------------
def load_allowlist(path: Path | None = None) -> dict:
    path = path or ALLOWLIST_PATH
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"accepted": [], "acknowledged_copyleft": []}


def _index(entries: Iterable[dict]) -> dict[tuple[str, str], dict]:
    out: dict[tuple[str, str], dict] = {}
    for e in entries:
        out[(e["name"].lower(), e.get("ecosystem", "pypi"))] = e
    return out


# --- Audit --------------------------------------------------------------------
@dataclass
class Finding:
    dep: Dep
    status: str  # "blocking" | "acknowledged" | "review" | "accepted" | "ok"
    note: str = ""


def decide_status(dep: Dep, accepted: dict, acknowledged: dict,
                  strict: bool = False) -> Finding:
    """Pure mapping from a classified dependency to a gate finding."""
    key = (dep.name.lower(), dep.ecosystem)
    ack = acknowledged.get(key)
    acc = accepted.get(key)
    if dep.tier in BLOCKING_TIERS:
        if ack:
            return Finding(dep, "acknowledged", ack.get("remediation", ""))
        if acc:
            return Finding(dep, "accepted", acc.get("reason", ""))
        if dep.dev_only:
            return Finding(dep, "review", "dev-only build tool (not distributed)")
        return Finding(dep, "blocking")
    if dep.tier in (WEAK_COPYLEFT, PROPRIETARY):
        if acc:
            return Finding(dep, "accepted", acc.get("reason", ""))
        return Finding(dep, "review")
    if dep.tier == UNKNOWN:
        if acc:
            # Manually reviewed: auto-detection failed (missing/legacy SPDX field)
            # but the real license was confirmed and recorded in the allowlist.
            return Finding(dep, "accepted", acc.get("reason", ""))
        return Finding(dep, "blocking" if strict else "review",
                       "license metadata unresolved")
    return Finding(dep, "ok")


def _merge(deps: dict[tuple[str, str], Dep], dep: Dep) -> None:
    key = (dep.name.lower(), dep.ecosystem)
    have = deps.get(key)
    if have is None:
        deps[key] = dep
        return
    have.sources |= dep.sources
    have.dev_only = have.dev_only and dep.dev_only
    have.license_text = have.license_text or dep.license_text
    have.version = have.version or dep.version


def audit(use_network: bool = True, strict: bool = False, root: Path | None = None,
          files: list[Path] | None = None, unread: list[str] | None = None) -> list[Finding]:
    """Classify every dependency the dependency files under ``root`` declare.

    ``files`` names those files outright; left out, they are the ones git
    tracks under ``root``. A repository's own allowlist (the first of
    :data:`ALLOWLIST_LOCATIONS` present) wins over this tool's. Pass a list as
    ``unread`` to collect the files present that could not be read.
    """
    root = _root(root)
    files = tracked_files(root) if files is None else files
    readable: list[Path] = []
    for path in files:
        if is_manifest(path):
            readable.append(path)
        elif path.name in UNREAD_NAMES and unread is not None:
            unread.append(str(path.relative_to(root)))

    deps: dict[tuple[str, str], Dep] = {}
    for path in readable:
        try:
            found: list[Dep] = (
                list(discover_python_deps([path], root).values())
                + (list(discover_npm_deps(path, root).values()) if path.name == "package-lock.json" else [])
                + discover_other_deps([path], root))
        except (ValueError, KeyError, TypeError, OSError, SyntaxError) as exc:
            # A file that will not parse is reported, not guessed at, and never crashes a push.
            if unread is not None:
                unread.append(f"{path.relative_to(root)} (could not parse: {type(exc).__name__})")
            continue
        for dep in found:
            _merge(deps, dep)

    resolve_python_licenses(
        {k[0]: v for k, v in deps.items() if v.ecosystem == "pypi"}, use_network
    )
    resolve_depsdev(deps.values(), use_network)
    for dep in deps.values():
        dep.tier, dep.meta = classify_license(dep.license_text)

    own = next((root / loc for loc in ALLOWLIST_LOCATIONS if (root / loc).exists()), None)
    allow = load_allowlist(own)
    accepted = _index(allow.get("accepted", []))
    acknowledged = _index(allow.get("acknowledged_copyleft", []))

    return [decide_status(dep, accepted, acknowledged, strict)
            for _, dep in sorted(deps.items())]


# --- Reporting ----------------------------------------------------------------
_TIER_LABEL = {
    PERMISSIVE: "Permissive",
    PUBLIC_DOMAIN: "Public domain",
    WEAK_COPYLEFT: "Weak / file-level copyleft",
    STRONG_COPYLEFT: "Strong copyleft",
    NETWORK_COPYLEFT: "Network copyleft (AGPL/SSPL)",
    PROPRIETARY: "Proprietary / commercial",
    UNKNOWN: "Unresolved",
}


def _row(f: Finding) -> str:
    flags = " ⚠️ commercial license available" if f.dep.meta.get("commercial_option") else ""
    note = f" — {f.note}" if f.note else ""
    return (f"| `{f.dep.name}` | {f.dep.ecosystem} | {f.dep.license_text or '—'} | "
            f"{_TIER_LABEL.get(f.dep.tier, f.dep.tier)}{flags}{note} |")


def render_markdown(findings: list[Finding], unread: Iterable[str] = ()) -> str:
    by_status: dict[str, list[Finding]] = {}
    for f in findings:
        by_status.setdefault(f.status, []).append(f)

    counts = {t: 0 for t in _TIER_LABEL}
    for f in findings:
        counts[f.dep.tier] = counts.get(f.dep.tier, 0) + 1

    lines = ["# Open-Source License Audit", ""]
    lines.append("> Generated by `license_audit.py` (license-gate) — do not edit by hand.")
    lines.append("")
    lines.append(f"_Dependencies scanned: **{len(findings)}**_")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Risk tier | Count |")
    lines.append("|---|---|")
    for tier in (NETWORK_COPYLEFT, STRONG_COPYLEFT, WEAK_COPYLEFT, PROPRIETARY,
                 UNKNOWN, PERMISSIVE, PUBLIC_DOMAIN):
        if counts.get(tier):
            lines.append(f"| {_TIER_LABEL[tier]} | {counts[tier]} |")
    lines.append("")

    blocking = by_status.get("blocking", [])
    ack = by_status.get("acknowledged", [])
    review = by_status.get("review", [])
    accepted = by_status.get("accepted", [])

    if blocking:
        lines += ["## ❌ Blocking — strong/network copyleft (not allow-listed)", "",
                  "These can require proprietary source disclosure. Resolve before "
                  "relying on the open-source representation.", "",
                  "| Package | Ecosystem | Declared license | Risk |", "|---|---|---|---|"]
        lines += [_row(f) for f in blocking] + [""]

    if ack:
        lines += ["## ⚠️ Action required — acknowledged copyleft (tracked)", "",
                  "Pre-existing copyleft dependencies that are allow-listed so the CI "
                  "gate blocks *new* additions without hiding these. Each needs "
                  "remediation.", "",
                  "| Package | Ecosystem | Declared license | Risk |", "|---|---|---|---|"]
        lines += [_row(f) for f in ack] + [""]

    if review:
        lines += ["## 🔎 Review — weak copyleft / dev-only / unresolved", "",
                  "| Package | Ecosystem | Declared license | Risk |", "|---|---|---|---|"]
        lines += [_row(f) for f in review] + [""]

    if accepted:
        lines += ["## ✅ Accepted exceptions", "",
                  "| Package | Ecosystem | Declared license | Risk |", "|---|---|---|---|"]
        lines += [_row(f) for f in accepted] + [""]

    lines += ["## ✅ Permissive / public domain", "",
              f"{len(by_status.get('ok', []))} dependencies under permissive or "
              "public-domain licenses (MIT/BSD/Apache/ISC/etc.) — no obligation "
              "beyond preserving notices.", ""]
    unread = list(unread)
    if unread:
        lines += ["## ⚪ Dependency files this tool cannot read", "",
                  "Not checked. Whatever they declare is outside this report.", ""]
        lines += [f"- `{name}`" for name in unread] + [""]
    return "\n".join(lines)


def audit_commit(commit: str, use_network: bool = True, strict: bool = False,
                 unread: list[str] | None = None) -> list[Finding]:
    """:func:`audit` over exactly what ``commit`` tracks."""
    with tempfile.TemporaryDirectory(prefix="license-audit-") as tmp:
        files = extract_commit(commit, Path(tmp))
        return audit(use_network, strict, root=Path(tmp), files=files, unread=unread)


def pushed_commits(lines: Iterable[str]) -> list[str]:
    """The commits a push sends, from git's pre-push lines; deletions carry none."""
    commits: list[str] = []
    for line in lines:
        parts = line.split()
        if len(parts) == 4 and parts[1].strip("0") and parts[1] not in commits:
            commits.append(parts[1])
    return commits


def pre_push(lines: Iterable[str], use_network: bool, strict: bool) -> int:
    """Refuse the push (exit 1) if any commit being pushed fails the gate."""
    commits = pushed_commits(lines)
    refused = 0
    unread: list[str] = []
    for commit in commits:
        blocking = [f for f in audit_commit(commit, use_network, strict, unread)
                    if f.status == "blocking"]
        if not blocking:
            continue
        refused += 1
        sys.stderr.write(
            f"\nLICENSE GATE: push refused. Commit {commit[:9]} carries "
            f"{len(blocking)} dependency(ies) under a license that can force "
            "disclosure of our source:\n")
        for f in blocking:
            flag = " (a paid commercial license exists)" if f.dep.meta.get("commercial_option") else ""
            sys.stderr.write(f"  {f.dep.name} ({f.dep.ecosystem}): {f.dep.license_text or 'unknown'}"
                             f"{flag}\n    in {', '.join(sorted(f.dep.sources))}\n")
    if refused:
        sys.stderr.write(
            "\nRemove the dependency, or record a reviewed exception in "
            f"{ALLOWLIST_LOCATIONS[0]} and commit it.\n\n")
        return 1
    if commits:
        sys.stderr.write(f"license gate: {len(commits)} commit(s) checked, no blocking licenses\n")
    if unread:
        sys.stderr.write(f"license gate: not checked (format not supported): "
                         f"{', '.join(sorted(set(unread)))}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Open-source license audit / CI gate.")
    ap.add_argument("--report", type=Path, help="write the Markdown report here")
    ap.add_argument("--json", type=Path, help="write machine-readable JSON here")
    ap.add_argument("--no-network", action="store_true",
                    help="do not query PyPI; use installed metadata only")
    ap.add_argument("--strict", action="store_true",
                    help="treat unresolved licenses as blocking")
    ap.add_argument("--commit", metavar="REV",
                    help="audit what this commit tracks instead of the working tree")
    ap.add_argument("--root", type=Path,
                    help="the repository to audit (default: the one this is run in)")
    ap.add_argument("--pre-push", action="store_true",
                    help="git pre-push mode: read the pushed refs on stdin, audit each commit")
    args = ap.parse_args(argv)

    if args.pre_push:
        return pre_push(sys.stdin, use_network=not args.no_network, strict=args.strict)
    unread: list[str] = []
    if args.commit:
        findings = audit_commit(args.commit, use_network=not args.no_network,
                                strict=args.strict, unread=unread)
    else:
        findings = audit(use_network=not args.no_network, strict=args.strict,
                         root=args.root, unread=unread)
    report = render_markdown(findings, unread)

    if args.report:
        args.report.write_text(report, encoding="utf-8")
    else:
        print(report)

    if args.json:
        payload = [{
            "name": f.dep.name, "ecosystem": f.dep.ecosystem,
            "license": f.dep.license_text, "tier": f.dep.tier,
            "status": f.status, "dev_only": f.dep.dev_only,
            "note": f.note, "sources": sorted(f.dep.sources),
            "commercial_option": bool(f.dep.meta.get("commercial_option")),
        } for f in findings]
        args.json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    blocking = [f for f in findings if f.status == "blocking"]
    if blocking:
        sys.stderr.write(
            f"\nLICENSE GATE FAILED: {len(blocking)} blocking dependency(ies): "
            + ", ".join(f.dep.name for f in blocking) + "\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
