# license-gate

Stops code that depends on GPL, AGPL or SSPL software from being pushed.
Those licenses can oblige us to publish our own source; everything else
(MIT, BSD, Apache, LGPL, MPL...) is reported but never blocks.

One checker, two gates:

| Gate | Where it runs | What happens on a problem |
|---|---|---|
| Pre-push hook | every `git push` from a machine where it is installed, in every repository | the push is refused; nothing leaves the machine |
| GitHub check | every push and pull request in each repository that calls the shared workflow | the check goes red |

## What it reads

| Ecosystem | Files |
|---|---|
| Python | `*requirements*.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock` |
| npm | `package-lock.json`, `yarn.lock`, `package.json` (when no lockfile sits beside it) |
| Java | `pom.xml` |
| Go | `go.mod` |
| Rust | `Cargo.lock` |

Licenses come from the lockfile where it records one, then installed package
metadata, the PyPI API, and [deps.dev](https://deps.dev). Gradle, pnpm, Bundler
and Composer files are not read yet; the report names any it finds. Datasets,
`fixtures/` and `node_modules/` are skipped. Dev-only dependencies (files named
`*dev*`/`*test*`, uv/poetry dev groups, npm dev packages in `package-lock.json`
or `package.json`, Maven `test` scope) are reported for review, not blocked.
`yarn.lock` does not say which packages are dev-only, so all of it counts.

It checks declared dependencies. It does not notice copyleft source code copied
into a repository.

## Install the push hook on a machine

```sh
curl -fsSL https://raw.githubusercontent.com/cortex-chris/license-gate/main/install.sh | sh
```

This clones the checker to `~/.local/share/license-gate` and sets the global
`core.hooksPath`. Each repository's own hooks (Git LFS, pre-commit...) still
run: the global hooks hand over to them. A repository that sets its own
`core.hooksPath` (husky does) keeps it and is not checked by the hook.
Re-run the command to update; remove with
`git config --global --unset core.hooksPath`.

The hook audits the commits being pushed, read from git, not the files on
disk. `git push --no-verify` skips it for one push; the GitHub check still runs.

## Add the GitHub check to a repository

Copy [`templates/license-audit.yml`](templates/license-audit.yml) to
`.github/workflows/license-audit.yml`.

## When something is flagged

Remove the dependency. If someone has reviewed it and it is genuinely fine,
record it in `.github/license-allowlist.json` and commit that with the change:

```json
{
  "accepted": [
    {"name": "somepkg", "ecosystem": "pypi", "license": "GPL-3.0", "reason": "build tool only, never shipped"}
  ],
  "acknowledged_copyleft": []
}
```

## Run it by hand

```sh
python3 license_audit.py --root path/to/repo      # Markdown report
python3 license_audit.py --commit HEAD            # one commit, as the hook sees it
python3 -m pytest -o addopts= -q                  # this tool's tests
```
