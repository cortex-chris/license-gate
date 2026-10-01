#!/bin/sh
# Install license-gate for every git repository on this machine: every push is
# checked for GPL, AGPL and SSPL dependencies, and refused if it carries one.
#
#   curl -fsSL https://raw.githubusercontent.com/cortex-chris/license-gate/main/install.sh | sh
#
# Re-run to update. Remove with:  git config --global --unset core.hooksPath
set -e

dest="${LICENSE_GATE_HOME:-$HOME/.local/share/license-gate}"
source_repo="${LICENSE_GATE_REPO:-https://github.com/cortex-chris/license-gate.git}"

if [ -d "$dest/.git" ]; then
    git -C "$dest" pull --ff-only --quiet
else
    mkdir -p "$(dirname "$dest")"
    git clone --quiet "$source_repo" "$dest"
fi

current=$(git config --global --get core.hooksPath || true)
if [ -n "$current" ] && [ "$current" != "$dest/hooks" ]; then
    printf >&2 'core.hooksPath is already set globally to %s; not overriding it.\n' "$current"
    exit 1
fi
git config --global core.hooksPath "$dest/hooks"

echo "license-gate installed at $dest"
echo "Every push from this machine is now checked. Repositories that set their"
echo "own core.hooksPath (husky, for example) keep theirs and are not checked."
