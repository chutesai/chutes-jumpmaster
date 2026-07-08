#!/bin/bash

# Script to update all chutes sub-repositories
# Clones repos that are missing, pulls repos that exist.
# Repo list is persisted in .sub-repos (untracked) after first run.
# New default repos are backfilled into existing .sub-repos files.
#
# Public default repos are ignored via the tracked .gitignore. Any other
# repos in .sub-repos (e.g. private ones) are ignored locally via
# .git/info/exclude, so their names never land in a tracked file.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUBREPOS_FILE="$SCRIPT_DIR/.sub-repos"
GITIGNORE_FILE="$SCRIPT_DIR/.gitignore"
GIT_EXCLUDE_FILE="$SCRIPT_DIR/.git/info/exclude"

# Default org used to build clone URLs for repos that don't specify one.
# .sub-repos entries may be either:
#   repo-name
#   owner/repo-name
#   https://github.com/owner/repo-name.git
DEFAULT_ORG="chutesai"

# Public, non-fork repos in the chutesai org
DEFAULT_REPOS=(
    "ai-sdk-provider-chutes"
    "antseed-verification"
    "bittencert"
    "chutes"
    "chutes-api"
    "chutes-audit"
    "chutes-autopilot"
    "chutes-docs"
    "chutes-dropzone"
    "chutes-e2ee-transport"
    "chutes-miner"
    "chutes-n8n-local"
    "chutes-search"
    "chutes-style"
    "claude-proxy"
    "cllmv"
    "e2ee-proxy"
    "e2ee-test"
    "fiber"
    "graval"
    "model-router"
    "n8n-nodes-chutes"
    "research-data-opt-in-proxy"
    "responses-proxy"
    "sek8s"
    "Sign-in-with-Chutes"
    "squad-api"
)

is_repo_in_file() {
    local repo="$1" file="$2"
    [ -f "$file" ] || return 1
    grep -qxF "$repo" "$file" || grep -qxF "/$repo" "$file"
}

parse_repo_spec() {
    local spec="$1"

    PARSED_REPO_OWNER="$DEFAULT_ORG"
    PARSED_REPO_NAME="$spec"
    PARSED_REPO_DISPLAY="$spec"

    spec="${spec%/}"
    spec="${spec%.git}"
    spec="${spec%/}"
    spec="${spec#https://github.com/}"
    spec="${spec#http://github.com/}"
    spec="${spec#git@github.com:}"

    if [[ "$spec" == */* ]]; then
        PARSED_REPO_OWNER="${spec%%/*}"
        PARSED_REPO_NAME="${spec#*/}"
    else
        PARSED_REPO_NAME="$spec"
    fi

    PARSED_REPO_CLONE_URL="https://github.com/$PARSED_REPO_OWNER/$PARSED_REPO_NAME.git"
    if [ "$PARSED_REPO_OWNER" = "$DEFAULT_ORG" ]; then
        PARSED_REPO_DISPLAY="$PARSED_REPO_NAME"
    else
        PARSED_REPO_DISPLAY="$PARSED_REPO_OWNER/$PARSED_REPO_NAME"
    fi
}

# Ensure every repo has a "/repo" ignore entry in $file, under $header.
# $label is the human-readable file name used in log messages.
ensure_repos_in_ignore_file() {
    local file="$1" header="$2" label="$3"
    shift 3
    local repos=("$@")
    local missing=()
    local repo

    for repo in "${repos[@]}"; do
        [ -n "$repo" ] || continue
        if ! is_repo_in_file "$repo" "$file"; then
            missing+=("$repo")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        [ -f "$file" ] || touch "$file"

        if ! grep -qxF "$header" "$file"; then
            [ -s "$file" ] && echo "" >> "$file"
            echo "$header" >> "$file"
        fi

        for repo in "${missing[@]}"; do
            echo "/$repo" >> "$file"
            echo "Added /$repo to $label"
        done
    fi

    for repo in "${repos[@]}"; do
        [ -n "$repo" ] || continue
        if ! is_repo_in_file "$repo" "$file"; then
            echo "[FAILED] Missing $label entry for $repo"
            exit 1
        fi
    done
}

ensure_default_repos_present() {
    local missing=()
    local repo

    [ -f "$SUBREPOS_FILE" ] || return 0

    for repo in "${DEFAULT_REPOS[@]}"; do
        if ! grep -v '^\s*#' "$SUBREPOS_FILE" | grep -qxF "$repo"; then
            missing+=("$repo")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        for repo in "${missing[@]}"; do
            echo "$repo" >> "$SUBREPOS_FILE"
            echo "Added default repo to .sub-repos: $repo"
        done
        echo ""
    fi
}

echo "=== Chutes Sub-repositories Update Script ==="
echo "Base directory: $SCRIPT_DIR"
echo ""

# ---------------------------------------------------------------------------
# First-run: create .sub-repos with defaults, prompt for extras
# ---------------------------------------------------------------------------
if [ ! -f "$SUBREPOS_FILE" ]; then
    echo "No .sub-repos file found. Setting up repo list for the first time."
    echo ""
    echo "Default public repos:"
    for r in "${DEFAULT_REPOS[@]}"; do
        echo "  - $r"
    done
    echo ""

    EXTRA_REPOS=()

    # Only prompt when running interactively
    if [ -t 0 ]; then
        echo "Enter any additional repo names to track (space-separated), or press Enter to skip:"
        read -r extra_input
        if [ -n "$extra_input" ]; then
            read -ra EXTRA_REPOS <<< "$extra_input"
        fi
    fi

    # Write .sub-repos
    {
        echo "# Sub-repos tracked by update_all_repos.sh"
        echo "# One repo per line. Use either <name> for $DEFAULT_ORG repos or <owner>/<name>."
        echo "# Lines starting with # are ignored."
        echo ""
        for r in "${DEFAULT_REPOS[@]}"; do
            echo "$r"
        done
        for r in "${EXTRA_REPOS[@]}"; do
            echo "$r"
        done
    } > "$SUBREPOS_FILE"

    echo ""
    echo "Created $SUBREPOS_FILE"

    echo ""
fi

ensure_default_repos_present

# ---------------------------------------------------------------------------
# Load repo list from .sub-repos (bash 3.2-compatible, no mapfile)
# ---------------------------------------------------------------------------
REPOS=()
while IFS= read -r line; do
    REPOS+=("$line")
done < <(grep -v '^\s*#' "$SUBREPOS_FILE" | grep -v '^\s*$')

# Public default repos go in the tracked .gitignore.
ensure_repos_in_ignore_file "$GITIGNORE_FILE" \
    "# Sub-repo directories (managed by update_all_repos.sh)" \
    ".gitignore" \
    "${DEFAULT_REPOS[@]}"

# Any repo in .sub-repos not already covered by .gitignore (e.g. a private
# repo or a repo from another owner) is ignored locally via .git/info/exclude,
# keeping its name out of tracked files.
LOCAL_REPOS=()
for repo_spec in "${REPOS[@]}"; do
    parse_repo_spec "$repo_spec"
    repo="$PARSED_REPO_NAME"
    if is_repo_in_file "$repo" "$GITIGNORE_FILE"; then
        continue
    fi
    LOCAL_REPOS+=("$repo")
done

if [ ${#LOCAL_REPOS[@]} -gt 0 ]; then
    ensure_repos_in_ignore_file "$GIT_EXCLUDE_FILE" \
        "# Local sub-repo directories (managed by update_all_repos.sh)" \
        ".git/info/exclude" \
        "${LOCAL_REPOS[@]}"
fi

SUCCESS_COUNT=0
FAILURE_COUNT=0
SKIPPED_COUNT=0

for REPO_SPEC in "${REPOS[@]}"; do
    parse_repo_spec "$REPO_SPEC"
    REPO="$PARSED_REPO_NAME"
    REPO_DISPLAY="$PARSED_REPO_DISPLAY"
    CLONE_URL="$PARSED_REPO_CLONE_URL"
    REPO_PATH="$SCRIPT_DIR/$REPO"

    # Detect whether the directory is a valid git repo
    REPO_VALID=false
    if [ -d "$REPO_PATH" ] && /usr/bin/git -C "$REPO_PATH" rev-parse --git-dir > /dev/null 2>&1; then
        REPO_VALID=true
    fi

    if [ "$REPO_VALID" = false ]; then
        if [ -d "$REPO_PATH" ]; then
            echo "[RECLONE] $REPO_DISPLAY - directory exists but is not a valid git repository, removing and re-cloning"
            rm -rf "$REPO_PATH"
        else
            echo "[CLONE] $REPO_DISPLAY <- $CLONE_URL"
        fi
        if /usr/bin/git clone "$CLONE_URL" "$REPO_PATH" 2>&1; then
            echo "[CLONED] $REPO_DISPLAY"
            ((SUCCESS_COUNT++))
        else
            echo "[FAILED] $REPO_DISPLAY - git clone failed"
            ((FAILURE_COUNT++))
        fi
        echo ""
        continue
    fi

    echo "[START] $REPO_DISPLAY"

    CURRENT_BRANCH=$(/usr/bin/git -C "$REPO_PATH" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
    DEFAULT_BRANCH=$(/usr/bin/git -C "$REPO_PATH" symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's|refs/remotes/origin/||' || echo "")
    UPSTREAM_BRANCH=$(/usr/bin/git -C "$REPO_PATH" rev-parse --abbrev-ref --symbolic-full-name @{u} 2>/dev/null || echo "")

    # Warn if not on the default branch (interactive runs only)
    if [ -t 1 ] && [ -n "$DEFAULT_BRANCH" ] && [ "$CURRENT_BRANCH" != "$DEFAULT_BRANCH" ]; then
        echo "[WARN]  $REPO_DISPLAY is on '$CURRENT_BRANCH', not '$DEFAULT_BRANCH' — pull may not reflect latest upstream"
    fi

    if [ -z "$UPSTREAM_BRANCH" ]; then
        echo "[SKIPPED] $REPO_DISPLAY - branch '$CURRENT_BRANCH' has no upstream tracking branch"
        ((SKIPPED_COUNT++))
        echo ""
        continue
    fi

    if PULL_OUTPUT=$(/usr/bin/git -C "$REPO_PATH" pull 2>&1); then
        echo "$PULL_OUTPUT"
        if echo "$PULL_OUTPUT" | grep -q "Already up to date"; then
            echo "[OK] $REPO_DISPLAY (branch: $CURRENT_BRANCH)"
        else
            echo "[UPDATED] $REPO_DISPLAY (branch: $CURRENT_BRANCH)"
        fi
        ((SUCCESS_COUNT++))
    else
        PULL_STATUS=$?
        echo "$PULL_OUTPUT"
        echo "[FAILED] $REPO_DISPLAY - git pull failed (exit: $PULL_STATUS)"
        ((FAILURE_COUNT++))
    fi

    echo ""
done

echo "=== Update Summary ==="
echo "Success: $SUCCESS_COUNT"
echo "Failed:  $FAILURE_COUNT"
echo "Skipped: $SKIPPED_COUNT"

if [ $FAILURE_COUNT -gt 0 ]; then
    echo ""
    echo "Some repositories failed to update. Please check the output above."
    exit 1
fi

echo ""
echo "All repositories updated successfully!"
