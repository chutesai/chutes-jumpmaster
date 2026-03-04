#!/bin/bash

# Script to update all chutes sub-repositories
# Clones repos that are missing, pulls repos that exist.
# Repo list is persisted in .sub-repos (untracked) after first run.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUBREPOS_FILE="$SCRIPT_DIR/.sub-repos"
GITIGNORE_FILE="$SCRIPT_DIR/.gitignore"

# Default org used to build clone URLs for repos that don't specify one
DEFAULT_ORG="chutesai"

DEFAULT_REPOS=(
    "chutes"
    "chutes-api"
    "chutes-miner"
    "chutes-e2ee-transport"
    "sek8s"
)

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
        echo "# One repo name per line. Cloned from https://github.com/$DEFAULT_ORG/<name>.git"
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

    # Add non-default repo directories to .gitignore
    if [ ${#EXTRA_REPOS[@]} -gt 0 ]; then
        added_any=false
        for r in "${EXTRA_REPOS[@]}"; do
            # Skip if already present in .gitignore
            if ! grep -qxF "$r" "$GITIGNORE_FILE" && ! grep -qxF "/$r" "$GITIGNORE_FILE"; then
                if [ "$added_any" = false ]; then
                    echo "" >> "$GITIGNORE_FILE"
                    echo "# Extra sub-repos (added by update_all_repos.sh)" >> "$GITIGNORE_FILE"
                    added_any=true
                fi
                echo "/$r" >> "$GITIGNORE_FILE"
                echo "Added /$r to .gitignore"
            fi
        done
    fi

    echo ""
fi

# ---------------------------------------------------------------------------
# Load repo list from .sub-repos (bash 3.2-compatible, no mapfile)
# ---------------------------------------------------------------------------
REPOS=()
while IFS= read -r line; do
    REPOS+=("$line")
done < <(grep -v '^\s*#' "$SUBREPOS_FILE" | grep -v '^\s*$')

SUCCESS_COUNT=0
FAILURE_COUNT=0
SKIPPED_COUNT=0

for REPO in "${REPOS[@]}"; do
    CLONE_URL="https://github.com/$DEFAULT_ORG/$REPO.git"
    REPO_PATH="$SCRIPT_DIR/$REPO"

    # Detect whether the directory is a valid git repo
    REPO_VALID=false
    if [ -d "$REPO_PATH" ] && /usr/bin/git -C "$REPO_PATH" rev-parse --git-dir > /dev/null 2>&1; then
        REPO_VALID=true
    fi

    if [ "$REPO_VALID" = false ]; then
        if [ -d "$REPO_PATH" ]; then
            echo "[RECLONE] $REPO - directory exists but is not a valid git repository, removing and re-cloning"
            rm -rf "$REPO_PATH"
        else
            echo "[CLONE] $REPO <- $CLONE_URL"
        fi
        if /usr/bin/git clone "$CLONE_URL" "$REPO_PATH" 2>&1; then
            echo "[CLONED] $REPO"
            ((SUCCESS_COUNT++))
        else
            echo "[FAILED] $REPO - git clone failed"
            ((FAILURE_COUNT++))
        fi
        echo ""
        continue
    fi

    echo "[START] $REPO"

    CURRENT_BRANCH=$(/usr/bin/git -C "$REPO_PATH" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
    DEFAULT_BRANCH=$(/usr/bin/git -C "$REPO_PATH" symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's|refs/remotes/origin/||' || echo "")

    # Warn if not on the default branch (interactive runs only)
    if [ -t 1 ] && [ -n "$DEFAULT_BRANCH" ] && [ "$CURRENT_BRANCH" != "$DEFAULT_BRANCH" ]; then
        echo "[WARN]  $REPO is on '$CURRENT_BRANCH', not '$DEFAULT_BRANCH' — pull may not reflect latest upstream"
    fi

    PULL_OUTPUT=$(/usr/bin/git -C "$REPO_PATH" pull 2>&1)
    PULL_STATUS=$?
    echo "$PULL_OUTPUT"
    if [ $PULL_STATUS -eq 0 ]; then
        if echo "$PULL_OUTPUT" | grep -q "Already up to date"; then
            echo "[OK] $REPO (branch: $CURRENT_BRANCH)"
        else
            echo "[UPDATED] $REPO (branch: $CURRENT_BRANCH)"
        fi
        ((SUCCESS_COUNT++))
    else
        echo "[FAILED] $REPO - git pull failed"
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
