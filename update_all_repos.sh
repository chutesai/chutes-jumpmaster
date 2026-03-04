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
        echo "# One repo per line. Format: <name> [clone-url]"
        echo "# If clone-url is omitted, https://github.com/$DEFAULT_ORG/<name>.git is used."
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
# Load repo list from .sub-repos
# ---------------------------------------------------------------------------
mapfile -t REPOS < <(grep -v '^\s*#' "$SUBREPOS_FILE" | grep -v '^\s*$')

SUCCESS_COUNT=0
FAILURE_COUNT=0
SKIPPED_COUNT=0

for REPO_ENTRY in "${REPOS[@]}"; do
    # Support optional inline clone URL: "<name> <url>"
    REPO=$(echo "$REPO_ENTRY" | awk '{print $1}')
    CLONE_URL=$(echo "$REPO_ENTRY" | awk '{print $2}')
    if [ -z "$CLONE_URL" ]; then
        CLONE_URL="https://github.com/$DEFAULT_ORG/$REPO.git"
    fi

    REPO_PATH="$SCRIPT_DIR/$REPO"

    if [ ! -d "$REPO_PATH" ]; then
        echo "[CLONE] $REPO <- $CLONE_URL"
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

    if [ ! -d "$REPO_PATH/.git" ]; then
        echo "[SKIP] $REPO - Directory exists but is not a git repository"
        ((SKIPPED_COUNT++))
        echo ""
        continue
    fi

    echo "[START] $REPO"

    CURRENT_BRANCH=$(/usr/bin/git -C "$REPO_PATH" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

    if /usr/bin/git -C "$REPO_PATH" pull 2>&1; then
        echo "[UPDATED] $REPO (branch: $CURRENT_BRANCH)"
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
