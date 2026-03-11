#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Chutes Utils Script
# =============================================================================
# Interactive deployment tool with optional flags for automation
# GUIDES: https://chutes.ai/docs/getting-started/first-chute
#         https://github.com/chutesai/chutes?tab=readme-ov-file#-deploying-a-chute
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
CHUTES_CONFIG="$HOME/.chutes/config.ini"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Flags
SHOW_HELP=false
LIST_IMAGES=false
LIST_CHUTES=false
BUILD_MODULE=""
DEPLOY_MODULE=""
STATUS_CHUTE=""
RUN_MODULE=""
RUN_DOCKER_MODULE=""
DELETE_CHUTE=""
LOGS_CHUTE=""
DISCOVER_MODULE=""
LOCAL_BUILD=false
ACCEPT_FEE=false
PUBLIC_DEPLOY=false
DEV_MODE=false
DEBUG_MODE=false
PORT=8000

DEFAULT_STARTUP_DELAY=300
DEFAULT_PROBE_TIMEOUT=60
DEFAULT_DISCOVER_GPUS="all"

# =============================================================================
# Helper Functions
# =============================================================================

print_header() {
    echo -e "\n${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} ${BLUE}$1${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}\n"
}

print_info() {
    echo -e "${BLUE}ℹ${NC}  $1"
}

print_success() {
    echo -e "${GREEN}✓${NC}  $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC}  $1"
}

print_error() {
    echo -e "${RED}✗${NC}  $1"
}

print_cmd() {
    echo -e "${YELLOW}\$${NC} $1"
}

confirm() {
    local prompt="$1"
    local default="${2:-n}"
    
    if [[ "$default" == "y" ]]; then
        read -rp "$prompt [Y/n]: " response
        [[ -z "$response" || "$response" =~ ^[Yy] ]]
    else
        read -rp "$prompt [y/N]: " response
        [[ "$response" =~ ^[Yy] ]]
    fi
}

ensure_venv() {
    if [[ ! -f "$VENV_DIR/bin/activate" ]]; then
        print_error "Virtual environment not found. Run setup.sh first."
        exit 1
    fi
    source "$VENV_DIR/bin/activate"
}

ensure_chutes_config() {
    if [[ ! -f "$CHUTES_CONFIG" ]]; then
        print_error "Chutes config not found at $CHUTES_CONFIG"
        print_info "Run setup.sh to register, or use Account → Link Bittensor Wallet in utils.sh."
        return 1
    fi
}

get_username() {
    grep -E "^username\s*=" "$CHUTES_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' '
}

get_user_id() {
    grep -E "^user_id\s*=" "$CHUTES_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' '
}

chutes_api_get_self_tsv() {
    ensure_chutes_config || return 1

    local py_bin="$VENV_DIR/bin/python3"
    if [[ ! -x "$py_bin" ]]; then
        return 1
    fi

    "$py_bin" - "$CHUTES_CONFIG" <<'PYCODE'
import json
import sys
import time
import urllib.error
import urllib.request
from configparser import ConfigParser

from substrateinterface import Keypair


config_path = sys.argv[1]
config = ConfigParser()
config.read(config_path)

base_url = config.get("api", "base_url", fallback="https://api.chutes.ai").rstrip("/")
hotkey = config.get("auth", "hotkey_ss58address", fallback="").strip()
seed = config.get("auth", "hotkey_seed", fallback="").strip().removeprefix("0x")
user_id = config.get("auth", "user_id", fallback="").strip()

if not hotkey or not seed:
    raise SystemExit(1)

nonce = str(int(time.time()))
message = f"{hotkey}:{nonce}:me"
signature = Keypair.create_from_seed(seed_hex=seed).sign(message.encode()).hex()
headers = {
    "X-Chutes-Hotkey": hotkey,
    "X-Chutes-Nonce": nonce,
    "X-Chutes-Signature": signature,
}
if user_id:
    headers["X-Chutes-UserID"] = user_id

request = urllib.request.Request(f"{base_url}/users/me", headers=headers, method="GET")
try:
    with urllib.request.urlopen(request, timeout=15) as response:
        data = json.load(response)
except urllib.error.HTTPError as exc:
    body = exc.read(300).decode("utf-8", "replace")
    sys.stderr.write(f"HTTP {exc.code}: {body}\n")
    raise SystemExit(1)
except Exception as exc:
    sys.stderr.write(f"{exc}\n")
    raise SystemExit(1)

fields = [
    data.get("username", ""),
    data.get("user_id", ""),
    data.get("payment_address", ""),
    "" if data.get("balance") is None else str(data.get("balance")),
]
sys.stdout.write("\t".join(fields) + "\n")
PYCODE
}

chutes_api_list_tsv() {
    # Query Chutes API directly (signed with hotkey) to avoid rich-table truncation.
    # Output: tab-delimited rows for the given object type.
    # - chutes: chute_id, name, status(hot|cold), slug
    # - images: image_id, name, tag, status
    local object_type="$1"
    local include_public="${2:-false}"

    ensure_venv
    ensure_chutes_config || return 1

    python - "$object_type" "$include_public" <<'PYCODE'
import asyncio
import sys

import aiohttp

from chutes.config import get_config
from chutes.util.auth import sign_request


def _truthy(s: str) -> bool:
    return str(s).strip().lower() in ("1", "true", "yes", "y", "on")


object_type = sys.argv[1]
include_public = _truthy(sys.argv[2]) if len(sys.argv) > 2 else False


def out(fields):
    sys.stdout.write(
        "\t".join("" if v is None else str(v).replace("\t", " ") for v in fields) + "\n"
    )


async def fetch_all():
    config = get_config()
    headers, _ = sign_request(purpose=object_type)
    items = []
    page = 0
    limit = 200
    base_params = {}
    if include_public:
        base_params["include_public"] = "true"

    async with aiohttp.ClientSession(base_url=config.generic.api_base_url) as session:
        while True:
            params = dict(base_params)
            params["limit"] = str(limit)
            params["page"] = str(page)
            async with session.get(f"/{object_type}/", headers=headers, params=params) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise SystemExit(
                        f"Failed to list {object_type}: {resp.status} {text[:300]}"
                    )
                data = await resp.json()

            batch = data.get("items") or []
            items.extend(batch)
            total = int(data.get("total") or 0)
            if not batch or len(items) >= total:
                break
            page += 1

    return items


items = asyncio.run(fetch_all())
for item in items:
    if object_type == "chutes":
        out(
            [
                item.get("chute_id"),
                item.get("name"),
                "hot" if item.get("hot") else "cold",
                item.get("slug"),
            ]
        )
    elif object_type == "images":
        out([item.get("image_id"), item.get("name"), item.get("tag"), item.get("status")])
PYCODE
}

show_usage() {
    cat << EOF
${CYAN}Chutes Utils Script${NC}

${YELLOW}Usage:${NC}
  ./utils.sh [OPTIONS]

${YELLOW}Options:${NC}
  -h, --help              Show this help message
  
  ${BLUE}Listing:${NC}
  --list-images           List all built images
  --list-chutes           List all deployed chutes
  --status NAME           Get status of a specific chute
  
  ${BLUE}Building:${NC}
  --build MODULE          Build a chute (e.g., deploy_xtts_whisper)
  --discover MODULE       Run route discovery (generate routes manifest)
  --local                 Build locally (no remote upload)
  
  ${BLUE}Running:${NC}
  --run-docker MODULE     Run built image in Docker with GPU
  --run MODULE            Run chute in dev mode (on host)
  --dev                   Enable dev mode
  --port PORT             Port for local run (default: 8000)
  
  ${BLUE}Deploying:${NC}
  --deploy MODULE         Deploy a chute
  --accept-fee            Accept deployment fees
  --public                Make deployment public
  
  ${BLUE}Management:${NC}
  --delete NAME           Delete a chute (interactive confirmation)
  --logs NAME             Warmup + stream logs (auto-watch, legacy fallback)
  --debug                 Enable debug output

${YELLOW}Available Modules:${NC}
$(list_modules_quiet)

${YELLOW}Examples:${NC}
  ./utils.sh                                    # Interactive mode
  ./utils.sh --list-chutes                      # List deployed chutes
  ./utils.sh --build deploy_xtts_whisper --local
  ./utils.sh --run-docker deploy_xtts_whisper    # Run in Docker with GPU
  ./utils.sh --run deploy_xtts_whisper           # Run on host (dev mode)
  ./utils.sh --deploy deploy_xtts_whisper --accept-fee
  ./utils.sh --status xtts-whisper

EOF
}

# =============================================================================
# Module Discovery
# =============================================================================

list_modules_quiet() {
    for f in "$SCRIPT_DIR"/deploy_*.py; do
        if [[ -f "$f" ]]; then
            basename "$f" .py
        fi
    done
}

list_modules() {
    print_header "Available Deploy Modules"
    local i=1
    for f in "$SCRIPT_DIR"/deploy_*.py; do
        if [[ -f "$f" ]]; then
            local name=$(basename "$f" .py)
            echo -e "  ${GREEN}$i)${NC} $name"
            i=$((i + 1))
        fi
    done
    echo ""
}

select_module() {
    local prompt="${1:-Select module}"
    local modules=()
    
    for f in "$SCRIPT_DIR"/deploy_*.py; do
        if [[ -f "$f" ]]; then
            modules+=("$(basename "$f" .py)")
        fi
    done
    
    if [[ ${#modules[@]} -eq 0 ]]; then
        print_error "No deploy_*.py modules found"
        return 1
    fi
    
    # Output menu to stderr so it doesn't get captured
    echo "" >&2
    local i=1
    for m in "${modules[@]}"; do
        echo -e "  ${GREEN}$i)${NC} $m" >&2
        i=$((i + 1))
    done
    echo "" >&2
    
    read -rp "$prompt (1-${#modules[@]}): " choice
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#modules[@]} ]]; then
        echo "${modules[$((choice - 1))]}"
        return 0
    else
        print_error "Invalid selection"
        return 1
    fi
}

run_route_discovery_for_module() {
    local module="$1"
    local chute_file="$SCRIPT_DIR/${module}.py"
    local tool_path="$SCRIPT_DIR/tools/discover_routes.py"

    if [[ ! -f "$chute_file" ]]; then
        print_error "Module file not found: $chute_file"
        return 1
    fi
    if [[ ! -f "$tool_path" ]]; then
        print_error "Route discovery tool not found at $tool_path"
        return 1
    fi

    print_header "Route Discovery: $module"
    print_info "This will run the base image and probe HTTP routes automatically."
    print_info "Press Enter to accept defaults."
    echo ""

    local startup_delay
    local probe_timeout
    local docker_gpus

    read -rp "Startup delay seconds [${DEFAULT_STARTUP_DELAY}]: " startup_delay
    startup_delay=${startup_delay:-$DEFAULT_STARTUP_DELAY}

    read -rp "Probe timeout seconds [${DEFAULT_PROBE_TIMEOUT}]: " probe_timeout
    probe_timeout=${probe_timeout:-$DEFAULT_PROBE_TIMEOUT}

    read -rp "Docker --gpus value [${DEFAULT_DISCOVER_GPUS}]: " docker_gpus
    docker_gpus=${docker_gpus:-$DEFAULT_DISCOVER_GPUS}

    ensure_venv
    pushd "$SCRIPT_DIR" >/dev/null || return 1

    local cmd=(python tools/discover_routes.py --chute-file "$chute_file" --startup-delay "$startup_delay" --probe-timeout "$probe_timeout")
    if [[ -n "$docker_gpus" ]]; then
        cmd+=(--docker-gpus "$docker_gpus")
    fi

    print_cmd "${cmd[*]}"
    echo ""
    "${cmd[@]}"
    local status=$?
    popd >/dev/null || true

    if [[ $status -eq 0 ]]; then
        local manifest="$SCRIPT_DIR/${module}.routes.json"
        print_success "Route discovery complete."
        if [[ -f "$manifest" ]]; then
            print_info "Manifest saved to $manifest"
        fi
    else
        print_error "Route discovery failed (exit $status)"
    fi
    return $status
}

prompt_route_discovery_before_build() {
    local module="$1"
    local manifest="$SCRIPT_DIR/${module}.routes.json"
    echo ""
    local default_answer="n"
    if [[ ! -f "$manifest" ]]; then
        default_answer="y"
        print_warning "Route manifest not found (${manifest##*/}); route discovery is strongly recommended."
    fi
    if confirm "Run route discovery for $module before building?" "$default_answer"; then
        if ! run_route_discovery_for_module "$module"; then
            if ! confirm "Discovery failed. Continue to build anyway?"; then
                return 1
            fi
        fi
    fi
    return 0
}

# =============================================================================
# Chutes Operations
# =============================================================================

do_list_images() {
    print_header "Built Images"
    ensure_venv
    print_cmd "chutes images list"
    echo ""
    chutes images list || print_warning "No images found or error listing"
}

do_list_chutes() {
    print_header "Deployed Chutes"
    ensure_venv
    print_cmd "chutes chutes list"
    echo ""
    chutes chutes list || print_warning "No chutes found or error listing"
}

do_chute_status() {
    local chute_name="$1"
    print_header "Chute Status: $chute_name"
    ensure_venv
    print_cmd "chutes chutes get \"$chute_name\""
    echo ""
    chutes chutes get "$chute_name" || print_error "Could not get chute status"
}

list_chute_names_from_modules() {
    for f in "$SCRIPT_DIR"/deploy_*.py; do
        if [[ -f "$f" ]]; then
            local name
            name=$(grep -oP "CHUTE_NAME\s*=\s*['\"]\\K[^'\"]*" "$f" 2>/dev/null | head -1)
            if [[ -z "$name" ]]; then
                name=$(basename "$f" .py)
                name="${name#deploy_}"
            fi
            [[ -n "$name" ]] && echo "$name"
        fi
    done
}

module_to_chute_name() {
    local module="$1"
    local py_file="$SCRIPT_DIR/${module}.py"
    local chute_name=""

    if [[ -f "$py_file" ]]; then
        chute_name=$(grep -oP "CHUTE_NAME\s*=\s*['\"]\\K[^'\"]*" "$py_file" 2>/dev/null | head -1)
    fi

    if [[ -z "$chute_name" ]]; then
        chute_name="${module#deploy_}"
    fi

    echo "$chute_name"
}

select_chute_for_status() {
    # Send all UI to stderr so command substitution only captures the name
    local chute_input=""
    echo "" >&2
    read -rp "Chute Name or ID (press Enter to list): " chute_input
    if [[ -n "$chute_input" ]]; then
        echo "$chute_input"
        return 0
    fi

    print_header "Select Deployed Chute" >&2

    local lines_raw=""
    local lines=()
    local chute_ids=()
    local chute_names=()
    local choice=""

    if ! lines_raw="$(chutes_api_list_tsv "chutes")"; then
        print_error "Failed to list chutes (API call). Check network/auth." >&2
        return 1
    fi

    if [[ -n "$lines_raw" ]]; then
        mapfile -t lines <<<"$lines_raw"
    fi

    for line in ${lines[@]+"${lines[@]}"}; do
        IFS=$'\t' read -r cid cname cstatus cslug <<<"$line"
        [[ -n "$cid" && -n "$cname" ]] || continue
        chute_ids+=("$cid")
        chute_names+=("$cname")
    done

    if [[ ${#chute_ids[@]} -eq 0 ]]; then
        print_warning "No deployed chutes found" >&2
        return 1
    fi

    echo -e "${BLUE}Deployed Chutes:${NC}" >&2
    local i=1
    while [[ $i -le ${#chute_ids[@]} ]]; do
        local idx=$((i-1))
        echo -e "  ${GREEN}$i)${NC} ${chute_names[$idx]} (id: ${chute_ids[$idx]})" >&2
        i=$((i + 1))
    done
    echo -e "  ${YELLOW}b)${NC} Back" >&2
    echo "" >&2

    read -rp "Select chute (1-${#chute_ids[@]}): " choice
    if [[ "$choice" == "b" || "$choice" == "B" ]]; then
        return 1
    fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#chute_ids[@]} ]]; then
        local idx=$((choice - 1))
        echo "${chute_ids[$idx]}"
        return 0
    fi

    print_error "Invalid selection" >&2
    return 1
}

do_build() {
    local module="$1"
    local local_flag=""
    local debug_flag=""
    
    if $LOCAL_BUILD; then
        local_flag="--local"
    fi
    
    if $DEBUG_MODE; then
        debug_flag="--debug"
    fi
    
    print_header "Building: $module"
    
    local username=$(get_username)
    if [[ -z "$username" ]]; then
        print_error "Could not determine username from config"
        return 1
    fi
    
    print_info "Username: $username"
    print_info "Module: ${module}:chute"
    if $LOCAL_BUILD; then
        print_info "Mode: Local build"
    else
        print_info "Mode: Remote build"
        print_warning "Remote builds require >= \$50 USD account balance"
    fi
    
    local manifest_file="$SCRIPT_DIR/${module}.routes.json"
    local env_prefix=""
    if [[ -f "$manifest_file" ]]; then
        print_info "Route manifest: $manifest_file"
        env_prefix="CHUTES_ROUTE_MANIFEST=\"$manifest_file\" "
    fi
    
    # Build the command string for display
    local cmd="${env_prefix}chutes build \"${module}:chute\""
    [[ -n "$local_flag" ]] && cmd="$cmd $local_flag"
    [[ -n "$debug_flag" ]] && cmd="$cmd $debug_flag"
    cmd="$cmd --wait"
    
    echo ""
    print_cmd "$cmd"
    echo ""
    
    if ! confirm "Proceed with build?" "y"; then
        print_warning "Build cancelled"
        return 0
    fi
    
    ensure_venv
    
    # shellcheck disable=SC2086
    set +e
    if [[ -f "$manifest_file" ]]; then
        CHUTES_ROUTE_MANIFEST="$manifest_file" chutes build "${module}:chute" $local_flag $debug_flag --wait
    else
        chutes build "${module}:chute" $local_flag $debug_flag --wait
    fi
    build_status=$?
    set -e
    
    if [[ $build_status -eq 0 ]]; then
        print_success "Build complete"
    else
        print_error "Build failed (exit $build_status)"
        return $build_status
    fi
    
    # For local builds, test chutes-inspecto.so compatibility
    if $LOCAL_BUILD; then
        local image=$(get_image_name "$module")
        if [[ -n "$image" ]] && docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "^${image}$"; then
            echo ""
            if ! test_inspecto_hash "$image"; then
                print_error "Image may fail remote build due to Python/inspecto incompatibility"
            fi
        fi
    fi
}

show_running_chute_containers() {
    local containers
    containers=$(docker ps --filter "name=chute-" --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null)
    
    if [[ -n "$containers" ]] && [[ $(echo "$containers" | wc -l) -gt 1 ]]; then
        echo -e "\n${CYAN}── Running Chute Containers ──${NC}"
        echo "$containers"
        echo ""
    fi
}

show_running_chute_processes() {
    local procs
    procs=$(pgrep -af "chutes run" 2>/dev/null | grep -v grep || true)
    
    if [[ -n "$procs" ]]; then
        echo -e "\n${CYAN}── Running Chute Processes ──${NC}"
        echo "$procs" | while read -r line; do
            local pid=$(echo "$line" | awk '{print $1}')
            local cmd=$(echo "$line" | cut -d' ' -f2-)
            echo -e "  ${GREEN}PID $pid:${NC} $cmd"
        done
        echo ""
    fi
}

show_running_chutes() {
    show_running_chute_containers
    show_running_chute_processes
}

do_run() {
    local module="$1"
    local dev_flag=""
    local debug_flag=""
    local background="${2:-false}"
    
    if $DEV_MODE; then
        dev_flag="--dev"
    fi
    
    if $DEBUG_MODE; then
        debug_flag="--debug"
    fi
    
    print_header "Running: $module (Dev Mode)"
    
    # Build command string for display
    local cmd="CHUTES_EXECUTION_CONTEXT=REMOTE chutes run \"${module}:chute\""
    [[ -n "$dev_flag" ]] && cmd="$cmd $dev_flag"
    [[ -n "$debug_flag" ]] && cmd="$cmd $debug_flag"
    cmd="$cmd --port $PORT"
    
    print_info "Module: ${module}:chute"
    print_info "Port: $PORT"
    print_info "Mode: Development (runs on host)"
    print_warning "This mode requires models/services to be available locally"
    
    echo ""
    print_cmd "$cmd"
    echo ""
    
    if ! confirm "Start chute?" "y"; then
        print_warning "Cancelled"
        return 0
    fi
    
    ensure_venv
    
    local log_file="/tmp/chute-${module}-$$.log"
    
    print_info "Starting chute in background..."
    print_info "Log file: $log_file"
    echo ""
    
    # Run in background
    # shellcheck disable=SC2086
    CHUTES_EXECUTION_CONTEXT=REMOTE chutes run "${module}:chute" $dev_flag $debug_flag --port "$PORT" > "$log_file" 2>&1 &
    local pid=$!
    
    print_success "Started with PID: $pid"
    
    # Monitor loop
    local ready=false
    local max_checks=20
    local check_count=0
    
    while [[ $check_count -lt $max_checks ]]; do
        # Check if process is still running
        if ! kill -0 "$pid" 2>/dev/null; then
            print_error "Process stopped unexpectedly"
            echo -e "\n${YELLOW}Last logs:${NC}"
            tail -50 "$log_file" 2>/dev/null || true
            return 1
        fi
        
        # Print last 25 lines
        echo -e "\n${CYAN}── Logs (last 25 lines) ──${NC}"
        tail -25 "$log_file" 2>/dev/null || echo "(waiting for output...)"
        echo -e "${CYAN}───────────────────────────${NC}\n"
        
        # Check if ready
        if curl -s --max-time 2 "http://127.0.0.1:${PORT}/openapi.json" > /dev/null 2>&1; then
            ready=true
            break
        fi
        
        print_info "Waiting for chute... (check $((check_count + 1))/$max_checks)"
        sleep 15
        check_count=$((check_count + 1))
    done
    
    if $ready; then
        print_success "Chute is ready!"
        verify_chute_cords "$PORT" "$module"
        
        echo -e "\n${GREEN}Chute is running (PID: $pid). Commands:${NC}"
        echo -e "  ${BLUE}View logs:${NC}  tail -f $log_file"
        echo -e "  ${BLUE}Stop:${NC}       kill $pid"
        echo -e "  ${BLUE}Test:${NC}       curl http://127.0.0.1:${PORT}/openapi.json"
        echo ""
        
        if confirm "Tail logs?"; then
            tail -f "$log_file"
        fi
    else
        print_warning "Chute did not become ready in time (may still be loading)"
        echo -e "\n${BLUE}Process is still running (PID: $pid)${NC}"
        echo -e "  ${BLUE}View logs:${NC}  tail -f $log_file"
        echo -e "  ${BLUE}Stop:${NC}       kill $pid"
        
        if confirm "Stop process?"; then
            kill "$pid" 2>/dev/null || true
        fi
    fi
}

get_image_name() {
    local module="$1"
    local py_file="$SCRIPT_DIR/${module}.py"
    
    if [[ ! -f "$py_file" ]]; then
        echo ""
        return
    fi
    
    # Try to extract image name and tag using Python (handles variable references)
    local result
    result=$(python3 -c "
import re
import sys

content = open('$py_file').read()

# Try to find CHUTE_NAME and CHUTE_TAG variables first
name_match = re.search(r'^CHUTE_NAME\s*=\s*[\"\\']([^\"\\']+)[\"\\']', content, re.MULTILINE)
tag_match = re.search(r'^CHUTE_TAG\s*=\s*[\"\\']([^\"\\']+)[\"\\']', content, re.MULTILINE)

if name_match and tag_match:
    print(f'{name_match.group(1)}:{tag_match.group(1)}')
    sys.exit(0)

# Fallback: try to find name= and tag= in Image() constructor with string literals
name_match = re.search(r'Image\s*\([^)]*name\s*=\s*[\"\\']([^\"\\']+)[\"\\']', content, re.DOTALL)
tag_match = re.search(r'Image\s*\([^)]*tag\s*=\s*[\"\\']([^\"\\']+)[\"\\']', content, re.DOTALL)

if name_match and tag_match:
    print(f'{name_match.group(1)}:{tag_match.group(1)}')
" 2>/dev/null)
    
    echo "$result"
}

test_inspecto_hash() {
    local image="$1"
    
    print_info "Testing chutes-inspecto.so compatibility..."
    print_cmd "docker run --rm --entrypoint \"\" $image bash -c 'pip install chutes --upgrade >/dev/null 2>&1 && chutes run does_not_exist:chute --generate-inspecto-hash; echo EXIT:\$?'"
    echo ""
    
    local output
    output=$(docker run --rm --entrypoint "" "$image" bash -c 'pip install chutes --upgrade >/dev/null 2>&1 && chutes run does_not_exist:chute --generate-inspecto-hash; echo EXIT:$?' 2>&1)
    local exit_line
    exit_line=$(echo "$output" | grep -oE 'EXIT:[0-9]+' | tail -1)
    local exit_code="${exit_line#EXIT:}"
    
    echo "$output"
    echo ""
    
    if [[ "$exit_code" == "0" ]]; then
        print_success "chutes-inspecto.so test passed (exit 0)"
        return 0
    elif [[ "$exit_code" == "139" ]]; then
        print_error "chutes-inspecto.so SEGFAULT (exit 139) - Conda Python issue"
        return 1
    else
        print_warning "chutes-inspecto.so test exited with code $exit_code"
        return 1
    fi
}

verify_chute_cords() {
    local port="$1"
    local module="$2"
    
    print_header "Verifying Chute Cords"
    
    # Try to get OpenAPI schema which lists all endpoints
    local schema
    schema=$(curl -s --max-time 5 "http://127.0.0.1:${port}/openapi.json" 2>/dev/null)
    
    if [[ -n "$schema" ]]; then
        print_success "OpenAPI schema available"
        
        # Extract and display paths
        local paths
        paths=$(echo "$schema" | python3 -c "import sys, json; d=json.load(sys.stdin); print('\n'.join(d.get('paths', {}).keys()))" 2>/dev/null)
        
        if [[ -n "$paths" ]]; then
            echo -e "\n${BLUE}Available Cords:${NC}"
            echo "$paths" | while read -r path; do
                echo -e "  ${GREEN}•${NC} $path"
            done
            echo ""
            return 0
        fi
    fi
    
    print_warning "Could not verify cords (chute may still be loading)"
    return 1
}

get_api_key() {
    if [[ -n "${CHUTES_API_KEY:-}" ]]; then
        echo "$CHUTES_API_KEY"
        return 0
    fi

    local key_file="$HOME/.chutes/api_key"
    if [[ -f "$key_file" ]]; then
        local key
        key=$(head -n1 "$key_file" 2>/dev/null | tr -d '[:space:]')
        if [[ -n "$key" ]]; then
            echo "$key"
            return 0
        fi
    fi

    print_error "CHUTES_API_KEY not set and ~/.chutes/api_key missing"
    print_info "Create one with: chutes keys create <name>"
    print_info "Or export CHUTES_API_KEY=cpk_..."
    return 1
}

get_fingerprint() {
    if [[ -n "${CHUTES_FINGERPRINT:-}" ]]; then
        echo "$CHUTES_FINGERPRINT"
        return 0
    fi
    return 1
}

get_api_base_url() {
    local base_url=""
    base_url=$(grep -E "^base_url" "$HOME/.chutes/config.ini" 2>/dev/null | head -n1 | cut -d'=' -f2 | tr -d '[:space:]' || true)
    if [[ -z "$base_url" ]]; then
        base_url="https://api.chutes.ai"
    fi
    echo "$base_url"
}

do_run_docker() {
    local module="$1"
    
    print_header "Run in Docker: $module"
    
    # Get image name from module
    local image=$(get_image_name "$module")
    if [[ -z "$image" ]]; then
        print_error "Could not determine image name from $module.py"
        return 1
    fi
    
    # Check if image exists
    if ! docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "^${image}$"; then
        print_error "Image '$image' not found. Build it first (option 3)."
        return 1
    fi
    
    # Get username from config
    local username=$(get_username)
    
    # Check if this is a wrapped image (has passthrough in the module)
    local is_wrapped=false
    if grep -q "passthrough=True" "$SCRIPT_DIR/${module}.py" 2>/dev/null; then
        is_wrapped=true
    fi
    
    print_info "Image: $image"
    print_info "Ports: $PORT, 8001, 8020, 8080"
    print_info "GPU: enabled"
    print_info "Username: $username"
    if $is_wrapped; then
        print_info "Mode: Wrapped image (runs base services + chutes)"
    else
        print_info "Mode: Standard chute"
    fi
    echo ""
    
    if ! confirm "Start container?" "y"; then
        print_warning "Cancelled"
        return 0
    fi
    
    # Stop any existing container with same name
    docker stop "chute-${module}" 2>/dev/null || true
    docker rm "chute-${module}" 2>/dev/null || true
    
    print_info "Starting container in background..."
    
    local container_id
    if $is_wrapped; then
        # For wrapped images: run original entrypoint in background, then start chutes
        # The original entrypoint starts the base services (e.g., XTTS, Whisper)
        container_id=$(docker run -d --rm --gpus all --name "chute-${module}" \
            -p "${PORT}:${PORT}" -p 8001:8001 -p 8020:8020 -p 8080:8080 \
            -e CHUTES_EXECUTION_CONTEXT=REMOTE \
            -e CHUTES_DEV_MODE=true \
            -e CHUTES_USERNAME="$username" \
            -w /app \
            "$image" \
            bash -c 'docker-entrypoint.sh & sleep 60 && chutes run '"${module}"':chute --dev --port '"$PORT")
    else
        # Standard chute: just run chutes directly
        container_id=$(docker run -d --rm --gpus all --name "chute-${module}" \
            -p "${PORT}:${PORT}" -p 8001:8001 -p 8020:8020 -p 8080:8080 \
            -e CHUTES_EXECUTION_CONTEXT=REMOTE \
            -e CHUTES_DEV_MODE=true \
            -e CHUTES_USERNAME="$username" \
            -w /app \
            --entrypoint chutes \
            "$image" \
            run "${module}:chute" --dev --port "$PORT")
    fi
    
    if [[ -z "$container_id" ]]; then
        print_error "Failed to start container"
        return 1
    fi
    
    print_success "Container started: ${container_id:0:12}"
    echo ""
    
    # Monitor loop
    local ready=false
    local max_checks=20  # 20 * 15s = 5 minutes
    local check_count=0
    
    while [[ $check_count -lt $max_checks ]]; do
        # Check if container is still running
        if ! docker ps -q --filter "id=$container_id" | grep -q .; then
            print_error "Container stopped unexpectedly"
            echo -e "\n${YELLOW}Last logs:${NC}"
            docker logs --tail 50 "$container_id" 2>&1 || true
            return 1
        fi
        
        # Print last 25 lines
        echo -e "\n${CYAN}── Container Logs (last 25 lines) ──${NC}"
        docker logs --tail 25 "$container_id" 2>&1
        echo -e "${CYAN}─────────────────────────────────────${NC}\n"
        
        # Check if ready
        if curl -s --max-time 2 "http://127.0.0.1:${PORT}/openapi.json" > /dev/null 2>&1; then
            ready=true
            break
        fi
        
        print_info "Waiting for chute... (check $((check_count + 1))/$max_checks)"
        sleep 15
        check_count=$((check_count + 1))
    done
    
    if $ready; then
        print_success "Chute is ready!"
        verify_chute_cords "$PORT" "$module"
        
        echo -e "\n${GREEN}Container is running. Commands:${NC}"
        echo -e "  ${BLUE}View logs:${NC}  docker logs -f chute-${module}"
        echo -e "  ${BLUE}Stop:${NC}       docker stop chute-${module}"
        echo -e "  ${BLUE}Test:${NC}       curl http://127.0.0.1:${PORT}/openapi.json"
        echo ""
        
        if confirm "Attach to container logs?"; then
            docker logs -f "chute-${module}"
        fi
    else
        print_error "Chute did not become ready in time"
        if confirm "Stop container?"; then
            docker stop "chute-${module}"
        fi
    fi
}

do_deploy() {
    local module="$1"
    local fee_flag=""
    local public_flag=""
    local debug_flag=""
    
    if $ACCEPT_FEE; then
        fee_flag="--accept-fee"
    fi
    
    if $PUBLIC_DEPLOY; then
        public_flag="--public"
    fi
    
    if $DEBUG_MODE; then
        debug_flag="--debug"
    fi
    
    print_header "Deploying: $module"
    
    # Show payment info
    echo -e "${BLUE}Payment Address:${NC}"
    grep -E "^address\\s*=" "$CHUTES_CONFIG" 2>/dev/null || print_warning "Payment address not found"
    echo ""
    
    print_warning "Deployment requires TAO balance and may incur fees"
    
    if ! $ACCEPT_FEE; then
        if confirm "Accept deployment fees?"; then
            fee_flag="--accept-fee"
        else
            print_warning "Deployment cancelled (fees not accepted)"
            return 0
        fi
    fi
    
    if ! $PUBLIC_DEPLOY; then
        if confirm "Make this deployment public?"; then
            public_flag="--public"
        fi
    fi
    
    # Build command string for display
    local cmd="chutes deploy \"${module}:chute\""
    [[ -n "$fee_flag" ]] && cmd="$cmd $fee_flag"
    [[ -n "$public_flag" ]] && cmd="$cmd $public_flag"
    [[ -n "$debug_flag" ]] && cmd="$cmd $debug_flag"
    
    echo ""
    print_cmd "$cmd"
    echo ""
    
    ensure_venv
    
    # shellcheck disable=SC2086
    chutes deploy "${module}:chute" $fee_flag $public_flag $debug_flag
    
    print_success "Deployment initiated"
}

list_deployed_chutes() {
    # Get list of deployed chutes (names only)
    # Accepts optional input: either a file path or pre-fetched text
    ensure_venv
    local input="${1:-}"
    local output=""
    
    if [[ -n "$input" && -f "$input" ]]; then
        output=$(cat "$input")
    else
        output="$input"
    fi
    
    if [[ -z "$output" ]]; then
        output=$(chutes chutes list 2>&1)
    fi
    
    # Check if any chutes found
    if echo "$output" | grep -q "Found 0 matching"; then
        return 0
    fi
    
    # Try to extract chute names from table output (box-drawn or plain)
    # Prefer the Name column in the table; fallback to whitespace-delimited lines
    printf "%s\n" "$output" | awk -F '│' '
        NF >= 3 {
            gsub(/^[ \t]+|[ \t]+$/, "", $2)
            name=$2
            if (name != "" && name != "Name" && name != "NAME" && name != "NAME ") {
                print name
            }
        }
    ' | grep -v "^[0-9]" 2>/dev/null || true
    
    printf "%s\n" "$output" | grep -E "^[a-z0-9]" | awk '{print $1}' | grep -v "^[0-9]" 2>/dev/null || true
}

select_chute_to_delete() {
    # Send all UI to stderr so command substitution only captures the name
    local chute_input=""
    echo "" >&2
    read -rp "Chute Name or ID to delete (press Enter to list): " chute_input
    if [[ -n "$chute_input" ]]; then
        echo "$chute_input"
        return 0
    fi

    print_header "Select Chute to Delete" >&2

    local lines_raw=""
    local lines=()
    local chute_ids=()
    local chute_names=()
    local chute_statuses=()
    local chute_slugs=()
    local choice=""

    if ! lines_raw="$(chutes_api_list_tsv "chutes")"; then
        print_error "Failed to list chutes (API call). Check network/auth." >&2
        return 1
    fi

    if [[ -n "$lines_raw" ]]; then
        mapfile -t lines <<<"$lines_raw"
    fi

    for line in ${lines[@]+"${lines[@]}"}; do
        IFS=$'\t' read -r cid cname cstatus cslug <<<"$line"
        [[ -n "$cid" && -n "$cname" ]] || continue
        chute_ids+=("$cid")
        chute_names+=("$cname")
        chute_statuses+=("$cstatus")
        chute_slugs+=("$cslug")
    done

    if [[ ${#chute_ids[@]} -eq 0 ]]; then
        print_warning "No deployed chutes found" >&2
        return 1
    fi

    echo -e "${BLUE}Deployed Chutes:${NC}" >&2
    local i=1
    while [[ $i -le ${#chute_ids[@]} ]]; do
        local idx=$((i-1))
        echo -e "  ${GREEN}$i)${NC} ${chute_names[$idx]} (${chute_statuses[$idx]})" >&2
        [[ -n "${chute_slugs[$idx]}" ]] && echo -e "      slug: ${chute_slugs[$idx]}" >&2
        echo -e "      id:   ${chute_ids[$idx]}" >&2
        i=$((i + 1))
    done
    echo -e "  ${YELLOW}b)${NC} Back" >&2
    echo "" >&2

    read -rp "Select chute to delete (1-${#chute_ids[@]}): " choice
    if [[ "$choice" == "b" || "$choice" == "B" ]]; then
        return 1
    fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#chute_ids[@]} ]]; then
        local idx=$((choice - 1))
        echo "${chute_ids[$idx]}|${chute_names[$idx]}"
        return 0
    fi

    print_error "Invalid selection" >&2
    return 1
}

do_delete() {
    local chute_ref="$1"
    local chute_id="${chute_ref%%|*}"
    local chute_name="${chute_ref#*|}"
    if [[ "$chute_id" == "$chute_name" ]]; then
        chute_name="$chute_id"
    fi
    
    print_header "Delete Chute: ${chute_name} (id: ${chute_id})"
    
    print_error "WARNING: This action is permanent!"
    echo ""
    
    if ! confirm "Are you sure you want to delete '${chute_name}' (id: ${chute_id})?"; then
        print_info "Deletion cancelled"
        return 0
    fi
    
    read -rp "Type the chute id to confirm: " confirm_id
    if [[ "$confirm_id" != "$chute_id" ]]; then
        print_error "IDs don't match. Deletion cancelled."
        return 1
    fi
    
    echo ""
    print_cmd "chutes chutes delete \"$chute_id\""
    echo ""
    
    ensure_venv
    chutes chutes delete "$chute_id"
    
    print_success "Chute deleted"
}

list_built_images() {
    # Get list of built images (names only from chutes images list)
    # Accepts optional input: either a file path or pre-fetched text
    local input="${1:-}"
    local output=""
    
    if [[ -n "$input" && -f "$input" ]]; then
        output=$(cat "$input")
    else
        output="$input"
    fi
    
    if [[ -z "$output" ]]; then
        ensure_venv
        output=$(chutes images list 2>&1)
    fi
    
    if printf "%s\n" "$output" | grep -q "Found 0 matching"; then
        return 0
    fi
    
    printf "%s\n" "$output" | awk -F '│' '
        NF >= 3 {
            gsub(/^[ \t]+|[ \t]+$/, "", $2)
            name=$2
            if (name != "" && name != "Name" && name != "NAME") {
                print name
            }
        }
    ' | grep -v "^[0-9]" 2>/dev/null || true
}

select_image_to_delete() {
    # Send all UI to stderr so command substitution only captures the name
    local image_input=""
    echo "" >&2
    read -rp "Image Name or ID to delete (press Enter to list): " image_input
    if [[ -n "$image_input" ]]; then
        echo "$image_input"
        return 0
    fi

    print_header "Select Image to Delete" >&2

    local lines_raw=""
    local lines=()
    local image_ids=()
    local image_names=()
    local image_tags=()
    local image_statuses=()
    local choice=""

    if ! lines_raw="$(chutes_api_list_tsv "images")"; then
        print_error "Failed to list images (API call). Check network/auth." >&2
        return 1
    fi

    if [[ -n "$lines_raw" ]]; then
        mapfile -t lines <<<"$lines_raw"
    fi

    for line in ${lines[@]+"${lines[@]}"}; do
        IFS=$'\t' read -r iid iname itag istatus <<<"$line"
        [[ -n "$iid" && -n "$iname" ]] || continue
        image_ids+=("$iid")
        image_names+=("$iname")
        image_tags+=("${itag:-unknown}")
        image_statuses+=("${istatus:-unknown}")
    done

    if [[ ${#image_ids[@]} -eq 0 ]]; then
        print_warning "No built images found" >&2
        return 1
    fi

    echo -e "${BLUE}Built Images:${NC}" >&2
    local i=1
    while [[ $i -le ${#image_ids[@]} ]]; do
        local idx=$((i-1))
        echo -e "  ${GREEN}$i)${NC} ${image_names[$idx]}:${image_tags[$idx]} (${image_statuses[$idx]})" >&2
        echo -e "      id: ${image_ids[$idx]}" >&2
        i=$((i + 1))
    done
    echo -e "  ${YELLOW}b)${NC} Back" >&2
    echo "" >&2

    read -rp "Select image to delete (1-${#image_ids[@]}): " choice
    if [[ "$choice" == "b" || "$choice" == "B" ]]; then
        return 1
    fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#image_ids[@]} ]]; then
        local idx=$((choice - 1))
        echo "${image_ids[$idx]}|${image_names[$idx]}|${image_tags[$idx]}"
        return 0
    fi

    print_error "Invalid selection" >&2
    return 1
}

do_delete_image() {
    local image_ref="$1"
    local image_id="${image_ref%%|*}"
    local rest="${image_ref#*|}"
    local image_name="${rest%%|*}"
    local image_tag="${rest#*|}"
    
    print_header "Delete Image: ${image_name}:${image_tag} (id: ${image_id})"
    
    print_error "WARNING: This action is permanent!"
    echo ""
    
    if ! confirm "Are you sure you want to delete '${image_name}:${image_tag}' (id: ${image_id})?"; then
        print_info "Deletion cancelled"
        return 0
    fi
    
    read -rp "Type the image id to confirm: " confirm_id
    if [[ "$confirm_id" != "$image_id" ]]; then
        print_error "IDs don't match. Deletion cancelled."
        return 1
    fi
    
    echo ""
    print_cmd "chutes images delete \"$image_id\""
    echo ""
    
    ensure_venv
    chutes images delete "$image_id"
    local status=$?
    if [[ $status -eq 0 ]]; then
        print_success "Image deleted"
    else
        print_error "Failed to delete image (exit $status)"
    fi
}

chutes_supports_stream_logs() {
    local help_text
    help_text=$(chutes warmup --help 2>&1 || true)
    [[ "$help_text" == *"--stream-logs"* ]]
}

do_check_logs_legacy_poll() {
    local chute_name="$1"
    
    print_header "Instance Logs (legacy polling): $chute_name"

    local api_key
    api_key=$(get_api_key) || return 1
    local base_url
    base_url=$(get_api_base_url)

    while true; do
        # Get chute JSON and extract instances
        local tmp_output
        tmp_output=$(mktemp)
        if ! chutes chutes get "$chute_name" >"$tmp_output" 2>&1; then
            print_error "Failed to get chute info for $chute_name"
            rm -f "$tmp_output"
            sleep 5
            continue
        fi

        local instance_ids
        instance_ids=$(python3 - "$tmp_output" <<'PYCODE'
import json, re, sys
path = sys.argv[1]
try:
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    match = re.search(r'\{[\s\S]*\}', text)
    if not match:
        sys.exit(0)
    data = json.loads(match.group())
    instances = data.get("instances") or []
    if not instances:
        sys.exit(0)
    
    def sort_key(inst):
        # Prefer active and verified instances
        return (not inst.get("active", False), not inst.get("verified", False), inst.get("last_verified_at") or "")
    
    instances = sorted(instances, key=sort_key)
    print("\n".join(inst["instance_id"] for inst in instances))
except Exception:
    sys.exit(0)
PYCODE
)
        rm -f "$tmp_output"

        if [[ -z "$instance_ids" ]]; then
            print_warning "No instances found for $chute_name. Retrying in 3s..."
            sleep 3
            continue
        fi

        mapfile -t ids_array <<< "$instance_ids"
        print_info "Found ${#ids_array[@]} instance(s). Iterating to find available logs..."

        for instance_id in "${ids_array[@]}"; do
            [[ -z "$instance_id" ]] && continue
            
            print_info "Checking logs for instance: $instance_id"
            local logs_url="${base_url}/instances/${instance_id}/logs"
            
            # We use --fail to make curl return non-zero on 4xx/5xx
            # We also want to see if it starts streaming. 
            # If it fails immediately, we try next.
            set +e
            curl --fail -N -H "Authorization: Bearer ${api_key}" "$logs_url"
            local curl_status=$?
            set -e
            
            if [[ $curl_status -eq 0 ]]; then
                # If curl exited with 0, it means it completed or was interrupted by user.
                # If it was interrupted (Ctrl+C), we should exit the script.
                # In most shells, Ctrl+C sends SIGINT to the foreground process group.
                # If the user stopped it, we are done.
                return 0
            fi
            
            print_warning "Logs unavailable for $instance_id (exit $curl_status). Trying next..."
        done
        
        print_warning "All instances checked, none providing logs. Restarting search in 3s..."
        sleep 3
    done
}

do_check_logs() {
    local chute_name="$1"

    print_header "Warmup + Stream Logs: $chute_name"
    ensure_venv

    if chutes_supports_stream_logs; then
        local -a cmd=(chutes warmup "$chute_name" --stream-logs)
        if $DEBUG_MODE; then
            cmd+=(--debug)
        fi

        print_info "Using SDK watcher mode (auto warmup + instance watch)."
        print_cmd "${cmd[*]}"

        set +e
        "${cmd[@]}"
        local warmup_status=$?
        set -e

        if [[ $warmup_status -eq 0 ]]; then
            return 0
        fi
        if [[ $warmup_status -eq 130 ]]; then
            return 130
        fi

        print_warning "SDK watcher failed (exit $warmup_status). Falling back to legacy polling mode."
    else
        print_warning "Installed chutes CLI does not support --stream-logs; using legacy polling mode."
    fi

    do_check_logs_legacy_poll "$chute_name"
}

select_chute_for_warmup() {
    # Send all UI to stderr so command substitution only captures the name
    local chute_input=""
    echo "" >&2
    read -rp "Chute Name or ID to warmup (press Enter to list): " chute_input
    if [[ -n "$chute_input" ]]; then
        echo "$chute_input"
        return 0
    fi

    print_header "Select Chute to Warmup" >&2

    local lines_raw=""
    local lines=()
    local chute_ids=()
    local chute_names=()
    local chute_statuses=()
    local chute_slugs=()
    local choice=""

    if ! lines_raw="$(chutes_api_list_tsv "chutes")"; then
        print_error "Failed to list chutes (API call). Check network/auth." >&2
        return 1
    fi

    if [[ -n "$lines_raw" ]]; then
        mapfile -t lines <<<"$lines_raw"
    fi

    for line in ${lines[@]+"${lines[@]}"}; do
        IFS=$'\t' read -r cid cname cstatus cslug <<<"$line"
        [[ -n "$cid" && -n "$cname" ]] || continue
        chute_ids+=("$cid")
        chute_names+=("$cname")
        chute_statuses+=("$cstatus")
        chute_slugs+=("$cslug")
    done

    if [[ ${#chute_ids[@]} -eq 0 ]]; then
        print_warning "No deployed chutes found" >&2
        return 1
    fi

    echo -e "${BLUE}Deployed Chutes:${NC}" >&2
    local i=1
    while [[ $i -le ${#chute_ids[@]} ]]; do
        local idx=$((i-1))
        echo -e "  ${GREEN}$i)${NC} ${chute_names[$idx]} (${chute_statuses[$idx]})" >&2
        [[ -n "${chute_slugs[$idx]}" ]] && echo -e "      slug: ${chute_slugs[$idx]}" >&2
        echo -e "      id:   ${chute_ids[$idx]}" >&2
        i=$((i + 1))
    done
    echo -e "  ${YELLOW}b)${NC} Back" >&2
    echo "" >&2

    read -rp "Select chute to warm up (1-${#chute_ids[@]}): " choice
    if [[ "$choice" == "b" || "$choice" == "B" ]]; then
        return 1
    fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#chute_ids[@]} ]]; then
        local idx=$((choice - 1))
        echo "${chute_ids[$idx]}|${chute_names[$idx]}"
        return 0
    fi

    print_error "Invalid selection" >&2
    return 1
}

do_warmup() {
    local chute_ref="$1"
    local chute_id="${chute_ref%%|*}"
    local chute_name="${chute_ref#*|}"
    if [[ "$chute_id" == "$chute_name" ]]; then
        chute_name="$chute_id"
    fi
    print_header "Warmup: ${chute_name} (id: ${chute_id})"
    
    ensure_venv
    
    print_cmd "chutes warmup \"${chute_id}\""
    echo ""
    
    if chutes warmup "${chute_id}"; then
        print_success "Warmup triggered for ${chute_name}"
    else
        print_error "Warmup failed for ${chute_name}"
        return 1
    fi
}

do_keep_warm() {
    local chute_ref="$1"
    local chute_id="${chute_ref%%|*}"
    local chute_name="${chute_ref#*|}"
    if [[ "$chute_id" == "$chute_name" ]]; then
        chute_name="$chute_id"
    fi
    
    read -rp "Warmup interval seconds [300]: " interval
    interval=${interval:-300}
    if ! [[ "$interval" =~ ^[0-9]+$ ]] || [[ "$interval" -le 0 ]]; then
        print_error "Interval must be a positive integer"
        return 1
    fi
    
    print_header "Keep Warm: ${chute_name} (id: ${chute_id}) every ${interval}s"
    print_info "Press Ctrl+C to stop."
    ensure_venv
    
    while true; do
        print_cmd "chutes warmup \"${chute_id}\""
        chutes warmup "${chute_id}" || print_warning "Warmup failed for ${chute_name}"
        sleep "$interval"
    done
}

do_link_bittensor_wallet() {
    print_header "Link Bittensor Wallet (existing Chutes account)"

    local fingerprint=""
    if fingerprint=$(get_fingerprint); then
        : # ok
    else
        read -rsp "Chutes fingerprint: " fingerprint
        echo ""
        fingerprint=$(printf '%s' "$fingerprint" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        if [[ -z "$fingerprint" ]]; then
            print_error "Fingerprint is required (set CHUTES_FINGERPRINT or paste it here)"
            return 1
        fi
    fi
    fingerprint=$(printf '%s' "$fingerprint" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    fingerprint="${fingerprint#Bearer }"
    fingerprint="${fingerprint#bearer }"
    fingerprint=$(printf '%s' "$fingerprint" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [[ -z "$fingerprint" ]]; then
        print_error "Fingerprint is required"
        return 1
    fi
    if [[ "$fingerprint" == cpk_* || "$fingerprint" == cak_* ]]; then
        print_error "API keys do not work for /users/change_bt_auth; provide your fingerprint instead."
        return 1
    fi
    local base_url
    base_url=$(get_api_base_url)

    print_info "This will update /users/change_bt_auth and write: $CHUTES_CONFIG"
    print_info "Auth: uses your fingerprint (CHUTES_FINGERPRINT)"
    echo ""

    if ! confirm "Continue?" "y"; then
        print_warning "Cancelled"
        return 0
    fi

    local wallet_dir="$HOME/.bittensor/wallets"
    if [[ ! -d "$wallet_dir" ]]; then
        print_error "No bittensor wallets found at $wallet_dir"
        print_info "Create one with btcli wallet new_coldkey/new_hotkey, then re-run."
        return 1
    fi

    local default_wallet=""
    local wallet_count=0
    for d in "$wallet_dir"/*/; do
        [[ -d "$d" ]] || continue
        wallet_count=$((wallet_count + 1))
        [[ -z "$default_wallet" ]] && default_wallet="$(basename "$d")"
    done
    if [[ $wallet_count -eq 0 ]]; then
        print_error "No wallets found in $wallet_dir"
        return 1
    fi

    local wallet_name=""
    read -rp "Wallet name (coldkey) [${default_wallet}]: " wallet_name
    wallet_name="${wallet_name:-$default_wallet}"
    if [[ ! -d "$wallet_dir/$wallet_name" ]]; then
        print_error "Wallet not found: $wallet_dir/$wallet_name"
        return 1
    fi

    local hotkey_dir="$wallet_dir/$wallet_name/hotkeys"
    if [[ ! -d "$hotkey_dir" ]]; then
        print_error "Hotkey directory not found: $hotkey_dir"
        return 1
    fi

    local default_hotkey=""
    local hotkey_count=0
    for f in "$hotkey_dir"/*; do
        [[ -f "$f" ]] || continue
        hotkey_count=$((hotkey_count + 1))
        [[ -z "$default_hotkey" ]] && default_hotkey="$(basename "$f")"
    done
    if [[ $hotkey_count -eq 0 ]]; then
        print_error "No hotkeys found in $hotkey_dir"
        return 1
    fi

    local hotkey_name=""
    read -rp "Hotkey name [${default_hotkey}]: " hotkey_name
    hotkey_name="${hotkey_name:-$default_hotkey}"

    local coldkey_pub_file="$wallet_dir/$wallet_name/coldkeypub.txt"
    local hotkey_file="$hotkey_dir/$hotkey_name"
    if [[ ! -f "$coldkey_pub_file" ]]; then
        print_error "Coldkey pub file not found: $coldkey_pub_file"
        return 1
    fi
    if [[ ! -f "$hotkey_file" ]]; then
        print_error "Hotkey file not found: $hotkey_file"
        return 1
    fi

    local coldkey_ss58
    coldkey_ss58=$(head -n1 "$coldkey_pub_file" 2>/dev/null | tr -d '[:space:]')
    if [[ -z "$coldkey_ss58" ]]; then
        print_error "Failed to read coldkey ss58 from $coldkey_pub_file"
        return 1
    fi

    local parsed
    parsed=$(python3 - "$hotkey_file" <<'PY'
import json, sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

def pick(d, keys):
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""

ss58 = pick(data, ["ss58Address", "ss58_address", "ss58"])
seed = pick(data, ["secretSeed", "secret_seed", "seed"])
if seed.startswith("0x"):
    seed = seed[2:]

if not ss58 or not seed:
    raise SystemExit("missing ss58Address or secretSeed")

print(f"{ss58}\t{seed}")
PY
) || {
        print_error "Failed to parse hotkey JSON (need ss58Address + secretSeed): $hotkey_file"
        return 1
    }

    local hotkey_ss58address=""
    local hotkey_seed=""
    IFS=$'\t' read -r hotkey_ss58address hotkey_seed <<<"$parsed"
    if [[ -z "$hotkey_ss58address" || -z "$hotkey_seed" ]]; then
        print_error "Failed to extract hotkey ss58/seed from $hotkey_file"
        return 1
    fi

    local username=""
    local user_id=""
    local payment_address=""
    local developer_payment_address=""
    local derived_user_id=""
    derived_user_id=$(python3 - "$fingerprint" <<'PY'
import hashlib, sys, uuid

fingerprint = sys.argv[1]
fingerprint_hash = hashlib.blake2b(fingerprint.encode()).hexdigest()
print(uuid.uuid5(uuid.NAMESPACE_OID, fingerprint_hash))
PY
) || true

    echo ""
    [[ -n "$derived_user_id" ]] && print_info "Derived user_id: ${derived_user_id}"
    print_info "Coldkey: ${coldkey_ss58}"
    print_info "Hotkey:  ${hotkey_ss58address}"
    echo ""

    if ! confirm "Update /users/change_bt_auth now?" "y"; then
        print_warning "Cancelled"
        return 0
    fi

    local payload
    payload=$(printf '{"coldkey":"%s","hotkey":"%s"}' "$coldkey_ss58" "$hotkey_ss58address")

    local resp_tmp
    resp_tmp=$(mktemp)
    local code
    code=$(curl -sS --connect-timeout 10 --max-time 30 -o "$resp_tmp" -w "%{http_code}" -X POST "${base_url}/users/change_bt_auth" \
        -H "Authorization: ${fingerprint}" \
        -H "Content-Type: application/json" \
        -d "$payload" || true)
    if [[ ! "$code" =~ ^2 ]]; then
        print_error "Failed to update /users/change_bt_auth (HTTP $code)"
        head -c 300 "$resp_tmp" 2>/dev/null || true
        echo ""
        rm -f "$resp_tmp"
        return 1
    fi

    local fields
    fields=$(python3 - "$resp_tmp" <<'PY'
import json, sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

def find_first(obj, keys):
    if isinstance(obj, dict):
        for k in keys:
            v = obj.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        for v in obj.values():
            r = find_first(v, keys)
            if r:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_first(v, keys)
            if r:
                return r
    return ""

username = find_first(data, ["username", "user_name", "name"])
user_id = find_first(data, ["user_id", "id", "uid"])
pay = find_first(data, ["payment_address", "paymentAddress", "address"])
devpay = find_first(data, ["developer_payment_address", "developerPaymentAddress", "developer_address", "developerAddress"])

print("\t".join([username, user_id, pay, devpay]))
PY
) || true
    IFS=$'\t' read -r username user_id payment_address developer_payment_address <<<"$fields"

    if [[ -z "$user_id" && -n "$derived_user_id" ]]; then
        user_id="$derived_user_id"
    fi
    [[ -n "$username" && -n "$user_id" ]] && print_info "Account: ${username} (${user_id})"

    if [[ -z "$username" || -z "$user_id" ]]; then
        print_error "Could not determine username/user_id from /users/change_bt_auth. Re-run, or fill config.ini manually."
        rm -f "$resp_tmp"
        return 1
    fi

    if [[ -z "$payment_address" ]]; then
        print_warning "No payment address detected from API (config will contain an empty payment address)"
    fi

    rm -f "$resp_tmp"

    mkdir -p "$(dirname "$CHUTES_CONFIG")"
    local old_umask
    old_umask=$(umask)
    umask 077

    local cfg_tmp
    cfg_tmp=$(mktemp)
    cat > "$cfg_tmp" <<EOF
[api]
base_url = ${base_url}

[auth]
username = ${username}
user_id = ${user_id}
hotkey_seed = ${hotkey_seed}
hotkey_name = ${hotkey_name}
hotkey_ss58address = ${hotkey_ss58address}

[payment]
address = ${payment_address}
developer_payment_address = ${developer_payment_address}
EOF
    mv "$cfg_tmp" "$CHUTES_CONFIG"
    chmod 600 "$CHUTES_CONFIG" 2>/dev/null || true
    umask "$old_umask" 2>/dev/null || true

    print_success "Linked wallet + wrote config: $CHUTES_CONFIG"
}

show_account_info() {
    print_header "Account Info"
    
    if [[ ! -f "$CHUTES_CONFIG" ]]; then
        print_warning "Not configured. Run setup.sh, or use Account → Link Bittensor Wallet."
        return 1
    fi
    
    local username=$(get_username)
    local user_id=$(get_user_id)
    local payment=$(grep -E "^address\s*=" "$CHUTES_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    local balance=""
    local live_fields=""

    if live_fields=$(chutes_api_get_self_tsv 2>/dev/null); then
        IFS=$'\t' read -r username user_id payment balance <<<"$live_fields"
    fi
    
    echo -e "${BLUE}Username:${NC}        ${username:-<not set>}"
    echo -e "${BLUE}User ID:${NC}         ${user_id:-<not set>}"
    echo -e "${BLUE}Payment Address:${NC} ${payment:-<not set>}"
    [[ -n "$balance" ]] && echo -e "${BLUE}Balance:${NC}         ${balance}"
    echo ""
    print_info "Add TAO to payment address for deployments"
    print_info "Account needs >= \$50 USD balance for remote builds"
}

do_create_from_image() {
    print_header "Create Chute from Docker Image"
    
    local image
    read -rp "Docker Image (e.g. elbios/xtts-whisper:latest): " image
    if [[ -z "$image" ]]; then
        print_error "Image is required"
        return 1
    fi
    
    local name
    read -rp "Chute Name (optional, press Enter for auto): " name
    
    local gpus
    read -rp "GPUs (e.g. all, 0, none) [${DEFAULT_DISCOVER_GPUS}]: " gpus
    gpus=${gpus:-$DEFAULT_DISCOVER_GPUS}
    
    local -a env_args=()
    echo -e "\nEnter Environment Variables (KEY=VALUE). Press Enter on empty line to finish."
    while true; do
        local env_var
        read -rp "ENV: " env_var
        if [[ -z "$env_var" ]]; then
            break
        fi
        env_args+=("--env" "$env_var")
    done
    
    echo ""
    print_info "Creating chute definition..."
    
    ensure_venv
    
    local cmd=(
        python3 "$SCRIPT_DIR/tools/create_chute_from_image.py" "$image"
        "--gpus" "$gpus"
        "--startup-delay" "$DEFAULT_STARTUP_DELAY"
        "--probe-timeout" "$DEFAULT_PROBE_TIMEOUT"
        "--interactive"
    )
    if [[ -n "$name" ]]; then
        cmd+=("--name" "$name")
    fi
    
    if [[ ${#env_args[@]} -gt 0 ]]; then
        cmd+=("${env_args[@]}")
    fi
    
    print_cmd "${cmd[*]}"
    "${cmd[@]}"
}

# =============================================================================
# Interactive Menu
# =============================================================================

show_menu() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Chutes Utils Hub${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${CYAN}── ACCOUNT ───────────────────────────────────────────────────────${NC}"
    echo -e "  ${GREEN} 1)${NC} Show Account Info (wallet + balance)"
    echo -e "  ${GREEN} 2)${NC} Link Bittensor Wallet (existing Chutes account)"
    echo ""
    echo -e "  ${CYAN}── BUILDING ──────────────────────────────────────────────────────${NC}"
    echo -e "  ${GREEN} 3)${NC} Build Chute (from local deploy_*.py)"
    echo -e "  ${GREEN} 4)${NC} Discover & Define (create from existing Docker image)"
    echo ""
    echo -e "  ${CYAN}── LOCAL TESTING ─────────────────────────────────────────────────${NC}"
    echo -e "  ${GREEN} 5)${NC} Run in Docker (GPU sanity test)"
    echo -e "  ${GREEN} 6)${NC} Run in Dev Mode (host process)"
    echo ""
    echo -e "  ${CYAN}── CLOUD OPERATIONS ──────────────────────────────────────────────${NC}"
    echo -e "  ${GREEN} 7)${NC} Deploy to Chutes.ai"
    echo -e "  ${GREEN} 8)${NC} Check Chute Status (health + instances)"
    echo -e "  ${GREEN} 9)${NC} Warmup + Stream Logs (auto-watch)"
    echo -e "  ${GREEN}10)${NC} Warmup Chute (trigger manual spin-up)"
    echo -e "  ${GREEN}11)${NC} Keep Chute Warm (continuous ping loop)"
    echo ""
    echo -e "  ${CYAN}── MANAGEMENT ────────────────────────────────────────────────────${NC}"
    echo -e "  ${GREEN}12)${NC} List & Delete Chutes"
    echo -e "  ${GREEN}13)${NC} List & Delete Images"
    echo ""
    echo -e "  ${GREEN} q)${NC} Quit"
    echo ""
}

show_build_menu() {
    echo ""
    echo -e "${CYAN}── Build Options ──${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} Local build (no upload)"
    echo -e "  ${GREEN}2)${NC} Remote build (requires \$50 balance)"
    echo -e "  ${GREEN}b)${NC} Back"
    echo ""
}

# =============================================================================
# Parse Arguments
# =============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            SHOW_HELP=true
            shift
            ;;
        --list-images)
            LIST_IMAGES=true
            shift
            ;;
        --list-chutes)
            LIST_CHUTES=true
            shift
            ;;
        --build)
            BUILD_MODULE="$2"
            shift 2
            ;;
        --discover)
            DISCOVER_MODULE="$2"
            shift 2
            ;;
        --deploy)
            DEPLOY_MODULE="$2"
            shift 2
            ;;
        --run-docker)
            RUN_DOCKER_MODULE="$2"
            shift 2
            ;;
        --run)
            RUN_MODULE="$2"
            shift 2
            ;;
        --status)
            STATUS_CHUTE="$2"
            shift 2
            ;;
        --delete)
            DELETE_CHUTE="$2"
            shift 2
            ;;
        --logs)
            LOGS_CHUTE="$2"
            shift 2
            ;;
        --local)
            LOCAL_BUILD=true
            shift
            ;;
        --accept-fee)
            ACCEPT_FEE=true
            shift
            ;;
        --public)
            PUBLIC_DEPLOY=true
            shift
            ;;
        --dev)
            DEV_MODE=true
            shift
            ;;
        --debug)
            DEBUG_MODE=true
            shift
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# =============================================================================
# Main
# =============================================================================

main() {
    # Handle flags
    if $SHOW_HELP; then
        show_usage
        exit 0
    fi

    # Check prerequisites
    ensure_venv
    
    if $LIST_IMAGES; then
        ensure_chutes_config
        do_list_images
        exit 0
    fi
    
    if $LIST_CHUTES; then
        ensure_chutes_config
        do_list_chutes
        exit 0
    fi
    
    if [[ -n "$STATUS_CHUTE" ]]; then
        ensure_chutes_config
        do_chute_status "$STATUS_CHUTE"
        exit 0
    fi
    
    if [[ -n "$BUILD_MODULE" ]]; then
        ensure_chutes_config
        do_build "$BUILD_MODULE"
        exit 0
    fi

    if [[ -n "$DISCOVER_MODULE" ]]; then
        run_route_discovery_for_module "$DISCOVER_MODULE"
        exit $?
    fi
    
    if [[ -n "$RUN_DOCKER_MODULE" ]]; then
        ensure_chutes_config
        do_run_docker "$RUN_DOCKER_MODULE"
        exit 0
    fi
    
    if [[ -n "$RUN_MODULE" ]]; then
        ensure_chutes_config
        do_run "$RUN_MODULE"
        exit 0
    fi
    
    if [[ -n "$DEPLOY_MODULE" ]]; then
        ensure_chutes_config
        do_deploy "$DEPLOY_MODULE"
        exit 0
    fi
    
    if [[ -n "$DELETE_CHUTE" ]]; then
        ensure_chutes_config
        do_delete "$DELETE_CHUTE"
        exit 0
    fi
    
    if [[ -n "$LOGS_CHUTE" ]]; then
        ensure_chutes_config
        do_check_logs "$LOGS_CHUTE"
        exit 0
    fi
    
    # Interactive mode
    while true; do
        show_menu
        read -rp "Select option: " choice
        
        case $choice in
            1)
                show_account_info
                ;;
            2)
                do_link_bittensor_wallet
                ;;
            3)
                ensure_chutes_config || continue
                module=$(select_module "Select module to build") || continue
                if ! prompt_route_discovery_before_build "$module"; then
                    continue
                fi
                echo ""
                show_build_menu
                read -rp "Select build type [1]: " bchoice
                bchoice=${bchoice:-1}
                case $bchoice in
                    1)
                        LOCAL_BUILD=true
                        do_build "$module"
                        LOCAL_BUILD=false
                        ;;
                    2)
                        LOCAL_BUILD=false
                        do_build "$module"
                        ;;
                    b|B) continue ;;
                    *) print_error "Invalid option" ;;
                esac
                ;;
            4)
                ensure_chutes_config || continue
                do_create_from_image
                ;;
            5)
                # Run in Docker (for wrapped services like XTTS)
                ensure_chutes_config || continue
                show_running_chute_containers
                module=$(select_module "Select module to run in Docker") || continue
                read -rp "Port [8000]: " port_input
                PORT="${port_input:-8000}"
                do_run_docker "$module"
                PORT=8000
                ;;
            6)
                # Run dev mode (for Python chutes, runs on host)
                ensure_chutes_config || continue
                show_running_chute_processes
                module=$(select_module "Select module for dev mode") || continue
                DEV_MODE=true
                read -rp "Port [8000]: " port_input
                PORT="${port_input:-8000}"
                do_run "$module"
                DEV_MODE=false
                PORT=8000
                ;;
            7)
                ensure_chutes_config || continue
                module=$(select_module "Select module to deploy") || continue
                do_deploy "$module"
                ;;
            8)
                ensure_chutes_config || continue
                chute_name=$(select_chute_for_status) || continue
                do_chute_status "$chute_name"
                ;;
            9)
                ensure_chutes_config || continue
                chute_name=$(select_chute_for_status) || continue
                do_check_logs "$chute_name"
                ;;
            10)
                ensure_chutes_config || continue
                chute_name=$(select_chute_for_warmup) || continue
                do_warmup "$chute_name"
                ;;
            11)
                ensure_chutes_config || continue
                chute_name=$(select_chute_for_warmup) || continue
                do_keep_warm "$chute_name"
                ;;
            12)
                ensure_chutes_config || continue
                chute_name=$(select_chute_to_delete) || continue
                if [[ -n "$chute_name" ]]; then
                    do_delete "$chute_name"
                fi
                ;;
            13)
                ensure_chutes_config || continue
                image_name=$(select_image_to_delete) || continue
                if [[ -n "$image_name" ]]; then
                    do_delete_image "$image_name"
                fi
                ;;
            q|Q)
                echo "Goodbye!"
                exit 0
                ;;
            *)
                print_error "Invalid option"
                ;;
        esac
    done
}

main
