#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Chutes Setup Script
# =============================================================================
# Interactive setup with optional force flags for automation
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
CHUTES_CONFIG="$HOME/.chutes/config.ini"
CHUTES_CONFIG_EXAMPLE="$SCRIPT_DIR/config.ini.example"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Defaults
FORCE_DEPS=false
FORCE_VENV=false
FORCE_WALLET=false
FORCE_CHUTES=false
SKIP_DEPS=false
WALLET_NAME=""
HOTKEY_NAME=""
SHOW_HELP=false
NON_INTERACTIVE=false

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

confirm() {
    local prompt="$1"
    local default="${2:-n}"
    
    if $NON_INTERACTIVE; then
        [[ "$default" == "y" ]] && return 0 || return 1
    fi
    
    if [[ "$default" == "y" ]]; then
        read -rp "$prompt [Y/n]: " response
        [[ -z "$response" || "$response" =~ ^[Yy] ]]
    else
        read -rp "$prompt [y/N]: " response
        [[ "$response" =~ ^[Yy] ]]
    fi
}

prompt_input() {
    local prompt="$1"
    local default="${2:-}"
    local result
    
    if [[ -n "$default" ]]; then
        read -rp "$prompt [$default]: " result
        echo "${result:-$default}"
    else
        read -rp "$prompt: " result
        echo "$result"
    fi
}

show_usage() {
    cat << EOF
${CYAN}Chutes Setup Script${NC}

${YELLOW}Usage:${NC}
  ./setup.sh [OPTIONS]

${YELLOW}Options:${NC}
  -h, --help            Show this help message
  -f, --force           Force all operations (recreate venv, wallet, config)
  --force-deps          Force reinstall dependencies
  --force-venv          Force recreate virtual environment
  --force-wallet        Force create new wallet (will prompt for names)
  --force-chutes        Force chutes registration
  --skip-deps           Skip dependency installation
  --wallet-name NAME    Wallet name for creation/detection
  --hotkey-name NAME    Hotkey name for creation/detection
  --non-interactive     Run without prompts (use defaults)

${YELLOW}Examples:${NC}
  ./setup.sh                          # Interactive mode
  ./setup.sh --force                  # Force all steps
  ./setup.sh --wallet-name mywallet   # Use specific wallet
  ./setup.sh --skip-deps              # Skip uv/pip installs

EOF
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
        -f|--force)
            FORCE_DEPS=true
            FORCE_VENV=true
            FORCE_WALLET=true
            FORCE_CHUTES=true
            shift
            ;;
        --force-deps)
            FORCE_DEPS=true
            shift
            ;;
        --force-venv)
            FORCE_VENV=true
            shift
            ;;
        --force-wallet)
            FORCE_WALLET=true
            shift
            ;;
        --force-chutes)
            FORCE_CHUTES=true
            shift
            ;;
        --skip-deps)
            SKIP_DEPS=true
            shift
            ;;
        --wallet-name)
            WALLET_NAME="$2"
            shift 2
            ;;
        --hotkey-name)
            HOTKEY_NAME="$2"
            shift 2
            ;;
        --non-interactive)
            NON_INTERACTIVE=true
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

if $SHOW_HELP; then
    show_usage
    exit 0
fi

# =============================================================================
# Dependency Checks
# =============================================================================

check_uv() {
    if command -v uv &> /dev/null; then
        print_success "uv is installed: $(uv --version 2>/dev/null || echo 'unknown version')"
        return 0
    fi
    return 1
}

check_btcli() {
    if command -v btcli &> /dev/null; then
        print_success "btcli is installed"
        return 0
    fi
    return 1
}

check_chutes() {
    if command -v chutes &> /dev/null; then
        print_success "chutes CLI is installed"
        return 0
    fi
    return 1
}

install_uv() {
    print_info "Installing uv..."
    if [[ "$(uname)" == "Darwin" ]]; then
        if command -v brew &> /dev/null; then
            brew install uv
        else
            curl -LsSf https://astral.sh/uv/install.sh | sh
        fi
    else
        curl -LsSf https://astral.sh/uv/install.sh | sh
    fi
}

setup_venv() {
    if [[ -d "$VENV_DIR" ]] && ! $FORCE_VENV; then
        print_success "Virtual environment exists: $VENV_DIR"
        if confirm "Recreate virtual environment?"; then
            rm -rf "$VENV_DIR"
        else
            return 0
        fi
    fi
    
    print_info "Creating virtual environment with Python 3.11..."
    uv venv --python 3.11 "$VENV_DIR"
    print_success "Virtual environment created"
}

install_packages() {
    print_info "Installing chutes and bittensor..."
    source "$VENV_DIR/bin/activate"
    uv pip install chutes 'bittensor<8'
    print_success "Packages installed"
}

# =============================================================================
# Wallet Functions
# =============================================================================

list_wallets() {
    local wallet_dir="$HOME/.bittensor/wallets"
    if [[ -d "$wallet_dir" ]]; then
        local wallets=()
        for w in "$wallet_dir"/*/; do
            if [[ -d "$w" ]]; then
                wallets+=("$(basename "$w")")
            fi
        done
        if [[ ${#wallets[@]} -gt 0 ]]; then
            echo "${wallets[@]}"
            return 0
        fi
    fi
    return 1
}

list_hotkeys() {
    local wallet_name="$1"
    local hotkey_dir="$HOME/.bittensor/wallets/$wallet_name/hotkeys"
    if [[ -d "$hotkey_dir" ]]; then
        local hotkeys=()
        for h in "$hotkey_dir"/*; do
            if [[ -f "$h" ]]; then
                hotkeys+=("$(basename "$h")")
            fi
        done
        if [[ ${#hotkeys[@]} -gt 0 ]]; then
            echo "${hotkeys[@]}"
            return 0
        fi
    fi
    return 1
}

show_wallet_info() {
    local wallet_dir="$HOME/.bittensor/wallets"
    
    print_header "Wallet Information"
    
    if [[ ! -d "$wallet_dir" ]]; then
        print_warning "No wallets found at $wallet_dir"
        return 1
    fi
    
    for w in "$wallet_dir"/*/; do
        if [[ -d "$w" ]]; then
            local wname="$(basename "$w")"
            echo -e "${GREEN}Wallet:${NC} $wname"
            
            # Check for coldkey
            if [[ -f "$w/coldkey" ]]; then
                echo -e "  ${BLUE}├─${NC} coldkey: ${GREEN}exists${NC}"
            elif [[ -f "$w/coldkeypub.txt" ]]; then
                echo -e "  ${BLUE}├─${NC} coldkey: ${YELLOW}pubkey only${NC}"
            fi
            
            # List hotkeys
            local hotkey_dir="$w/hotkeys"
            local hotkey_count=0
            if [[ -d "$hotkey_dir" ]]; then
                shopt -s nullglob
                for h in "$hotkey_dir"/*; do
                    if [[ -f "$h" ]]; then
                        hotkey_count=$((hotkey_count + 1))
                        echo -e "  ${BLUE}└─${NC} hotkey: $(basename "$h")"
                    fi
                done
                shopt -u nullglob
            fi
            if [[ $hotkey_count -eq 0 ]]; then
                echo -e "  ${BLUE}└─${NC} hotkeys: ${YELLOW}none${NC}"
            fi
            echo ""
        fi
    done
    return 0
}

create_wallet() {
    source "$VENV_DIR/bin/activate"
    
    local wname="${WALLET_NAME:-}"
    local hname="${HOTKEY_NAME:-}"
    
    if [[ -z "$wname" ]]; then
        wname=$(prompt_input "Enter wallet name" "chutes")
    fi
    
    if [[ -z "$hname" ]]; then
        hname=$(prompt_input "Enter hotkey name" "default")
    fi
    
    print_info "Creating coldkey for wallet: $wname"
    echo -e "${YELLOW}IMPORTANT: Save your mnemonic securely!${NC}"
    btcli wallet new_coldkey --n_words 24 --wallet.name "$wname"
    
    print_info "Creating hotkey: $hname"
    btcli wallet new_hotkey --wallet.name "$wname" --n_words 24 --wallet.hotkey "$hname"
    
    print_success "Wallet '$wname' with hotkey '$hname' created"
    
    # Store for later use
    WALLET_NAME="$wname"
    HOTKEY_NAME="$hname"
}

# =============================================================================
# Chutes Functions
# =============================================================================

check_chutes_config() {
    if [[ -f "$CHUTES_CONFIG" ]]; then
        print_success "Chutes config exists: $CHUTES_CONFIG"
        return 0
    fi
    return 1
}

show_chutes_config() {
    if [[ ! -f "$CHUTES_CONFIG" ]]; then
        print_warning "No chutes config found at $CHUTES_CONFIG"
        return 1
    fi
    
    print_header "Chutes Account Info"
    
    # Parse config.ini
    local username=$(grep -E "^username\s*=" "$CHUTES_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    local user_id=$(grep -E "^user_id\s*=" "$CHUTES_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    local hotkey_name=$(grep -E "^hotkey_name\s*=" "$CHUTES_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    local hotkey_ss58=$(grep -E "^hotkey_ss58address\s*=" "$CHUTES_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    local payment_addr=$(grep -E "^address\s*=" "$CHUTES_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    
    echo -e "${BLUE}Username:${NC}    ${username:-<not set>}"
    echo -e "${BLUE}User ID:${NC}     ${user_id:-<not set>}"
    echo -e "${BLUE}Hotkey:${NC}      ${hotkey_name:-<not set>}"
    echo -e "${BLUE}SS58 Address:${NC} ${hotkey_ss58:-<not set>}"
    echo -e "${BLUE}Payment:${NC}     ${payment_addr:-<not set>}"
}

register_chutes() {
    source "$VENV_DIR/bin/activate"
    
    print_info "Starting chutes registration..."
    echo -e "${YELLOW}You will need:${NC}"
    echo "  1. Your desired username"
    echo "  2. Select your coldkey/hotkey"
    echo "  3. A registration token from: https://rtok.chutes.ai/users/registration_token"
    echo ""
    
    chutes register
    
    if [[ -f "$CHUTES_CONFIG" ]]; then
        print_success "Registration complete!"
        show_chutes_config
    else
        print_error "Registration may have failed - no config found"
    fi
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

    return 1
}

get_api_base_url() {
    if [[ -n "${CHUTES_API_BASE_URL:-}" ]]; then
        echo "$CHUTES_API_BASE_URL"
        return 0
    fi
    echo "https://api.chutes.ai"
}

link_existing_chutes_account() {
    print_header "Link Existing Chutes Account (website → CLI)"

    print_info "This updates /users/change_bt_auth and writes: $CHUTES_CONFIG"
    print_info "Requires a Chutes API key (CHUTES_API_KEY or ~/.chutes/api_key)"
    echo ""

    local api_key=""
    if api_key=$(get_api_key); then
        : # ok
    else
        if $NON_INTERACTIVE; then
            print_error "CHUTES_API_KEY not set and ~/.chutes/api_key missing (required for linking)"
            return 1
        fi
        api_key=$(prompt_input "Chutes API key (cpk_...)" "")
        if [[ -z "$api_key" ]]; then
            print_error "API key is required"
            return 1
        fi
        if confirm "Save API key to ~/.chutes/api_key for later?" "y"; then
            mkdir -p "$HOME/.chutes"
            printf "%s\n" "$api_key" > "$HOME/.chutes/api_key"
            chmod 600 "$HOME/.chutes/api_key" 2>/dev/null || true
            print_success "Saved ~/.chutes/api_key"
        fi
    fi

    local base_url
    base_url=$(get_api_base_url)

    # Pick wallet/hotkey (defaults from prior steps if available)
    local wallet_name="${WALLET_NAME:-}"
    if [[ -z "$wallet_name" ]]; then
        local wallets
        if wallets=$(list_wallets); then
            wallet_name=$(prompt_input "Wallet name (coldkey)" "$(echo "$wallets" | awk '{print $1}')")
        else
            wallet_name=$(prompt_input "Wallet name (coldkey)" "")
        fi
    else
        wallet_name=$(prompt_input "Wallet name (coldkey)" "$wallet_name")
    fi
    if [[ -z "$wallet_name" ]]; then
        print_error "Wallet name is required"
        return 1
    fi

    local hotkey_name="${HOTKEY_NAME:-}"
    if [[ -z "$hotkey_name" ]]; then
        local hotkeys
        if hotkeys=$(list_hotkeys "$wallet_name"); then
            hotkey_name=$(prompt_input "Hotkey name" "$(echo "$hotkeys" | awk '{print $1}')")
        else
            hotkey_name=$(prompt_input "Hotkey name" "default")
        fi
    else
        hotkey_name=$(prompt_input "Hotkey name" "$hotkey_name")
    fi
    if [[ -z "$hotkey_name" ]]; then
        print_error "Hotkey name is required"
        return 1
    fi

    local wallet_dir="$HOME/.bittensor/wallets/$wallet_name"
    local coldkey_pub_file="$wallet_dir/coldkeypub.txt"
    local hotkey_file="$wallet_dir/hotkeys/$hotkey_name"
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

    local auth_header_primary="$api_key"
    local auth_header_secondary="Bearer ${api_key}"
    if [[ "$api_key" =~ ^[Bb]earer[[:space:]]+ ]]; then
        auth_header_primary="$api_key"
        auth_header_secondary="$api_key"
    fi

    local username=""
    local user_id=""
    local payment_address=""
    local developer_payment_address=""

    echo ""
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
        -H "Authorization: ${auth_header_primary}" \
        -H "Content-Type: application/json" \
        -d "$payload" || true)
    if [[ ! "$code" =~ ^2 ]] && [[ "$auth_header_secondary" != "$auth_header_primary" ]]; then
        code=$(curl -sS --connect-timeout 10 --max-time 30 -o "$resp_tmp" -w "%{http_code}" -X POST "${base_url}/users/change_bt_auth" \
            -H "Authorization: ${auth_header_secondary}" \
            -H "Content-Type: application/json" \
            -d "$payload" || true)
        if [[ "$code" =~ ^2 ]]; then
            local tmp="$auth_header_primary"
            auth_header_primary="$auth_header_secondary"
            auth_header_secondary="$tmp"
        fi
    fi
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

    rm -f "$resp_tmp"

    [[ -n "$username" && -n "$user_id" ]] && print_info "Account: ${username} (${user_id})"

    if [[ -z "$username" || -z "$user_id" ]]; then
        print_error "Could not determine username/user_id from /users/change_bt_auth. Re-run, or fill config.ini manually."
        return 1
    fi

    if [[ -z "$payment_address" && ! $NON_INTERACTIVE ]]; then
        payment_address=$(prompt_input "Payment address (TAO ss58) [optional]" "")
    fi

    if [[ -f "$CHUTES_CONFIG" && ! $FORCE_CHUTES ]]; then
        if ! confirm "Overwrite existing $CHUTES_CONFIG?" "y"; then
            print_warning "Cancelled"
            return 0
        fi
    fi

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
    show_chutes_config
}

# =============================================================================
# Interactive Menu
# =============================================================================

show_menu() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Chutes Setup${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} Setup (deps → venv → wallet → chutes)"
    echo -e "  ${GREEN}2)${NC} Wallet management"
    echo -e "  ${GREEN}3)${NC} Chutes account management"
    echo -e "  ${GREEN}4)${NC} Show current status"
    echo -e "  ${GREEN}q)${NC} Quit"
    echo ""
}

show_wallet_menu() {
    echo ""
    echo -e "${CYAN}── Wallet Management ──${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} Show existing wallets"
    echo -e "  ${GREEN}2)${NC} Create new wallet"
    echo -e "  ${GREEN}b)${NC} Back to main menu"
    echo ""
}

show_chutes_menu() {
    echo ""
    echo -e "${CYAN}── Chutes Account Management ──${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} Show current account info"
    echo -e "  ${GREEN}2)${NC} Register new account"
    echo -e "  ${GREEN}3)${NC} Link existing account to wallet (website → CLI)"
    echo -e "  ${GREEN}4)${NC} View config.ini.example"
    echo -e "  ${GREEN}b)${NC} Back to main menu"
    echo ""
}

show_status() {
    print_header "Current Status"
    
    echo -e "${BLUE}System Dependencies:${NC}"
    check_uv || print_warning "uv not found"
    
    echo ""
    echo -e "${BLUE}Venv Packages (in .venv):${NC}"
    # Check btcli/chutes in venv directly without sourcing
    if [[ -f "$VENV_DIR/bin/activate" ]]; then
        if [[ -x "$VENV_DIR/bin/btcli" ]]; then
            print_success "btcli installed in venv"
        else
            print_warning "btcli not installed in venv"
        fi
        if [[ -x "$VENV_DIR/bin/chutes" ]]; then
            print_success "chutes CLI installed in venv"
        else
            print_warning "chutes CLI not installed in venv"
        fi
        print_info "Activate with: source .venv/bin/activate"
    else
        print_warning "Virtual environment not set up"
    fi
    
    echo ""
    echo -e "${BLUE}Virtual Environment:${NC}"
    if [[ -d "$VENV_DIR" ]]; then
        print_success "$VENV_DIR exists"
    else
        print_warning "Not created"
    fi
    
    echo ""
    echo -e "${BLUE}Wallets:${NC}"
    local wallets
    if wallets=$(list_wallets); then
        print_success "Found wallets: $wallets"
    else
        print_warning "No wallets found"
    fi
    
    echo ""
    echo -e "${BLUE}Chutes Config (~/.chutes/config.ini):${NC}"
    if [[ -f "$CHUTES_CONFIG" ]]; then
        print_success "Config exists"
        local username=$(grep -E "^username\s*=" "$CHUTES_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        local hotkey_name=$(grep -E "^hotkey_name\s*=" "$CHUTES_CONFIG" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        if [[ -n "$username" ]]; then
            echo -e "       User: ${GREEN}$username${NC}"
        fi
        if [[ -n "$hotkey_name" ]]; then
            echo -e "       Hotkey: ${GREEN}$hotkey_name${NC}"
        fi
    else
        print_warning "Not found at $CHUTES_CONFIG"
        print_info "Run option 3 → Register, or copy config.ini.example"
    fi
}

run_full_setup() {
    print_header "Setup Wizard"
    
    # =========================================================================
    # Step 1: Check system dependencies
    # =========================================================================
    echo -e "${CYAN}[1/4]${NC} ${BLUE}System Dependencies${NC}"
    echo ""
    
    if check_uv; then
        : # already printed success
    else
        if $FORCE_DEPS || confirm "Install uv (required for venv)?"; then
            install_uv
        else
            print_error "uv is required to continue"
            return 1
        fi
    fi
    
    # =========================================================================
    # Step 2: Virtual environment & packages
    # =========================================================================
    echo ""
    echo -e "${CYAN}[2/4]${NC} ${BLUE}Virtual Environment & Packages${NC}"
    echo ""
    
    local venv_needs_setup=false
    local packages_need_install=false
    
    if [[ -d "$VENV_DIR" ]]; then
        print_success "Virtual environment exists: .venv"
        if $FORCE_VENV; then
            venv_needs_setup=true
        elif confirm "Recreate virtual environment?"; then
            venv_needs_setup=true
        fi
    else
        print_warning "Virtual environment not found"
        venv_needs_setup=true
    fi
    
    # Check if packages are installed
    if [[ -x "$VENV_DIR/bin/btcli" ]] && [[ -x "$VENV_DIR/bin/chutes" ]]; then
        print_success "btcli and chutes CLI installed in venv"
    else
        packages_need_install=true
    fi
    
    if $venv_needs_setup; then
        setup_venv
        packages_need_install=true
    fi
    
    if $packages_need_install; then
        install_packages
    fi
    
    # Activate venv for subsequent steps
    source "$VENV_DIR/bin/activate"
    
    # =========================================================================
    # Step 3: Wallet check
    # =========================================================================
    echo ""
    echo -e "${CYAN}[3/4]${NC} ${BLUE}Bittensor Wallet${NC}"
    echo ""
    
    local wallets
    if wallets=$(list_wallets); then
        print_success "Found wallets: $wallets"
        show_wallet_info
        if $FORCE_WALLET || confirm "Create a new wallet?"; then
            create_wallet
        else
            if [[ -z "$WALLET_NAME" ]]; then
                WALLET_NAME=$(echo "$wallets" | awk '{print $1}')
                print_info "Using wallet: $WALLET_NAME"
            fi
        fi
    else
        print_warning "No wallets found in ~/.bittensor/wallets/"
        if confirm "Create a new wallet now?" "y"; then
            create_wallet
        else
            print_warning "Skipping wallet creation"
        fi
    fi
    
    # =========================================================================
    # Step 4: Chutes config check
    # =========================================================================
    echo ""
    echo -e "${CYAN}[4/4]${NC} ${BLUE}Chutes Account${NC}"
    echo ""
    
    if [[ -f "$CHUTES_CONFIG" ]]; then
        print_success "Chutes config exists: ~/.chutes/config.ini"
        show_chutes_config
        if $FORCE_CHUTES || confirm "Re-register with Chutes?"; then
            register_chutes
        fi
    else
        print_warning "Chutes config not found: ~/.chutes/config.ini"
        echo ""
        if confirm "Already have a Chutes account (website) and want to link this wallet?" "n"; then
            link_existing_chutes_account
        else
            echo -e "To register, you'll need a token from:"
            echo -e "  ${CYAN}https://rtok.chutes.ai/users/registration_token${NC}"
            echo ""
            if confirm "Register with Chutes now?" "y"; then
                register_chutes
            else
                print_warning "Skipping Chutes registration"
                print_info "You can link/register later via option 3 in the menu"
            fi
        fi
    fi
    
    # =========================================================================
    # Done
    # =========================================================================
    echo ""
    print_header "Setup Complete"
    show_status
}

# =============================================================================
# Main
# =============================================================================

main() {
    # Non-interactive full setup
    if $NON_INTERACTIVE || $FORCE_DEPS || $FORCE_VENV || $FORCE_WALLET || $FORCE_CHUTES; then
        run_full_setup
        exit 0
    fi
    
    # Interactive menu
    while true; do
        show_menu
        read -rp "Select option: " choice
        
        case $choice in
            1)
                run_full_setup
                ;;
            2)
                while true; do
                    show_wallet_menu
                    read -rp "Select option: " wchoice
                    case $wchoice in
                        1) show_wallet_info ;;
                        2)
                            if [[ ! -f "$VENV_DIR/bin/activate" ]]; then
                                print_error "Virtual environment required. Run option 1 first."
                            else
                                source "$VENV_DIR/bin/activate"
                                create_wallet
                            fi
                            ;;
                        b|B) break ;;
                        *) print_error "Invalid option" ;;
                    esac
                done
                ;;
            3)
                while true; do
                    show_chutes_menu
                    read -rp "Select option: " cchoice
                    case $cchoice in
                        1) show_chutes_config ;;
                        2)
                            if [[ ! -f "$VENV_DIR/bin/activate" ]]; then
                                print_error "Virtual environment required. Run option 1 first."
                            else
                                source "$VENV_DIR/bin/activate"
                                register_chutes
                            fi
                            ;;
                        3)
                            link_existing_chutes_account
                            ;;
                        4)
                            if [[ -f "$CHUTES_CONFIG_EXAMPLE" ]]; then
                                echo ""
                                cat "$CHUTES_CONFIG_EXAMPLE"
                                echo ""
                            else
                                print_error "config.ini.example not found"
                            fi
                            ;;
                        b|B) break ;;
                        *) print_error "Invalid option" ;;
                    esac
                done
                ;;
            4)
                show_status
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
