#!/usr/bin/env bash
set -euo pipefail

blue="\033[0;94m"
green="\033[0;92m"
yellow="\033[0;93m"
red="\033[0;91m"
NC="\033[0m"

cat <<'EOF'
      _
     | |
   __| | _   _  _ __   _ __   _   _
  / _` || | | || '_ \ | '_ \ | | | |
 | (_| || |_| || |_) || |_) || |_| |
  \__,_| \__,_|| .__/ | .__/  \__, |
               | |    | |      __/ |
               |_|    |_|     |___/

secure one-time download server

EOF

api_hist=""
NGROK_URL="http://127.0.0.1:4040/api/requests/http?limit=1"
PROJECT_DIR=""
APT_UPDATED=0
NGROK_PID=""
BASIC_AUTH=""
LOG_FILE="/tmp/duppy_ngrok.log"
SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_MODE=""
BIND_ADDRESS="127.0.0.1"
CERT_DIR="${SCRIPT_ROOT}/.tls"
CERT_FILE="${CERT_DIR}/duppy.crt"
KEY_FILE="${CERT_DIR}/duppy.key"
NGROK_DOMAIN="${DUPPY_NGROK_DOMAIN:-}"
CLIENT_NAME="${1:-}"
CLIENT_SLUG=""
SHARE_TOKEN=""
SHARE_DIR=""
SHARE_PATH=""
BASIC_USERNAME=""
BASIC_PASSWORD=""
RUNTIME_ID=""

if [ -n "${VIRTUAL_ENV:-}" ]; then
    VENV_DIR="${VIRTUAL_ENV%/}"
    USING_USER_VENV=1
else
    VENV_DIR="${SCRIPT_ROOT}/duppy-venv"
    USING_USER_VENV=0
fi
PYTHON_BIN="${VENV_DIR}/bin/python3"

log_info() {
    printf "\n[${green}+${NC}] %s" "$1"
}

log_warn() {
    printf "\n[${yellow}*${NC}] %s" "$1"
}

log_error() {
    printf "\n[${red}!${NC}] %s" "$1"
}

command_exists() {
    command -v "$1" > /dev/null 2>&1
}

sanitize_client_name() {
    local raw="$1"
    local slug
    slug=$(echo "$raw" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//; s/-+/-/g')
    if [ -z "$slug" ]; then
        slug="client"
    fi
    CLIENT_SLUG="$slug"
}

generate_uuid() {
    if command_exists uuidgen; then
        uuidgen | tr 'A-Z' 'a-z'
        return
    fi
    python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
}

prepare_runtime_identity() {
    sanitize_client_name "$CLIENT_NAME"
    RUNTIME_ID="$(generate_uuid)"
    SHARE_TOKEN="${CLIENT_SLUG}-${RUNTIME_ID}"
    SHARE_PATH="/${SHARE_TOKEN}"
    local rand_suffix
    rand_suffix=$(printf "%04d" $(((RANDOM % 9000) + 1000)))
    BASIC_USERNAME="${CLIENT_SLUG}-${rand_suffix}"
    BASIC_PASSWORD="$(openssl rand -hex 12)"
    BASIC_AUTH="${BASIC_USERNAME}:${BASIC_PASSWORD}"
}

set_run_mode() {
    local mode=$1
    case "$mode" in
        internet)
            RUN_MODE="internet"
            BIND_ADDRESS="127.0.0.1"
            log_info "Internet mode selected (ngrok tunnel)"
            ;;
        local)
            RUN_MODE="local"
            BIND_ADDRESS="0.0.0.0"
            log_info "Local network mode selected"
            ;;
    esac
}

choose_run_mode() {
    if [ -n "${DUPPY_MODE:-}" ]; then
        local normalized="${DUPPY_MODE,,}"
        if [[ "$normalized" == "internet" || "$normalized" == "local" ]]; then
            set_run_mode "$normalized"
            return
        else
            log_error "Invalid DUPPY_MODE value '${DUPPY_MODE}'. Use 'internet' or 'local'."
            exit 1
        fi
    fi

    while true; do
        printf "\nSelect mode:\n  [1] Internet (ngrok tunnel)\n  [2] Local network only\n"
        read -r -p "[?] Enter choice [1/2]: " selection
        case "${selection:-1}" in
            ""|1)
                set_run_mode internet
                return
                ;;
            2)
                set_run_mode local
                return
                ;;
            *)
                log_warn "Invalid selection. Please choose 1 or 2."
            ;;
        esac
    done
}

require_client_name() {
    if [ -z "$CLIENT_NAME" ]; then
        log_error "Client name required. Usage: ./duppy.sh <client-name>"
        exit 1
    fi
}

run_privileged() {
    if command_exists sudo && [ "$EUID" -ne 0 ]; then
        sudo "$@"
    else
        "$@"
    fi
}

update_apt_cache_once() {
    if [ "$APT_UPDATED" -eq 0 ]; then
        log_info "Updating package index"
        if run_privileged apt-get update -y > /dev/null 2>&1; then
            APT_UPDATED=1
        else
            log_error "Cannot update package index. Exiting."
            exit 1
        fi
    fi
}

install_apt_package() {
    local package=$1
    update_apt_cache_once
    if run_privileged apt-get install -y "$package" > /dev/null 2>&1; then
        log_info "$package installed"
    else
        log_error "Failed to install $package"
        exit 1
    fi
}

ensure_command() {
    local cmd=$1
    local package=$2
    if command_exists "$cmd"; then
        return
    fi
    log_warn "$cmd not found. Installing $package."
    install_apt_package "$package"
}

install_python_module() {
    local module=$1
    log_info "Installing python module ${module}"
    if "$PYTHON_BIN" -m pip install "$module" > /dev/null 2>&1; then
        log_info "${module} installed"
    else
        log_error "Unable to install python module ${module}"
        exit 1
    fi
}

bootstrap_pip_with_get_pip() {
    local get_pip
    get_pip=$(mktemp -t duppy-get-pip-XXXXXX.py)
    if curl -fsSL https://bootstrap.pypa.io/get-pip.py -o "$get_pip"; then
        if "$PYTHON_BIN" "$get_pip" > /dev/null 2>&1; then
            rm -f "$get_pip"
            return 0
        fi
    fi
    rm -f "$get_pip"
    return 1
}

ensure_pip_in_venv() {
    if "$PYTHON_BIN" -m pip --version > /dev/null 2>&1; then
        return
    fi

    log_warn "Python virtual environment is missing pip, attempting to bootstrap it"
    if "$PYTHON_BIN" -m ensurepip --upgrade > /dev/null 2>&1; then
        log_info "pip installed in virtual environment"
        return
    fi

    log_warn "ensurepip unavailable. Falling back to get-pip bootstrap"
    if bootstrap_pip_with_get_pip; then
        log_info "pip installed in virtual environment"
        return
    fi

    log_error "Unable to install pip inside the virtual environment"
    exit 1
}

ensure_virtualenv() {
    if [ -x "$PYTHON_BIN" ]; then
        ensure_pip_in_venv
        if [ "$USING_USER_VENV" -eq 1 ]; then
            log_info "Using active python virtual environment at ${VENV_DIR}"
        else
            log_info "Using python virtual environment at ${VENV_DIR}"
        fi
        return
    fi

    if [ "$USING_USER_VENV" -eq 1 ]; then
        log_error "Active virtual environment at ${VENV_DIR} does not provide python3"
        exit 1
    fi

    log_info "Creating python virtual environment in ${VENV_DIR}"
    if python3 -m venv "$VENV_DIR" > /dev/null 2>&1; then
        log_info "Virtual environment created"
    else
        log_warn "python3 -m venv failed; installing python3-venv and retrying"
        install_apt_package python3-venv
        if python3 -m venv "$VENV_DIR" > /dev/null 2>&1; then
            log_info "Virtual environment created after installing python3-venv"
        else
            log_error "Unable to create python virtual environment"
            exit 1
        fi
    fi

    ensure_pip_in_venv
}

ensure_tls_certificate() {
    if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
        log_info "Using existing TLS certificate (${CERT_FILE})"
        return
    fi

    log_info "Generating self-signed TLS certificate for local mode"
    if mkdir -p "$CERT_DIR" && openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_FILE" -out "$CERT_FILE" -subj "/CN=duppy.local" > /dev/null 2>&1; then
        log_info "TLS certificate created at ${CERT_DIR}"
    else
        log_error "Failed to create TLS certificate in ${CERT_DIR}"
        exit 1
    fi
}

prompt_yes_no() {
    local prompt=$1
    local response
    while true; do
        read -r -p "[?] ${prompt} [y/n]: " response
        case "${response,,}" in
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) log_warn "Please enter yes or no." ;;
        esac
    done
}

install_ngrok() {
    log_info "Adding ngrok apt repository"
    if ! run_privileged curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc -o /etc/apt/trusted.gpg.d/ngrok.asc; then
        log_error "Failed to download ngrok signing key"
        exit 1
    fi
    if ! printf "deb https://ngrok-agent.s3.amazonaws.com buster main\n" | run_privileged tee /etc/apt/sources.list.d/ngrok.list > /dev/null; then
        log_error "Failed to configure ngrok repository"
        exit 1
    fi
    APT_UPDATED=0
    install_apt_package ngrok
}

configure_ngrok_auth() {
    local config_file="${HOME}/.config/ngrok/ngrok.yml"
    if [ -f "$config_file" ] && grep -q "authtoken" "$config_file" 2>/dev/null; then
        return
    fi

    log_info "Ngrok auth token not detected."
    read -r -p "[?] Enter ngrok auth token (leave blank to skip): " auth_token
    if [ -n "${auth_token:-}" ]; then
        if ngrok config add-authtoken "$auth_token" > /dev/null 2>&1; then
            log_info "Auth token added"
        else
            log_warn "Unable to add auth token automatically. Please configure it manually."
        fi
    fi
}

ensure_ngrok() {
    if command_exists ngrok; then
        log_info "ngrok already installed"
    else
        log_warn "ngrok is not installed"
        if prompt_yes_no "Install ngrok now?"; then
            install_ngrok
        else
            log_error "ngrok is required. Exiting."
            exit 1
        fi
    fi
    configure_ngrok_auth
}

ensure_gunicorn() {
    if "$PYTHON_BIN" -c "import gunicorn" > /dev/null 2>&1; then
        log_info "gunicorn already installed"
        return
    fi

    log_warn "gunicorn python module is not installed"
    if prompt_yes_no "Install gunicorn now?"; then
        install_python_module gunicorn
    else
        log_error "gunicorn is required. Exiting."
        exit 1
    fi
}

ensure_flask() {
    if "$PYTHON_BIN" -c "import flask" > /dev/null 2>&1; then
        log_info "Flask already installed"
        return
    fi
    install_python_module flask
}

configure_app_auth_env() {
    export DUPPY_BASIC_AUTH="$BASIC_AUTH"
    export DUPPY_USERNAME="$BASIC_USERNAME"
    export DUPPY_PASSWORD="$BASIC_PASSWORD"
    export DUPPY_ENDPOINT="$SHARE_TOKEN"
    export DUPPY_PAYLOAD_DIR="$SHARE_DIR"
    export DUPPY_CLIENT_NAME="$CLIENT_NAME"
    export DUPPY_REQUIRE_BASIC_AUTH="1"
}

ensure_base_dependencies() {
    ensure_command curl curl
    ensure_command jq jq
    ensure_command git git
    ensure_command pgrep procps
    ensure_command python3 python3
    ensure_command openssl openssl
    if ! python3 -m pip --version > /dev/null 2>&1; then
        log_warn "python3-pip not found. Installing."
        install_apt_package python3-pip
    fi
    if ! python3 -c "import ensurepip" > /dev/null 2>&1; then
        log_warn "python3-venv (ensurepip) not found. Installing."
        install_apt_package python3-venv
    elif ! python3 -m venv --help > /dev/null 2>&1; then
        log_warn "python3-venv not found. Installing."
        install_apt_package python3-venv
    fi
}

resolve_project_dir() {
    local script_root="$SCRIPT_ROOT"

    if [ -f "${script_root}/Uploader.py" ]; then
        PROJECT_DIR="${script_root}"
        return
    fi

    if [ -d "${script_root}/duppy" ] && [ -f "${script_root}/duppy/Uploader.py" ]; then
        PROJECT_DIR="${script_root}/duppy"
        return
    fi

    log_info "Pulling duppy repository"
    if git clone https://github.com/deeexcee-io/duppy.git "${script_root}/duppy" > /dev/null 2>&1; then
        PROJECT_DIR="${script_root}/duppy"
        log_info "duppy repository cloned"
    else
        log_error "Unable to clone duppy repository"
        exit 1
    fi
}

prepare_share_directory() {
    local short_id="${RUNTIME_ID%%-*}"
    if [ -z "$short_id" ]; then
        short_id="${RUNTIME_ID:0:8}"
    fi
    SHARE_DIR="${PROJECT_DIR}/${CLIENT_SLUG}-${short_id}"
    if mkdir -p "$SHARE_DIR"; then
        log_info "Created client folder at ${SHARE_DIR}"
    else
        log_error "Unable to create client folder at ${SHARE_DIR}"
        exit 1
    fi
}

start_gunicorn() {
    log_info "Starting gunicorn server"
    local gunicorn_args=(-D -w 2 -b "${BIND_ADDRESS}:8000" --chdir "$PROJECT_DIR")
    if [ "$RUN_MODE" == "local" ]; then
        ensure_tls_certificate
        gunicorn_args+=(--keyfile "$KEY_FILE" --certfile "$CERT_FILE")
    fi
    if "$PYTHON_BIN" -m gunicorn "${gunicorn_args[@]}" Uploader:Uploader > /dev/null 2>&1; then
        log_info "gunicorn started successfully"
    else
        log_error "gunicorn failed to start"
        exit 1
    fi
}

start_ngrok() {
    log_info "Starting ngrok tunnel on port 8000"
    local ngrok_args=(http 8000 --basic-auth="$BASIC_AUTH")
    if [ -n "$NGROK_DOMAIN" ]; then
        log_info "Using custom ngrok domain ${NGROK_DOMAIN}"
        ngrok_args+=(--domain="$NGROK_DOMAIN")
    fi
    ngrok "${ngrok_args[@]}" > "$LOG_FILE" 2>&1 &
    NGROK_PID=$!
    sleep 1
    if ps -p "$NGROK_PID" > /dev/null 2>&1; then
        log_info "ngrok started successfully (pid ${NGROK_PID})"
    else
        log_error "ngrok failed to start. Check ${LOG_FILE} for details."
        exit 1
    fi
}

get_ngrok_public_url() {
    local attempt
    local public_url=""
    for attempt in $(seq 1 15); do
        if response=$(curl -sf http://127.0.0.1:4040/api/tunnels); then
            public_url=$(echo "$response" | jq -r '.tunnels[0].public_url // empty')
            if [ -n "$public_url" ]; then
                print_share_details "$public_url"
                return
            fi
        fi
        sleep 1
    done
    log_warn "Unable to determine ngrok public URL"
}

check_ngrok_api() {
    local api_data=""
    if ! api_data=$(curl -sf "$NGROK_URL" 2> /dev/null); then
        return
    fi

    local latest_request
    local latest_response
    latest_request=$(echo "$api_data" | jq -r '.requests[0].request.uri // empty')
    latest_response=$(echo "$api_data" | jq -r '.requests[0].response.status // empty')

    if [ -z "$latest_request" ] || [ -z "$latest_response" ]; then
        return
    fi

    if [ "$api_data" == "$api_hist" ]; then
        return
    fi

    local request_path="$latest_request"
    request_path="${request_path%%\?*}"
    if [ -n "$request_path" ]; then
        request_path="${request_path%/}"
    fi

    if [ "$request_path" == "$SHARE_PATH" ]; then
        printf "\n[${green}+${NC}] Download page visited"
    elif [[ "$request_path" == ${SHARE_PATH}/* ]]; then
        local downloaded_file="${request_path#${SHARE_PATH}/}"
        printf "\n[${green}+${NC}] New File Downloaded: ${green}%s${NC}" "$downloaded_file"
    fi

    api_hist="$api_data"
}

print_share_details() {
    local base_url="${1%/}"
    local share_url="${base_url}/${SHARE_TOKEN}"
    printf "\n[${green}+${NC}] Share URL: ${green}%s${NC}" "$share_url"
    printf "\n[${green}+${NC}] Username: ${green}%s${NC}" "$BASIC_USERNAME"
    printf "\n[${green}+${NC}] Password: ${green}%s${NC}" "$BASIC_PASSWORD"
    printf "\n[${green}+${NC}] Place files in: ${green}%s${NC}" "$SHARE_DIR"
}

print_local_access_info() {
    local host_ip
    host_ip=$(hostname -I 2> /dev/null | awk '{print $1}')
    if [ -z "$host_ip" ]; then
        host_ip="127.0.0.1"
    fi
    local base_url="https://${host_ip}:8000"
    print_share_details "$base_url"
    printf "\n[${green}+${NC}] Certificate path: ${CERT_FILE}"
    printf "\n[${green}+${NC}] Share/trust the certificate so testers avoid warnings."
}

cleanup() {
    printf "\n\n${yellow}Shutting down...${NC}\n"
    if pkill -f "gunicorn.*Uploader:Uploader" > /dev/null 2>&1; then
        log_info "gunicorn stopped"
    else
        log_warn "gunicorn process not found"
    fi

    if [ -n "$NGROK_PID" ] && ps -p "$NGROK_PID" > /dev/null 2>&1; then
        kill "$NGROK_PID"
        log_info "ngrok stopped"
    else
        pkill -x ngrok > /dev/null 2>&1 || true
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM

main() {
    require_client_name
    choose_run_mode
    ensure_base_dependencies
    ensure_virtualenv
    ensure_flask
    ensure_gunicorn
    resolve_project_dir
    prepare_runtime_identity
    prepare_share_directory
    configure_app_auth_env
    start_gunicorn

    if [ "$RUN_MODE" == "internet" ]; then
        ensure_ngrok
        start_ngrok
        get_ngrok_public_url

        while true; do
            check_ngrok_api
            sleep 0.5
        done
    else
        print_local_access_info
        while true; do
            sleep 2
        done
    fi
}

main
