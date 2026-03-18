#!/usr/bin/env bash
set -euo pipefail

REPO="ygcaicn/gomitm"
APP="gomitm"
SERVICE_NAME="gomitm"
INSTALL_BIN="/usr/local/bin/${APP}"
INSTALL_ETC_DIR="/etc/${APP}"
INSTALL_SHARE_DIR="/usr/local/share/${APP}"
INSTALL_DATA_DIR="/var/lib/${APP}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

usage() {
  cat <<USAGE
Usage:
  install-release.sh install [version]
  install-release.sh remove

Examples:
  bash -c "\$(curl -L https://github.com/ygcaicn/gomitm/raw/main/install-release.sh)" @ install
  bash -c "\$(curl -L https://github.com/ygcaicn/gomitm/raw/main/install-release.sh)" @ remove
USAGE
}

log() {
  printf '[%s] %s\n' "${APP}" "$*"
}

err() {
  printf '[%s] ERROR: %s\n' "${APP}" "$*" >&2
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "Please run as root."
    exit 1
  fi
}

ensure_supported_os() {
  if [ "$(uname -s)" != "Linux" ]; then
    err "Unsupported OS: $(uname -s). Only Linux is supported."
    exit 1
  fi

  if [ ! -f /etc/os-release ]; then
    err "Unsupported Linux distribution (missing /etc/os-release)."
    exit 1
  fi

  # shellcheck source=/dev/null
  . /etc/os-release
  local distro="${ID:-}"
  local like="${ID_LIKE:-}"
  local supported=false

  case "$distro" in
    ubuntu|debian|rhel|centos|rocky|almalinux|fedora|arch|opensuse-leap|opensuse-tumbleweed)
      supported=true
      ;;
  esac

  if [ "$supported" = false ] && [ -n "$like" ]; then
    case " $like " in
      *" debian "*|*" ubuntu "*|*" rhel "*|*" fedora "*|*" suse "*|*" arch "*)
        supported=true
        ;;
    esac
  fi

  if [ "$supported" = false ]; then
    err "Unsupported Linux distribution: ${distro:-unknown}."
    err "Supported families: Debian/Ubuntu, RHEL/CentOS/Rocky/Alma, Fedora, Arch, openSUSE."
    exit 1
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    err "systemd is required but systemctl was not found."
    exit 1
  fi
}

map_arch() {
  case "$(uname -m)" in
    x86_64|amd64)
      echo "amd64"
      ;;
    aarch64|arm64)
      echo "arm64"
      ;;
    *)
      err "Unsupported architecture: $(uname -m). Only amd64 and arm64 are supported."
      exit 1
      ;;
  esac
}

fetch() {
  local url="$1"
  local out="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
    return
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
    return
  fi

  err "Neither curl nor wget was found."
  exit 1
}

get_latest_version() {
  local api="https://api.github.com/repos/${REPO}/releases/latest"
  local raw

  if command -v curl >/dev/null 2>&1; then
    raw="$(curl -fsSL "$api")"
  elif command -v wget >/dev/null 2>&1; then
    raw="$(wget -qO- "$api")"
  else
    err "Neither curl nor wget was found."
    exit 1
  fi

  local tag
  tag="$(printf '%s\n' "$raw" | sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"

  if [ -z "$tag" ]; then
    err "Failed to detect latest release tag from GitHub."
    exit 1
  fi

  echo "$tag"
}

patch_default_config() {
  local cfg="$1"

  sed -i.bak \
    -e 's#path: "\./modules/#path: "/usr/local/share/gomitm/modules/#g' \
    -e 's#ca_dir: "~/.gomitm/ca"#ca_dir: "/var/lib/gomitm/ca"#g' \
    -e 's#har_out: "\./tmp/session.har"#har_out: "/var/lib/gomitm/session.har"#g' \
    "$cfg"
  rm -f "${cfg}.bak"
}

ensure_service_user() {
  if id -u "$APP" >/dev/null 2>&1; then
    return
  fi

  local nologin
  nologin="$(command -v nologin || true)"
  if [ -z "$nologin" ]; then
    if [ -x /usr/sbin/nologin ]; then
      nologin="/usr/sbin/nologin"
    elif [ -x /sbin/nologin ]; then
      nologin="/sbin/nologin"
    else
      nologin="/bin/false"
    fi
  fi

  useradd --system --home "$INSTALL_DATA_DIR" --shell "$nologin" "$APP"
}

write_service() {
  cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=gomitm SOCKS5 MITM proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${APP}
Group=${APP}
WorkingDirectory=${INSTALL_DATA_DIR}
ExecStart=${INSTALL_BIN} serve --config ${INSTALL_ETC_DIR}/config.yaml
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${INSTALL_DATA_DIR}

[Install]
WantedBy=multi-user.target
UNIT
}

install_release() {
  local version="${1:-}"
  local arch
  arch="$(map_arch)"

  if [ -z "$version" ]; then
    version="$(get_latest_version)"
  fi

  if [[ "$version" != v* ]]; then
    err "Version must start with 'v', got: $version"
    exit 1
  fi

  local asset="${APP}_${version}_linux_${arch}.tar.gz"
  local url="https://github.com/${REPO}/releases/download/${version}/${asset}"
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  log "Installing ${APP} ${version} (${arch})"
  log "Downloading: ${url}"
  fetch "$url" "${tmpdir}/${asset}"

  tar -xzf "${tmpdir}/${asset}" -C "$tmpdir"

  local payload_dir
  payload_dir="$(find "$tmpdir" -maxdepth 1 -type d -name "${APP}_${version}_linux_${arch}" | head -n1)"
  if [ -z "$payload_dir" ] || [ ! -d "$payload_dir" ]; then
    err "Failed to locate extracted payload directory."
    exit 1
  fi

  install -d -m 0755 /usr/local/bin "$INSTALL_ETC_DIR" "$INSTALL_SHARE_DIR/modules" "$INSTALL_DATA_DIR"
  install -m 0755 "$payload_dir/$APP" "$INSTALL_BIN"

  cp -f "$payload_dir/modules/"* "$INSTALL_SHARE_DIR/modules/"

  if [ ! -f "$INSTALL_ETC_DIR/config.yaml" ]; then
    cp "$payload_dir/config.yaml" "$INSTALL_ETC_DIR/config.yaml"
    patch_default_config "$INSTALL_ETC_DIR/config.yaml"
    log "Installed default config: $INSTALL_ETC_DIR/config.yaml"
  else
    log "Keeping existing config: $INSTALL_ETC_DIR/config.yaml"
  fi

  ensure_service_user
  chown -R "$APP:$APP" "$INSTALL_DATA_DIR"
  chmod 0750 "$INSTALL_DATA_DIR"

  write_service

  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"

  log "Install completed."
  log "Binary: $INSTALL_BIN"
  log "Config: $INSTALL_ETC_DIR/config.yaml"
  log "Modules: $INSTALL_SHARE_DIR/modules"
  log "Data: $INSTALL_DATA_DIR"
  if INSTALLED_VERSION="$("$INSTALL_BIN" version 2>/dev/null)"; then
    log "Installed version: ${INSTALLED_VERSION}"
  else
    log "Installed version: (failed to query via '$INSTALL_BIN version')"
  fi
  systemctl --no-pager --full status "$SERVICE_NAME" || true
}

remove_release() {
  log "Removing ${APP}"

  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  fi

  rm -f "$SERVICE_FILE"
  systemctl daemon-reload >/dev/null 2>&1 || true

  rm -f "$INSTALL_BIN"
  rm -rf "$INSTALL_SHARE_DIR"

  log "Removed: $INSTALL_BIN"
  log "Removed: $INSTALL_SHARE_DIR"

  log "Retained paths:"
  if [ -d "$INSTALL_ETC_DIR" ]; then
    log "  - $INSTALL_ETC_DIR"
  else
    log "  - $INSTALL_ETC_DIR (not found)"
  fi
  if [ -d "$INSTALL_DATA_DIR" ]; then
    log "  - $INSTALL_DATA_DIR"
  else
    log "  - $INSTALL_DATA_DIR (not found)"
  fi

  if [ -f "$INSTALL_ETC_DIR/config.yaml" ]; then
    log "Retained config: $INSTALL_ETC_DIR/config.yaml"
  else
    log "Retained config: $INSTALL_ETC_DIR/config.yaml (not found)"
  fi
  if [ -f "$INSTALL_DATA_DIR/ca/root_ca.crt" ]; then
    log "Retained cert: $INSTALL_DATA_DIR/ca/root_ca.crt"
  else
    log "Retained cert: $INSTALL_DATA_DIR/ca/root_ca.crt (not found)"
  fi
  if [ -f "$INSTALL_DATA_DIR/ca/root_ca.key" ]; then
    log "Retained key: $INSTALL_DATA_DIR/ca/root_ca.key"
  else
    log "Retained key: $INSTALL_DATA_DIR/ca/root_ca.key (not found)"
  fi

  if id -u "$APP" >/dev/null 2>&1; then
    log "Retained service user: $APP"
  fi
}

main() {
  local action="${1:-}"
  local version="${2:-}"

  case "$action" in
    install)
      need_root
      ensure_supported_os
      install_release "$version"
      ;;
    remove)
      need_root
      ensure_supported_os
      remove_release
      ;;
    -h|--help|help|"")
      usage
      ;;
    *)
      err "Unknown action: $action"
      usage
      exit 1
      ;;
  esac
}

main "$@"
