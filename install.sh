#!/usr/bin/env bash
# =============================================================================
#  Kallix SIEM — Installer
#  Supports: Ubuntu 20.04, 22.04, 24.04
# =============================================================================
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RESET="\033[0m"
BOLD="\033[1m"
DIM="\033[2m"
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
WHITE="\033[1;37m"
TEAL="\033[38;5;43m"

# ── Helpers ───────────────────────────────────────────────────────────────────
banner() {
  clear
  echo -e "${TEAL}"
  echo "  ██╗  ██╗ █████╗ ██╗     ██╗     ██╗██╗  ██╗"
  echo "  ██║ ██╔╝██╔══██╗██║     ██║     ██║╚██╗██╔╝"
  echo "  █████╔╝ ███████║██║     ██║     ██║ ╚███╔╝ "
  echo "  ██╔═██╗ ██╔══██║██║     ██║     ██║ ██╔██╗ "
  echo "  ██║  ██╗██║  ██║███████╗███████╗██║██╔╝ ██╗"
  echo "  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═╝"
  echo -e "${DIM}${WHITE}  Threat Intelligence Platform — Installer${RESET}"
  echo ""
  echo -e "${DIM}  ────────────────────────────────────────────${RESET}"
  echo ""
}

section() {
  echo ""
  echo -e "${CYAN}${BOLD}  ▶ $1${RESET}"
  echo -e "${DIM}  ──────────────────────────────────────────${RESET}"
}

step() {
  echo -e "    ${WHITE}•${RESET} $1"
}

ok() {
  echo -e "    ${GREEN}✔${RESET}  $1"
}

warn() {
  echo -e "    ${YELLOW}⚠${RESET}  $1"
}

fail() {
  echo ""
  echo -e "  ${RED}${BOLD}✘ ERROR: $1${RESET}"
  echo ""
  exit 1
}

prompt() {
  local var_name="$1"
  local prompt_text="$2"
  local default="${3:-}"
  local is_secret="${4:-false}"

  if [[ -n "$default" ]]; then
    echo -ne "    ${WHITE}${prompt_text}${RESET} ${DIM}[${default}]${RESET}: "
  else
    echo -ne "    ${WHITE}${prompt_text}${RESET}: "
  fi

  if [[ "$is_secret" == "true" ]]; then
    read -rs value
    echo ""
  else
    read -r value
  fi

  if [[ -z "$value" && -n "$default" ]]; then
    value="$default"
  fi

  printf -v "$var_name" '%s' "$value"
}

confirm() {
  echo -ne "    ${WHITE}$1${RESET} ${DIM}[y/N]${RESET}: "
  read -r answer
  [[ "$answer" =~ ^[Yy]$ ]]
}

divider() {
  echo -e "${DIM}  ────────────────────────────────────────────${RESET}"
}

spinner() {
  local pid=$1
  local msg=$2
  local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    i=$(( (i+1) % ${#spin} ))
    printf "\r    ${CYAN}${spin:$i:1}${RESET}  ${msg}..."
    sleep 0.1
  done
  printf "\r    ${GREEN}✔${RESET}  %-50s\n" "$msg"
}

run_quietly() {
  local msg="$1"; shift
  "$@" > /tmp/kallix_install.log 2>&1 &
  local pid=$!
  spinner "$pid" "$msg"
  wait "$pid" || fail "$msg failed. Check /tmp/kallix_install.log"
}

# ── Pre-flight ────────────────────────────────────────────────────────────────
banner

echo -e "  ${WHITE}${BOLD}Welcome to the Kallix SIEM installer.${RESET}"
echo -e "  ${DIM}This script will install and configure all components on Ubuntu.${RESET}"
echo ""
echo -e "  ${DIM}Components:${RESET} PostgreSQL · C++ Backend · React Frontend · systemd Service"
echo ""
divider
echo ""

# Root check
if [[ $EUID -ne 0 ]]; then
  fail "This script must be run as root (use: sudo ./install.sh)"
fi

# Ubuntu check
if ! grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
  warn "This script targets Ubuntu. Other distros may work but are untested."
  confirm "Continue anyway?" || exit 0
fi

# Architecture
ARCH=$(uname -m)
if [[ "$ARCH" != "x86_64" && "$ARCH" != "aarch64" ]]; then
  fail "Unsupported architecture: $ARCH (requires x86_64 or aarch64)"
fi

INSTALL_DIR="/opt/kallix"
SERVICE_USER="kallix"
ENV_FILE="/etc/kallix/kallix.env"
SYSTEMD_UNIT="/etc/systemd/system/kallix.service"
NGINX_CONF="/etc/nginx/sites-available/kallix"

# ── Gather configuration ──────────────────────────────────────────────────────
section "Configuration"
echo -e "  ${DIM}Enter your deployment settings. Press Enter to accept defaults.${RESET}"
echo ""

prompt KALLIX_HOST         "Server hostname or IP"           "localhost"
prompt API_PORT            "API port"                         "8080"
prompt FRONTEND_PORT       "Frontend port (nginx)"            "3000"
prompt PG_DB               "PostgreSQL database name"         "kallix"
prompt PG_USER             "PostgreSQL user"                  "kallix"
prompt PG_PASS             "PostgreSQL password (min 8 chars)" "" "true"
while [[ -z "$PG_PASS" ]] || [[ ${#PG_PASS} -lt 8 ]]; do
  [[ -z "$PG_PASS" ]] && warn "PostgreSQL password cannot be empty." \
                       || warn "PostgreSQL password must be at least 8 characters."
  prompt PG_PASS "PostgreSQL password (min 8 chars)" "" "true"
done
prompt PG_PASS_CONFIRM     "Confirm PostgreSQL password"      "" "true"
while [[ "$PG_PASS" != "$PG_PASS_CONFIRM" ]]; do
  warn "Passwords do not match. Try again."
  prompt PG_PASS         "PostgreSQL password (min 8 chars)" "" "true"
  prompt PG_PASS_CONFIRM "Confirm PostgreSQL password"       "" "true"
done

echo ""
prompt ADMIN_USER          "Admin username"                   "admin"
prompt ADMIN_PASS          "Admin password (min 12 chars)"    "" "true"
while [[ ${#ADMIN_PASS} -lt 12 ]]; do
  warn "Password must be at least 12 characters."
  prompt ADMIN_PASS "Admin password (min 12 chars)" "" "true"
done

echo ""
if confirm "Configure SMTP for password reset emails?"; then
  SMTP_ENABLED=true
  prompt SMTP_HOST     "SMTP host"     "smtp.sendgrid.net"
  prompt SMTP_PORT     "SMTP port"     "465"
  prompt SMTP_USER     "SMTP username" "apikey"
  prompt SMTP_PASS     "SMTP password" "" "true"
  prompt SMTP_FROM     "From address"  "noreply@${KALLIX_HOST}"
  prompt SMTP_BASE_URL "Base URL for reset links" "https://${KALLIX_HOST}"
else
  SMTP_ENABLED=false
  SMTP_HOST=""; SMTP_PORT="465"; SMTP_USER=""; SMTP_PASS=""
  SMTP_FROM="noreply@kallix.local"; SMTP_BASE_URL=""
fi

echo ""
if confirm "Configure Azure Monitor integration?"; then
  AZURE_ENABLED=true
  prompt AZURE_TENANT  "Azure Tenant ID"       ""
  prompt AZURE_CLIENT  "Azure Client ID"       ""
  prompt AZURE_SECRET  "Azure Client Secret"   "" "true"
  prompt AZURE_SUB     "Azure Subscription ID" ""
else
  AZURE_ENABLED=false
  AZURE_TENANT=""; AZURE_CLIENT=""; AZURE_SECRET=""; AZURE_SUB=""
fi

echo ""
if confirm "Install Nginx as reverse proxy?"; then
  INSTALL_NGINX=true
  echo ""
  if confirm "Set up HTTPS with Let's Encrypt (certbot)?"; then
    SETUP_HTTPS=true
    prompt DOMAIN_NAME "Domain name (e.g. kallix.cloud)" "${KALLIX_HOST}"
    prompt CERTBOT_EMAIL "Email for Let's Encrypt notifications" ""
  else
    SETUP_HTTPS=false
    DOMAIN_NAME="${KALLIX_HOST}"
    CERTBOT_EMAIL=""
  fi
else
  INSTALL_NGINX=false
  SETUP_HTTPS=false
  DOMAIN_NAME="${KALLIX_HOST}"
  CERTBOT_EMAIL=""
fi

echo ""
divider
echo ""
echo -e "  ${WHITE}${BOLD}Review your configuration:${RESET}"
echo ""
echo -e "    Host            : ${CYAN}${KALLIX_HOST}${RESET}"
echo -e "    API port        : ${CYAN}${API_PORT}${RESET}"
echo -e "    Frontend port   : ${CYAN}${FRONTEND_PORT}${RESET}"
echo -e "    PostgreSQL      : ${CYAN}${PG_USER}@localhost/${PG_DB}${RESET}"
echo -e "    Admin user      : ${CYAN}${ADMIN_USER}${RESET}"
echo -e "    SMTP            : ${CYAN}${SMTP_ENABLED}${RESET}"
echo -e "    Azure Monitor   : ${CYAN}${AZURE_ENABLED}${RESET}"
echo -e "    Nginx proxy     : ${CYAN}${INSTALL_NGINX}${RESET}"
echo -e "    Install dir     : ${CYAN}${INSTALL_DIR}${RESET}"
echo ""
confirm "Proceed with installation?" || { echo "  Aborted."; exit 0; }

# ── System packages ───────────────────────────────────────────────────────────
section "Installing system packages"

run_quietly "Updating package lists" \
  apt-get update -y

PACKAGES=(
  build-essential cmake git curl wget
  libpq-dev libssl-dev libcurl4-openssl-dev
  pkg-config ca-certificates gnupg lsb-release
  postgresql postgresql-contrib
)

if [[ "$INSTALL_NGINX" == "true" ]]; then
  PACKAGES+=(nginx)
fi

run_quietly "Installing packages" \
  apt-get install -y "${PACKAGES[@]}"

# Node.js 20 LTS
if ! command -v node &>/dev/null || [[ "$(node -v 2>/dev/null | cut -d. -f1 | tr -d 'v')" -lt 18 ]]; then
  run_quietly "Installing Node.js 20 LTS" bash -c \
    "curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs"
else
  ok "Node.js $(node -v) already installed"
fi

ok "All system packages installed"

# ── PostgreSQL setup ──────────────────────────────────────────────────────────
section "Configuring PostgreSQL"

run_quietly "Starting PostgreSQL service" \
  systemctl enable --now postgresql

# Set postgres superuser password so peer auth isn't required for local tools
step "Setting postgres superuser password"
sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD '${PG_PASS}';" \
  >> /tmp/kallix_pg.log 2>&1
ok "postgres superuser password set"

# Create DB user + database
step "Creating database user and database"
sudo -u postgres psql -v ON_ERROR_STOP=1 <<EOF > /tmp/kallix_pg.log 2>&1 || true
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${PG_USER}') THEN
    CREATE ROLE ${PG_USER} WITH LOGIN PASSWORD '${PG_PASS}';
  ELSE
    ALTER ROLE ${PG_USER} WITH PASSWORD '${PG_PASS}';
  END IF;
END
\$\$;
SELECT 'CREATE DATABASE ${PG_DB}' WHERE NOT EXISTS (
  SELECT FROM pg_database WHERE datname = '${PG_DB}'
)\gexec
GRANT ALL PRIVILEGES ON DATABASE ${PG_DB} TO ${PG_USER};
ALTER DATABASE ${PG_DB} OWNER TO ${PG_USER};
EOF
ok "Database '${PG_DB}' ready, user '${PG_USER}' configured"

# ── Create system user ────────────────────────────────────────────────────────
section "Creating system user"

if ! id "$SERVICE_USER" &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
  ok "System user '${SERVICE_USER}' created"
else
  ok "System user '${SERVICE_USER}' already exists"
fi

# ── Build backend ─────────────────────────────────────────────────────────────
section "Building Kallix backend (C++20)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "${SCRIPT_DIR}/build"
run_quietly "Configuring with CMake" \
  cmake -S "${SCRIPT_DIR}" -B "${SCRIPT_DIR}/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DOUTPOST_BUILD_TESTS=OFF

NPROC=$(nproc)
run_quietly "Compiling (using ${NPROC} cores — this may take a few minutes)" \
  cmake --build "${SCRIPT_DIR}/build" --target outpost -j"${NPROC}"

ok "Backend binary built"

# ── Build frontend ────────────────────────────────────────────────────────────
section "Building Kallix frontend (React)"

FRONTEND_DIR="${SCRIPT_DIR}/frontend"

run_quietly "Installing npm dependencies" \
  npm --prefix "$FRONTEND_DIR" ci --silent

# Inject the API base URL for the production build
cat > "${FRONTEND_DIR}/.env.production" <<EOF
VITE_API_BASE=http://${KALLIX_HOST}:${API_PORT}
EOF

run_quietly "Building production frontend" \
  npm --prefix "$FRONTEND_DIR" run build

ok "Frontend built"

# ── Install files ─────────────────────────────────────────────────────────────
section "Installing Kallix to ${INSTALL_DIR}"

mkdir -p "${INSTALL_DIR}/bin"
mkdir -p "${INSTALL_DIR}/config/rules"
mkdir -p "${INSTALL_DIR}/frontend"
mkdir -p "${INSTALL_DIR}/logs"
mkdir -p /etc/kallix

step "Copying backend binary"
cp "${SCRIPT_DIR}/build/outpost" "${INSTALL_DIR}/bin/kallix"
chmod 750 "${INSTALL_DIR}/bin/kallix"

step "Copying config and rules"
cp "${SCRIPT_DIR}/config/outpost.yaml" "${INSTALL_DIR}/config/outpost.yaml"
cp -r "${SCRIPT_DIR}/config/rules/." "${INSTALL_DIR}/config/rules/" 2>/dev/null || true

step "Copying frontend build"
cp -r "${FRONTEND_DIR}/dist/." "${INSTALL_DIR}/frontend/"

step "Setting ownership"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"
chown -R root:root /etc/kallix
chmod 750 /etc/kallix

ok "Files installed"

# ── Write environment file ────────────────────────────────────────────────────
section "Writing environment configuration"

cat > "${ENV_FILE}" <<EOF
# Kallix SIEM — Environment Configuration
# Generated by install.sh on $(date)
# This file contains secrets — readable by root only

# PostgreSQL
PGHOST=localhost
PGPORT=5432
PGDATABASE=${PG_DB}
PGUSER=${PG_USER}
PGPASSWORD=${PG_PASS}

# Initial admin account
KALLIX_ADMIN_PASS=${ADMIN_PASS}

# SMTP
KALLIX_SMTP_USERNAME=${SMTP_USER}
KALLIX_SMTP_PASSWORD=${SMTP_PASS}

# Azure Monitor
KALLIX_AZURE_TENANT_ID=${AZURE_TENANT}
KALLIX_AZURE_CLIENT_ID=${AZURE_CLIENT}
KALLIX_AZURE_CLIENT_SECRET=${AZURE_SECRET}
KALLIX_AZURE_SUBSCRIPTION_ID=${AZURE_SUB}

# API
OUTPOST_CORS_ORIGIN=http://${KALLIX_HOST}:${FRONTEND_PORT}
KALLIX_SECURE_COOKIES=false   # updated to true automatically if certbot succeeds
EOF

chmod 600 "${ENV_FILE}"
ok "Environment file written to ${ENV_FILE}"

# Update outpost.yaml with non-secret settings
step "Updating config file"
cat > "${INSTALL_DIR}/config/outpost.yaml" <<EOF
syslog:
  bind_address: 0.0.0.0
  udp_port: 5514
  tcp_port: 5514
  enable_udp: true
  enable_tcp: true
postgres:
  host: localhost
  port: 5432
  database: ${PG_DB}
  user: ${PG_USER}
  password: ""         # loaded from env: PGPASSWORD
api:
  bind_address: 0.0.0.0
  port: ${API_PORT}
  cors_origin: ""      # loaded from env: OUTPOST_CORS_ORIGIN
hec:
  token: ""            # auto-generated on first start if blank
integrations:
  m365:
    enabled: false
    tenant_id: ""
    client_id: ""
    client_secret: ""
    poll_interval_sec: 60
  azure:
    enabled: ${AZURE_ENABLED}
    tenant_id: ""
    client_id: ""
    client_secret: ""    # loaded from env: KALLIX_AZURE_CLIENT_SECRET
    subscription_id: ""
    poll_interval_sec: 60
smtp:
  enabled: ${SMTP_ENABLED}
  host: ${SMTP_HOST}
  port: ${SMTP_PORT}
  username: ""           # loaded from env: KALLIX_SMTP_USERNAME
  password: ""           # loaded from env: KALLIX_SMTP_PASSWORD
  from: ${SMTP_FROM}
  from_name: Kallix SIEM
  use_ssl: true
  base_url: ${SMTP_BASE_URL}
auth:
  default_admin_user: ${ADMIN_USER}
  default_admin_pass: ""   # loaded from env: KALLIX_ADMIN_PASS
  session_ttl_hours: 24
logging:
  level: info
  file: ${INSTALL_DIR}/logs/kallix.log
workers:
  parser_threads: 2
EOF

chown "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}/config/outpost.yaml"
ok "Config file written"

# ── systemd service ───────────────────────────────────────────────────────────
section "Installing systemd service"

cat > "${SYSTEMD_UNIT}" <<EOF
[Unit]
Description=Kallix SIEM — Threat Intelligence Platform
Documentation=https://github.com/your-org/kallix
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${INSTALL_DIR}/bin/kallix ${INSTALL_DIR}/config/outpost.yaml
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=kallix

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${INSTALL_DIR}/logs
PrivateTmp=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

run_quietly "Reloading systemd daemon" \
  systemctl daemon-reload

run_quietly "Enabling Kallix service" \
  systemctl enable kallix

ok "systemd service installed and enabled"

# ── Nginx config ──────────────────────────────────────────────────────────────
if [[ "$INSTALL_NGINX" == "true" ]]; then
  section "Configuring Nginx reverse proxy"

  cat > "${NGINX_CONF}" <<EOF
server {
    listen ${FRONTEND_PORT};
    server_name ${KALLIX_HOST};

    root ${INSTALL_DIR}/frontend;
    index index.html;

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Serve React SPA — all routes fall back to index.html
    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # Proxy API requests to the backend
    location /api/ {
        proxy_pass         http://127.0.0.1:${API_PORT};
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 60s;
    }

    # HEC endpoint
    location /services/ {
        proxy_pass         http://127.0.0.1:${API_PORT};
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_read_timeout 60s;
    }
}
EOF

  ln -sf "${NGINX_CONF}" /etc/nginx/sites-enabled/kallix
  rm -f /etc/nginx/sites-enabled/default

  run_quietly "Testing Nginx config" \
    nginx -t

  run_quietly "Restarting Nginx" \
    systemctl restart nginx

  ok "Nginx configured and running"

  # ── HTTPS via Let's Encrypt ─────────────────────────────────────────────────
  if [[ "$SETUP_HTTPS" == "true" ]]; then
    section "Setting up HTTPS (Let's Encrypt)"

    run_quietly "Installing certbot" \
      apt-get install -y certbot python3-certbot-nginx

    step "Requesting certificate for ${DOMAIN_NAME}"
    certbot --nginx \
      -d "${DOMAIN_NAME}" \
      --non-interactive \
      --agree-tos \
      --email "${CERTBOT_EMAIL}" \
      --redirect \
      >> /tmp/kallix_install.log 2>&1 || {
        warn "Certbot failed — DNS may not be pointing to this server yet."
        warn "Run manually later: certbot --nginx -d ${DOMAIN_NAME}"
      }

    # Enable auto-renewal
    systemctl enable --now certbot.timer 2>/dev/null || true

    # Flip secure_cookies on now that we have HTTPS
    sed -i 's/^KALLIX_SECURE_COOKIES=.*/KALLIX_SECURE_COOKIES=true/' "${ENV_FILE}"

    ok "HTTPS configured — certificate auto-renews via certbot.timer"
    FRONTEND_PORT=443
  fi
fi

# ── Firewall (ufw) ────────────────────────────────────────────────────────────
if command -v ufw &>/dev/null; then
  section "Configuring firewall"
  step "Opening ports: ${FRONTEND_PORT} (frontend), ${API_PORT} (API), 5514 (syslog)"
  ufw allow "${FRONTEND_PORT}/tcp" > /dev/null 2>&1 || true
  ufw allow "${API_PORT}/tcp"      > /dev/null 2>&1 || true
  ufw allow 5514/udp               > /dev/null 2>&1 || true
  ufw allow 5514/tcp               > /dev/null 2>&1 || true
  ok "Firewall rules added"
fi

# ── Start service ─────────────────────────────────────────────────────────────
section "Starting Kallix"

run_quietly "Starting Kallix service" \
  systemctl start kallix

sleep 3

if systemctl is-active --quiet kallix; then
  ok "Kallix is running"
else
  warn "Service may not have started — check: journalctl -u kallix -n 50"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
banner

echo -e "  ${GREEN}${BOLD}✔  Installation complete!${RESET}"
echo ""
divider
echo ""
echo -e "  ${WHITE}${BOLD}Access Kallix:${RESET}"
if [[ "$INSTALL_NGINX" == "true" ]]; then
  echo -e "    ${CYAN}http://${KALLIX_HOST}:${FRONTEND_PORT}${RESET}"
else
  echo -e "    Frontend  →  ${CYAN}http://${KALLIX_HOST}:${FRONTEND_PORT}${RESET}  ${DIM}(serve ${INSTALL_DIR}/frontend manually)${RESET}"
  echo -e "    API       →  ${CYAN}http://${KALLIX_HOST}:${API_PORT}/api/health${RESET}"
fi
echo ""
echo -e "  ${WHITE}${BOLD}Credentials:${RESET}"
echo -e "    Username  →  ${CYAN}${ADMIN_USER}${RESET}"
echo -e "    Password  →  ${DIM}(as entered during setup)${RESET}"
echo ""
echo -e "  ${WHITE}${BOLD}Syslog / CEF ingestion:${RESET}"
echo -e "    UDP/TCP   →  ${CYAN}${KALLIX_HOST}:5514${RESET}"
echo ""
echo -e "  ${WHITE}${BOLD}Useful commands:${RESET}"
echo -e "    ${DIM}Status   :${RESET}  systemctl status kallix"
echo -e "    ${DIM}Logs     :${RESET}  journalctl -u kallix -f"
echo -e "    ${DIM}Restart  :${RESET}  systemctl restart kallix"
echo -e "    ${DIM}Stop     :${RESET}  systemctl stop kallix"
echo -e "    ${DIM}Env file :${RESET}  ${ENV_FILE}"
echo -e "    ${DIM}Config   :${RESET}  ${INSTALL_DIR}/config/outpost.yaml"
echo ""
echo -e "  ${DIM}${BOLD}Note:${RESET}${DIM} Change your admin password after first login."
echo -e "  Set HTTPS via certbot + nginx for production deployments.${RESET}"
echo ""
divider
echo ""
