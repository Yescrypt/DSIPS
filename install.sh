#!/bin/bash
# ==============================================================
#  DSIPS v2.0 — Detection & Security Intrusion Prevention System
#  https://github.com/Yescrypt/DSIPS
# ==============================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC}  $1"; }
info() { echo -e "  ${BLUE}•${NC}  $1"; }
warn() { echo -e "  ${YELLOW}!${NC}  $1"; }
err()  { echo -e "  ${RED}✗${NC}  $1"; exit 1; }
ask()  { echo -e "  ${CYAN}?${NC}  $1"; }

INSTALL_DIR="/opt/dsips"
CONFIG_DIR="/etc/dsips"
LOG_DIR="/var/log/dsips"
SRC="$(cd "$(dirname "$0")" && pwd)"
API_URL="https://dsips.yescrypt.uz"

[[ $EUID -ne 0 ]] && err "Root kerak:  sudo bash install.sh"

# ── Banner ────────────────────────────────────────────────────
clear
echo ""
echo -e "${BOLD}${BLUE}"
echo "  ██████╗ ███████╗██╗██████╗ ███████╗"
echo "  ██╔══██╗██╔════╝██║██╔══██╗██╔════╝"
echo "  ██║  ██║███████╗██║██████╔╝███████╗"
echo "  ██║  ██║╚════██║██║██╔═══╝ ╚════██║"
echo "  ██████╔╝███████║██║██║     ███████║"
echo "  ╚═════╝ ╚══════╝╚═╝╚═╝     ╚══════╝"
echo -e "${NC}"
echo -e "  ${BOLD}Detection & Security Intrusion Prevention System v2.0${NC}"
echo -e "  ${CYAN}https://github.com/Yescrypt/DSIPS${NC}"
echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── OS ────────────────────────────────────────────────────────
[ -f /etc/os-release ] && . /etc/os-release || true
info "OS: ${BOLD}${PRETTY_NAME:-Linux}${NC}"
echo ""
ask "Davom etasizmi? [Y/n]"
read -r C; [[ "${C,,}" == "n" ]] && exit 0
echo ""

# ── Savolar ───────────────────────────────────────────────────
echo -e "  ${BOLD}Sozlash${NC}"
echo -e "  ${YELLOW}──────────────────────────────────────────────${NC}"
echo ""

ask "Server nomi [$(hostname)]:"
read -r SERVER_NAME
SERVER_NAME="${SERVER_NAME:-$(hostname)}"
echo ""

ask "Telegram User ID:"
echo -e "  ${CYAN}  → @userinfobot ga /start yuboring${NC}"
read -r TG_USER_ID
while [[ -z "$TG_USER_ID" || ! "$TG_USER_ID" =~ ^-?[0-9]+$ ]]; do
    warn "Raqam kiriting!"
    ask "Telegram User ID:"
    read -r TG_USER_ID
done
echo ""

# ── Summary ───────────────────────────────────────────────────
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Xulosa${NC}"
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Server nomi    : ${BOLD}${SERVER_NAME}${NC}"
echo -e "  Telegram ID    : ${BOLD}${TG_USER_ID}${NC}"
echo ""
ask "O'rnatishni boshlaysizmi? [Y/n]"
read -r GO; [[ "${GO,,}" == "n" ]] && exit 0
echo ""

# ── Tizim paketlari ───────────────────────────────────────────
info "Tizim paketlari o'rnatilmoqda..."
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq \
        python3 python3-pip python3-venv \
        iptables iptables-persistent \
        ipset \
        curl wget \
        fail2ban \
        2>/dev/null || true
elif command -v yum &>/dev/null; then
    yum install -y -q python3 python3-pip iptables ipset curl fail2ban 2>/dev/null || true
elif command -v dnf &>/dev/null; then
    dnf install -y -q python3 python3-pip iptables ipset curl fail2ban 2>/dev/null || true
fi
ok "Tizim paketlari tayyor"

# ── Papkalar ──────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
chmod 750 "$CONFIG_DIR"
ok "Papkalar yaratildi"

# ── Agent fayllari ────────────────────────────────────────────
cp -r "$SRC/agent" "$INSTALL_DIR/"
ok "Agent fayllari ko'chirildi → $INSTALL_DIR"

# ── Python venv ───────────────────────────────────────────────
info "Python virtual environment yaratilmoqda..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -q aiohttp
ok "Python environment tayyor"

# ── Log fayllar aniqlash ──────────────────────────────────────
LOG_FILES=()
declare -a CANDIDATE_LOGS=(
    "/var/log/nginx/access.log"
    "/var/log/apache2/access.log"
    "/var/log/auth.log"
    "/var/log/syslog"
    "/var/log/fail2ban.log"
    "/var/log/crowdsec.log"
    "/var/log/nginx/modsec_audit.log"
    "/var/log/apache2/modsec_audit.log"
)

for f in "${CANDIDATE_LOGS[@]}"; do
    [ -f "$f" ] && LOG_FILES+=("\"$f\"")
done

LOG_FILES_JSON="[$(IFS=,; echo "${LOG_FILES[*]}")]"
ok "Log fayllar aniqlandi: ${#LOG_FILES[@]} ta"

# ── Config ────────────────────────────────────────────────────
cat > "$CONFIG_DIR/config.json" << CONF
{
  "server_name":      "$SERVER_NAME",
  "telegram_user_id": "$TG_USER_ID",
  "api_url":          "$API_URL",
  "firewall_backend": "auto",
  "ddos_threshold":   100,
  "ddos_window":      10,
  "block_critical":   86400,
  "block_high":       3600,
  "block_ddos":       600,
  "whitelisted_ips":  ["127.0.0.1", "::1"],
  "dry_run":          false,
  "log_files":        $LOG_FILES_JSON
}
CONF
chmod 600 "$CONFIG_DIR/config.json"
ok "Config saqlandi: $CONFIG_DIR/config.json"

# ── Fail2ban integratsiya ─────────────────────────────────────
if command -v fail2ban-client &>/dev/null; then
    info "Fail2ban sozlanmoqda..."

    # SSH jail kuchaytirish
    cat > /etc/fail2ban/jail.d/dsips.conf << 'F2B'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
backend  = auto

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 3600

[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 5

[nginx-botsearch]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/access.log
maxretry = 2

[nginx-req-limit]
enabled  = true
filter   = nginx-req-limit
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 10
F2B

    # nginx-req-limit filter
    cat > /etc/fail2ban/filter.d/nginx-req-limit.conf << 'F2BF'
[Definition]
failregex = limiting requests, excess:.* by zone.*client: <HOST>
ignoreregex =
F2BF

    systemctl enable fail2ban --quiet 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null && ok "Fail2ban sozlandi" || warn "Fail2ban ishga tushmadi"
else
    warn "Fail2ban topilmadi — o'tkazib yuborildi"
fi

# ── CrowdSec (ixtiyoriy) ──────────────────────────────────────
if command -v cscli &>/dev/null; then
    info "CrowdSec mavjud — DSIPS bilan birga ishlaydi"
    ok "CrowdSec aniqlandi"
else
    warn "CrowdSec o'rnatilmagan (ixtiyoriy)"
    echo -e "  ${CYAN}  O'rnatish: curl -s https://install.crowdsec.net | bash${NC}"
fi

# ── Systemd service ───────────────────────────────────────────
cat > /etc/systemd/system/dsips.service << SVCEOF
[Unit]
Description=DSIPS Security Agent v2.0
After=network-online.target fail2ban.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 -m agent.main
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dsips

[Install]
WantedBy=multi-user.target
SVCEOF
systemctl daemon-reload
ok "Systemd service o'rnatildi"

# ── API tekshirish ────────────────────────────────────────────
info "Cloud API tekshirilmoqda..."
if curl -sf "${API_URL}/health" > /dev/null 2>&1; then
    ok "Cloud API ishlayapti..."
else
    warn "Cloud API ga ulanib bo'lmadi — alertlar navbatda saqlanadi."
fi
echo ""

# ── Ishga tushirish ───────────────────────────────────────────
ask "Hozir ishga tushirasizmi? [Y/n]"
read -r START
if [[ "${START,,}" != "n" ]]; then
    systemctl enable dsips --quiet
    systemctl restart dsips
    sleep 2
    if systemctl is-active --quiet dsips; then
        ok "DSIPS ishlayapti!"
    else
        warn "Ishga tushmadi. Tekshiring: journalctl -u dsips -n 20"
    fi
fi

# ── Tayyor ────────────────────────────────────────────────────
echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}${BOLD}✓  DSIPS v2.0 muvaffaqiyatli o'rnatildi!${NC}"
echo ""
echo -e "  ${BOLD}Himoya qatlamlari:${NC}"
echo -e "  ${GREEN}✓${NC}  DSIPS Agent    — web/auth hujumlar"
echo -e "  ${GREEN}✓${NC}  Fail2ban       — SSH/web brute force"
echo -e "  ${GREEN}✓${NC}  iptables       — TCP/UDP flood, port scan"
command -v cscli &>/dev/null && echo -e "  ${GREEN}✓${NC}  CrowdSec       — community threat intel"
echo ""
echo -e "  ${BOLD}Buyruqlar:${NC}"
echo -e "  Loglar   : ${CYAN}journalctl -u dsips -f${NC}"
echo -e "  Status   : ${CYAN}systemctl status dsips${NC}"
echo -e "  Restart  : ${CYAN}systemctl restart dsips${NC}"
echo -e "  Uninstall: ${CYAN}sudo bash uninstall.sh${NC}"
echo ""
echo -e "  ${BOLD}Telegram:${NC}"
echo -e "  Alertlar ${BOLD}${TG_USER_ID}${NC} ga yuboriladi"
echo -e "  Bot: ${CYAN}@dsips_bot${NC}"
echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""


