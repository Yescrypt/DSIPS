#!/bin/bash
# DSIPS Uninstaller

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "${RED}Run as root${NC}" && exit 1

echo ""
echo -e "${YELLOW}This will remove DSIPS agent from this server.${NC}"
echo -e "Config in /etc/dsips will be preserved."
echo ""
read -rp "  Continue? [y/N] " CONFIRM
[[ "${CONFIRM,,}" != "y" ]] && echo "  Aborted." && exit 0

echo ""

# Stop and disable service
if systemctl is-active --quiet dsips 2>/dev/null; then
    systemctl stop dsips
    echo -e "  ${GREEN}✓${NC}  Service stopped"
fi
if systemctl is-enabled --quiet dsips 2>/dev/null; then
    systemctl disable dsips --quiet
    echo -e "  ${GREEN}✓${NC}  Service disabled"
fi

# Remove service file
rm -f /etc/systemd/system/dsips.service
systemctl daemon-reload
echo -e "  ${GREEN}✓${NC}  Systemd service removed"

# Remove install directory
rm -rf /opt/dsips
echo -e "  ${GREEN}✓${NC}  /opt/dsips removed"

# Remove ipset rules if present
if command -v ipset &>/dev/null; then
    iptables -D INPUT -m set --match-set dsips_blocked src -j DROP 2>/dev/null || true
    ipset destroy dsips_blocked 2>/dev/null || true
    echo -e "  ${GREEN}✓${NC}  ipset rules cleared"
fi

echo ""
echo -e "  ${GREEN}DSIPS uninstalled.${NC}"
echo -e "  Config preserved at: /etc/dsips/config.json"
echo -e "  Logs preserved at:   /var/log/dsips/"
echo ""
