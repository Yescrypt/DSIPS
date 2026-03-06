"""
DSIPS Agent Configuration
/etc/dsips/config.json dan o'qiydi
"""

import json
import socket
from pathlib import Path
from dataclasses import dataclass, field
from typing import List

CONFIG_PATH = "/etc/dsips/config.json"

DEFAULT_LOGS = [
    "/var/log/nginx/access.log",
    "/var/log/apache2/access.log",
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/fail2ban.log",
    "/var/log/crowdsec.log",
    "/var/log/nginx/modsec_audit.log",
    "/var/log/apache2/modsec_audit.log",
]


def _load() -> dict:
    p = Path(CONFIG_PATH)
    if not p.exists():
        raise FileNotFoundError(
            f"Config topilmadi: {CONFIG_PATH}\n"
            "O'rnating: sudo bash install.sh"
        )
    with open(p) as f:
        return json.load(f)


@dataclass
class Config:
    server_name:      str
    telegram_user_id: str
    api_url:          str       = "https://dsips.yescrypt.uz"
    api_key:          str       = ""
    firewall_backend: str       = "auto"
    ddos_threshold:   int       = 100
    ddos_window:      int       = 10
    block_critical:   int       = 86400
    block_high:       int       = 3600
    block_ddos:       int       = 600
    whitelisted_ips:  List[str] = field(default_factory=list)
    dry_run:          bool      = False
    log_files:        List[str] = field(default_factory=list)

    def __post_init__(self):
        for ip in ("127.0.0.1", "::1"):
            if ip not in self.whitelisted_ips:
                self.whitelisted_ips.append(ip)
        if not self.log_files:
            self.log_files = [f for f in DEFAULT_LOGS if Path(f).exists()]


def load_config() -> Config:
    d = _load()
    return Config(
        server_name      = d.get("server_name", socket.gethostname()),
        telegram_user_id = d["telegram_user_id"],
        api_url          = d.get("api_url", "https://dsips.yescrypt.uz"),
        api_key          = d.get("api_key", ""),
        firewall_backend = d.get("firewall_backend", "auto"),
        ddos_threshold   = d.get("ddos_threshold", 100),
        ddos_window      = d.get("ddos_window", 10),
        block_critical   = d.get("block_critical", 86400),
        block_high       = d.get("block_high", 3600),
        block_ddos       = d.get("block_ddos", 600),
        whitelisted_ips  = d.get("whitelisted_ips", []),
        dry_run          = d.get("dry_run", False),
        log_files        = d.get("log_files", []),
    )
