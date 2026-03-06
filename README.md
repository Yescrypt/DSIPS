<div align="center">

# 🛡️ DSIPS

### Detection & Security Intrusion Prevention System

**Real-time attack detection · Automatic IP blocking · Telegram alerts**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-orange?style=flat-square)](#)

</div>

---

## What is DSIPS?

DSIPS is a lightweight, **production-ready IDS/IPS** for Linux servers. It monitors your server logs in real-time, detects attacks as they happen, automatically blocks malicious IPs via your firewall, and sends instant alerts to your Telegram.

**No heavy daemons. No complex config. One command to install.**

```
Your Linux Server                  Your Cloud API                 Your Telegram
┌────────────────┐                ┌──────────────┐              ┌─────────────────┐
│  DSIPS Agent   │                │  dsips API   │              │  🔴 Alert!      │
│                │  POST /alert   │              │  Bot sends   │  SQL Injection  │
│  Watches logs  │ ─────────────► │  Receives    │ ───────────► │  IP: 1.2.3.4   │
│  Detects hits  │                │  alert       │              │  Server: web-01 │
│  Blocks IPs    │◄───────────── │  Queues cmd  │◄──────────── │                 │
│                │  GET /commands │              │  Admin press │  [Block] [WHOIS]│
└────────────────┘                └──────────────┘              └─────────────────┘
         │
         │ iptables / ufw / ipset
         ▼
    🚫 Attacker blocked
```

---

## ✨ Features

| | |
|---|---|
| 🔍 **Real-time monitoring** | nginx, apache, auth.log, syslog |
| 💉 **SQL Injection** | Full pattern library including blind SQLi |
| 💥 **RCE / Command Injection** | Shell escape, code execution attempts |
| 📂 **Directory Traversal / LFI** | Path traversal, PHP filter chains |
| 🔑 **Brute Force** | Auth failure tracking per IP |
| 🌊 **DDoS Detection** | Request rate threshold per IP |
| 🔍 **Scanner Detection** | sqlmap, nikto, nmap, gobuster, etc. |
| 🔮 **XSS** | Reflected XSS pattern detection |
| 🚫 **Auto Block** | iptables / ufw / ipset (auto-detected) |
| 📱 **Telegram Alerts** | Rich messages with Block / Unblock buttons |
| 📡 **Command Polling** | Agent polls API for admin commands |
| 🔁 **Alert Queue** | Local queue when API unreachable |

---

## 🚀 Install

```bash
git clone https://github.com/dsips/dsips.git
cd dsips
sudo bash install.sh
```

That's it. The installer will ask you **3 questions**:

```
  Detected OS: Ubuntu 22.04
  Continue with this system? [Y/n]

  ? Server name [web-server-1]:

  ? Your Telegram User ID:
      (Get it: open @userinfobot in Telegram, send /start)
  > 123456789

  ? Firewall backend [auto / iptables / ufw / ipset]:
  > auto
```

Then it will:
- Install system dependencies
- Create a Python virtual environment
- Write `/etc/dsips/config.json`
- Install and start the `dsips` systemd service

---

## 📱 Telegram Alerts

When an attack is detected, you receive:

```
🔴 DSIPS Security Alert
━━━━━━━━━━━━━━━━━━━━
💉 Attack:   SQL Injection
🌐 IP:       185.220.101.42
🖥️ Server:   web-server-1
📍 Path:     /login?id=1' UNION SELECT...
⏰ Time:     2025-01-15 14:32:01 UTC
🎯 Severity: CRITICAL
━━━━━━━━━━━━━━━━━━━━

[🔒 Block IP]  [🔓 Unblock IP]
[🔍 WHOIS]     [🗺️ IP Info]
```

Press **[Block IP]** → the API queues the command → your agent polls and executes `iptables` block within 10 seconds.

---

## ⚙️ Configuration

Config file is created automatically at `/etc/dsips/config.json`:

```json
{
  "server_name":      "web-server-1",
  "api_url":          "https://dsips.yescrypt.uz",
  "telegram_user_id": "123456789",
  "firewall_backend": "auto",
  "ddos_threshold":   100,
  "ddos_window":      10,
  "block_critical":   86400,
  "block_high":       3600,
  "block_ddos":       600,
  "whitelisted_ips":  ["127.0.0.1", "::1"],
  "dry_run":          false
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `server_name` | hostname | Shown in alerts |
| `telegram_user_id` | — | Your Telegram numeric ID |
| `firewall_backend` | `auto` | `auto` / `iptables` / `ufw` / `ipset` |
| `ddos_threshold` | `100` | Requests per window to trigger DDoS block |
| `ddos_window` | `10` | Window in seconds |
| `block_critical` | `86400` | Block duration for critical attacks (24h) |
| `block_high` | `3600` | Block duration for high severity (1h) |
| `block_ddos` | `600` | Block duration for DDoS (10min) |
| `whitelisted_ips` | `127.0.0.1` | IPs that are never blocked |
| `dry_run` | `false` | Detect but don't block |

---

## 🔒 Attack Types & Severity

| Attack | Severity | Auto-Block | Detection |
|--------|----------|-----------|-----------|
| SQL Injection | 🔴 Critical | ✅ 24h | UNION, blind, time-based |
| Remote Code Execution | 🔴 Critical | ✅ 24h | Shell escape, eval |
| Command Injection | 🔴 Critical | ✅ 24h | Piping, backticks |
| Directory Traversal | 🟠 High | ✅ 1h | `../`, `/etc/passwd` |
| Local File Inclusion | 🟠 High | ✅ 1h | PHP filters, wrappers |
| Brute Force | 🟠 High | ✅ 1h | 10 failures / 60s |
| DDoS | 🟠 High | ✅ 10min | 100 req / 10s |
| XSS | 🟠 High | alert only | Script tags, event handlers |
| Scanner Tools | 🟡 Medium | ✅ 10min | User-Agent patterns |

---

## 🗂️ Project Structure

```
dsips/
├── agent/
│   ├── config/
│   │   └── settings.py      # Loads /etc/dsips/config.json
│   └── core/
│       ├── detector.py      # Attack pattern engine
│       ├── monitor.py       # Async log tail
│       ├── blocker.py       # iptables / ufw / ipset
│       ├── reporter.py      # Sends alerts to Cloud API
│       └── poller.py        # Polls API for Telegram commands
│   └── main.py              # Entry point
├── install.sh               # Interactive installer
├── uninstall.sh             # Clean removal
├── requirements.txt         # Python deps (aiohttp only)
└── README.md
```

---

## 🔧 Management

```bash
# Service control
systemctl status dsips
systemctl restart dsips
journalctl -u dsips -f

# Edit config
nano /etc/dsips/config.json
systemctl restart dsips

# Uninstall
sudo bash uninstall.sh
```

---

## 🗺️ Roadmap

- **v1.0** ✅ Real-time IDS · Auto-block · Telegram alerts
- **v1.1** GeoIP blocking · fail2ban import · ipset integration
- **v1.2** ML anomaly detection · custom rule engine
- **v2.0** Centralized dashboard · WAF mode · multi-server view

---

## 🤝 Contributing

Pull requests welcome. For major changes, open an issue first.

## 📄 License

[MIT](LICENSE)
