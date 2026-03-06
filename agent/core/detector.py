"""
DSIPS Attack Detector v2.0
- Web hujumlar: SQLi, XSS, RCE, LFI, Traversal, CMDi
- Brute force: SSH, web login
- DDoS/DoS: HTTP rate, TCP/UDP flood
- Fail2ban log integration
- CrowdSec log integration
- ModSecurity log integration

Qoidalar:
  CRITICAL/HIGH zarar → avto blok
  MEDIUM shubha    → faqat alert, blok tugmasi
"""

import re
import time
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Deque
from enum import Enum

from agent.config.settings import Config

logger = logging.getLogger("dsips.detector")


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"


class AttackType(str, Enum):
    SQL_INJECTION = "SQL Injection"
    XSS           = "Cross-Site Scripting"
    DIR_TRAVERSAL = "Directory Traversal"
    RCE           = "Remote Code Execution"
    LFI           = "Local File Inclusion"
    CMD_INJECTION = "Command Injection"
    SCANNER       = "Scanner / Recon"
    BRUTE_FORCE   = "Brute Force"
    DDOS          = "DDoS / Rate Abuse"
    TCP_FLOOD     = "TCP Flood"
    UDP_FLOOD     = "UDP Flood"
    PORT_SCAN     = "Port Scan"
    # Integratsiyalar
    FAIL2BAN      = "Fail2ban"
    CROWDSEC      = "CrowdSec"
    MODSECURITY   = "ModSecurity"


@dataclass
class Hit:
    attack_type:  AttackType
    severity:     Severity
    ip:           str
    path:         str
    raw_line:     str
    source_file:  str
    timestamp:    float = field(default_factory=time.time)
    details:      str   = ""
    should_block: bool  = False
    source:       str   = "dsips"   # dsips / fail2ban / crowdsec / modsecurity


# ── Web hujum patternlari ─────────────────────────────────────

RE_SQL = re.compile(
    r"(union[\s+]+select|select.+from|insert\s+into|drop\s+table|"
    r"exec\s*\(|xp_cmdshell|'\s*or\s*'?\d|'\s*--\s*$|/\*.*\*/|"
    r"information_schema|benchmark\s*\(|sleep\s*\(|waitfor\s+delay|"
    r"0x[0-9a-f]{4,}|cast\s*\(.+as\s+|load_file\s*\(|into\s+outfile)",
    re.IGNORECASE,
)
RE_XSS = re.compile(
    r"(<script[\s>]|</script>|javascript:|on(load|error|click|mouseover|submit)\s*=|"
    r"<iframe[\s>]|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie|eval\s*\(|"
    r"&#x[0-9a-f]+;|%3cscript)",
    re.IGNORECASE,
)
RE_TRAVERSAL = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e|/etc/passwd|/etc/shadow|"
    r"/proc/self|\.htaccess|\.htpasswd|/boot\.ini|c:\\windows)",
    re.IGNORECASE,
)
RE_RCE = re.compile(
    r"(;(ls|cat|id|whoami|uname|wget|curl|bash|sh|python|perl)\s|"
    r"\|(ls|cat|id|whoami|wget|curl|bash)\s|`[^`]+`|\$\([^)]+\)|"
    r"cmd\.exe|/bin/sh|/bin/bash|system\s*\(|passthru\s*\(|"
    r"shell_exec\s*\(|popen\s*\(|base64_decode\s*\()",
    re.IGNORECASE,
)
RE_LFI = re.compile(
    r"(php://filter|php://input|data://|expect://|phar://|"
    r"file=\.\./|page=\.\./|include=\.\./)",
    re.IGNORECASE,
)
RE_CMD = re.compile(
    r"(;[\s]*rm\s+-|;[\s]*mkfifo|;[\s]*nc\s+|"
    r"&&\s*(rm|wget|curl|chmod)|>\s*/dev/tcp/)",
    re.IGNORECASE,
)
RE_SCANNER = re.compile(
    r"(sqlmap|nikto|nmap|masscan|nessus|openvas|acunetix|w3af|"
    r"dirbuster|gobuster|dirb|wfuzz|hydra|medusa|metasploit|"
    r"burpsuite|owasp.?zap|nuclei|whatweb|wapiti|zgrab|skipfish)",
    re.IGNORECASE,
)
RE_BRUTE = re.compile(
    r"(failed password for|authentication failure|invalid user .+ from|"
    r"failed login|bad password|pam_unix.*auth.*failure|"
    r'HTTP/\d\.\d" 401)',
    re.IGNORECASE,
)

# ── Fail2ban log patternlari ──────────────────────────────────
# /var/log/fail2ban.log
RE_FAIL2BAN_BAN = re.compile(
    r"fail2ban\.actions\s+\[.+\]:\s+(?:WARNING|NOTICE)\s+"
    r"(?:\[[\w-]+\]\s+)?Ban\s+(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
RE_FAIL2BAN_UNBAN = re.compile(
    r"fail2ban\.actions.*Unban\s+(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
# Jail nomi
RE_FAIL2BAN_JAIL = re.compile(r"\[([\w-]+)\].*Ban", re.IGNORECASE)

# ── CrowdSec log patternlari ──────────────────────────────────
# /var/log/crowdsec.log
RE_CROWDSEC_BAN = re.compile(
    r"crowdsec.*(?:ban|added|remediation).*?(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
RE_CROWDSEC_ALERT = re.compile(
    r"crowdsec.*(?:alert|trigger|detect).*?(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)

# ── ModSecurity log patternlari ───────────────────────────────
# /var/log/nginx/modsec_audit.log yoki /var/log/apache2/modsec_audit.log
RE_MODSEC_IP = re.compile(
    r"\[client\s+(\d{1,3}(?:\.\d{1,3}){3})\]|"
    r"ModSecurity.*\[id\s+\"(\d+)\"\].*?(\d{1,3}(?:\.\d{1,3}){3})|"
    r"^(\d{1,3}(?:\.\d{1,3}){3}).*ModSecurity",
    re.IGNORECASE,
)
RE_MODSEC_BLOCK = re.compile(
    r"(Access denied|ModSecurity.*phase|Inbound Anomaly)",
    re.IGNORECASE,
)
RE_MODSEC_RULE = re.compile(r'\[id "(\d+)"\]', re.IGNORECASE)
RE_MODSEC_MSG  = re.compile(r'\[msg "([^"]+)"\]', re.IGNORECASE)

# ── Parsing ───────────────────────────────────────────────────
RE_WEBLOG = re.compile(
    r'^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+'
    r'"[A-Z]+\s+([^\s"]+)',
    re.IGNORECASE,
)
RE_IP = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')


class Detector:
    def __init__(self, cfg: Config, blocker, reporter):
        self.cfg      = cfg
        self.blocker  = blocker
        self.reporter = reporter

        self._reqs:  Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=cfg.ddos_threshold * 2)
        )
        self._auths: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=50))
        self._done:  set = set()
        self._cool:  Dict[str, float] = {}

    # ── Yordamchilar ──────────────────────────────────────────

    def _parse_weblog(self, line: str):
        m = RE_WEBLOG.match(line)
        if m:
            return m.group(1), m.group(2)
        ip = RE_IP.search(line)
        pm = re.search(r'"[A-Z]+\s+(/[^\s"]*)', line)
        return (ip.group(1) if ip else "unknown"), (pm.group(1) if pm else line[:200])

    def _white(self, ip: str) -> bool:
        return ip in self.cfg.whitelisted_ips or ip == "unknown"

    def _ddos(self, ip: str) -> bool:
        now = time.time()
        q   = self._reqs[ip]
        q.append(now)
        return sum(1 for t in q if t > now - self.cfg.ddos_window) >= self.cfg.ddos_threshold

    def _brute(self, ip: str) -> bool:
        now = time.time()
        q   = self._auths[ip]
        q.append(now)
        return sum(1 for t in q if t > now - 60) >= 5  # 5 ta xato/daqiqa

    def _cooldown(self, ip: str, atype: str) -> bool:
        k = f"{ip}:{atype}"
        if time.time() - self._cool.get(k, 0) < 120:
            return True
        self._cool[k] = time.time()
        return False

    # ── Fail2ban log tahlili ──────────────────────────────────

    def _parse_fail2ban(self, line: str, source: str):
        m = RE_FAIL2BAN_BAN.search(line)
        if not m:
            return None
        ip   = m.group(1)
        jail = (RE_FAIL2BAN_JAIL.search(line) or re.search(r'$', '')).group(1) \
               if RE_FAIL2BAN_JAIL.search(line) else "unknown"
        return Hit(
            attack_type  = AttackType.FAIL2BAN,
            severity     = Severity.HIGH,
            ip           = ip,
            path         = f"jail: {jail}",
            raw_line     = line,
            source_file  = source,
            should_block = True,
            source       = "fail2ban",
            details      = f"Fail2ban ban: [{jail}]",
        )

    # ── CrowdSec log tahlili ──────────────────────────────────

    def _parse_crowdsec(self, line: str, source: str):
        m = RE_CROWDSEC_BAN.search(line)
        if m:
            return Hit(
                attack_type  = AttackType.CROWDSEC,
                severity     = Severity.HIGH,
                ip           = m.group(1),
                path         = "crowdsec decision",
                raw_line     = line,
                source_file  = source,
                should_block = True,
                source       = "crowdsec",
                details      = "CrowdSec community ban",
            )
        m = RE_CROWDSEC_ALERT.search(line)
        if m:
            return Hit(
                attack_type  = AttackType.CROWDSEC,
                severity     = Severity.MEDIUM,
                ip           = m.group(1),
                path         = "crowdsec alert",
                raw_line     = line,
                source_file  = source,
                should_block = False,
                source       = "crowdsec",
                details      = "CrowdSec alert",
            )
        return None

    # ── ModSecurity log tahlili ───────────────────────────────

    def _parse_modsec(self, line: str, source: str):
        if not RE_MODSEC_BLOCK.search(line):
            return None
        m  = RE_MODSEC_IP.search(line)
        if not m:
            return None
        ip  = next((g for g in m.groups() if g), None)
        if not ip:
            return None
        rule = RE_MODSEC_RULE.search(line)
        msg  = RE_MODSEC_MSG.search(line)
        details = f"Rule {rule.group(1)}" if rule else ""
        if msg:
            details += f": {msg.group(1)[:80]}"
        return Hit(
            attack_type  = AttackType.MODSECURITY,
            severity     = Severity.HIGH,
            ip           = ip,
            path         = "modsecurity block",
            raw_line     = line,
            source_file  = source,
            should_block = True,
            source       = "modsecurity",
            details      = details or "ModSecurity block",
        )

    # ── Asosiy tahlil ─────────────────────────────────────────

    async def analyze(self, line: str, source: str):
        # Integratsiya loglari
        if "fail2ban" in source or "fail2ban" in line.lower():
            hit = self._parse_fail2ban(line, source)
            if hit:
                await self._handle(hit)
            return

        if "crowdsec" in source or "crowdsec" in line.lower():
            hit = self._parse_crowdsec(line, source)
            if hit:
                await self._handle(hit)
            return

        if "modsec" in source or "ModSecurity" in line:
            hit = self._parse_modsec(line, source)
            if hit:
                await self._handle(hit)
            return

        # Oddiy web/auth log
        ip, path = self._parse_weblog(line)
        if self._white(ip):
            return

        # DDoS tracking
        if any(x in source for x in ("access.log", "nginx", "apache")):
            self._reqs[ip].append(time.time())

        # Auth tracking
        if any(x in source for x in ("auth.log", "syslog", "secure")):
            if RE_BRUTE.search(line):
                self._auths[ip].append(time.time())

        hit = None

        if RE_SQL.search(line):
            hit = Hit(AttackType.SQL_INJECTION, Severity.CRITICAL, ip, path,
                      line, source, should_block=True)
        elif RE_RCE.search(line):
            hit = Hit(AttackType.RCE, Severity.CRITICAL, ip, path,
                      line, source, should_block=True)
        elif RE_CMD.search(line):
            hit = Hit(AttackType.CMD_INJECTION, Severity.CRITICAL, ip, path,
                      line, source, should_block=True)
        elif RE_TRAVERSAL.search(line):
            hit = Hit(AttackType.DIR_TRAVERSAL, Severity.HIGH, ip, path,
                      line, source, should_block=True)
        elif RE_LFI.search(line):
            hit = Hit(AttackType.LFI, Severity.HIGH, ip, path,
                      line, source, should_block=True)
        elif RE_XSS.search(line):
            # XSS — faqat alert, blok emas (false positive ko'p)
            hit = Hit(AttackType.XSS, Severity.MEDIUM, ip, path,
                      line, source, should_block=False)
        elif RE_SCANNER.search(line):
            hit = Hit(AttackType.SCANNER, Severity.MEDIUM, ip, path,
                      line, source, should_block=True,
                      details="Recon tool detected")
        elif RE_BRUTE.search(line) and self._brute(ip):
            hit = Hit(AttackType.BRUTE_FORCE, Severity.HIGH, ip, path,
                      line, source, should_block=True,
                      details="5+ auth failure/min")
        elif self._ddos(ip):
            hit = Hit(AttackType.DDOS, Severity.HIGH, ip, path,
                      line, source, should_block=True,
                      details=f">{self.cfg.ddos_threshold} req/{self.cfg.ddos_window}s")

        if hit:
            await self._handle(hit)

    async def _handle(self, h: Hit):
        if self._cooldown(h.ip, h.attack_type.value):
            return

        logger.warning(
            f"[{h.severity.upper()}] {h.attack_type.value} | "
            f"{h.ip} | {h.source} | {h.path[:60]}"
        )

        if h.should_block and h.ip not in self._done and not self.cfg.dry_run:
            dur = {
                Severity.CRITICAL: self.cfg.block_critical,
                Severity.HIGH:     self.cfg.block_high,
                Severity.MEDIUM:   self.cfg.block_ddos,
            }.get(h.severity, self.cfg.block_high)

            if await self.blocker.block(h.ip, dur, h.attack_type.value):
                self._done.add(h.ip)
        elif self.cfg.dry_run and h.should_block:
            logger.info(f"[DRY RUN] Would block: {h.ip}")

        await self.reporter.send(h)
