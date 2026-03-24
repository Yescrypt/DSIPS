"""
DSIPS Detector v3.1 — To'g'rilangan versiya

Blok muddatlari:
  CRITICAL (SQLi, RCE, CMDi)    → 3600s (1 soat)
  HIGH     (Traversal, LFI, BF) → 1800s (30 daqiqa)
  MEDIUM   (Scanner, DDoS)      → 1800s (30 daqiqa)
  XSS                           → faqat alert (blok yo'q)

Xizmat nazorati:
  SSH  brute (3 urinish/5 daqiqa) → 3600s
  FTP  brute (5 urinish/5 daqiqa) → 1800s
  SMTP brute (5 urinish/5 daqiqa) → 1800s
  HTTP 401 brute (10 urinish/daqiqa) → 1800s
  MySQL, PostgreSQL, Redis (5 urinish/5 daqiqa) → 3600s

Oddiy foydalanuvchi himoyasi:
  - Whitelist IP lar hech qachon bloklanmaydi
  - Cooldown: bir IP/hujum turi 5 daqiqada bir marta alert (oldin 2 daqiqa edi — kamaytirildi)
  - DDoS: 150 req/10s (oldin 100 edi — false positive kamayadi)
  - SSH brute: 3 urinish (parolni unutish mumkin, 2 emas)
  - Blok qilingan IP unblock bo'lsa _done dan ham o'chiriladi
"""

import re
import time
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Deque, Optional, Set

from agent.config.settings import Config

logger = logging.getLogger("dsips.detector")


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


class AttackType(str, Enum):
    SQL_INJECTION = "SQL Injection"
    XSS           = "Cross-Site Scripting"
    DIR_TRAVERSAL = "Directory Traversal"
    RCE           = "Remote Code Execution"
    LFI           = "Local File Inclusion"
    CMD_INJECTION = "Command Injection"
    SCANNER       = "Scanner / Recon"
    BRUTE_FORCE   = "Brute Force"
    SSH_BRUTE     = "SSH Brute Force"
    FTP_BRUTE     = "FTP Brute Force"
    SMTP_BRUTE    = "SMTP Brute Force"
    HTTP_BRUTE    = "HTTP Brute Force"
    DB_BRUTE      = "Database Brute Force"
    DDOS          = "DDoS / Rate Abuse"
    FAIL2BAN      = "Fail2ban"
    CROWDSEC      = "CrowdSec"
    MODSECURITY   = "ModSecurity"


# Har bir hujum turi uchun blok muddati (soniya)
BLOCK_DURATION: Dict[AttackType, int] = {
    AttackType.SQL_INJECTION: 3600,
    AttackType.RCE:           3600,
    AttackType.CMD_INJECTION: 3600,
    AttackType.SSH_BRUTE:     3600,
    AttackType.DB_BRUTE:      3600,
    AttackType.FAIL2BAN:      3600,
    AttackType.CROWDSEC:      3600,
    AttackType.MODSECURITY:   3600,

    AttackType.DIR_TRAVERSAL: 1800,
    AttackType.LFI:           1800,
    AttackType.BRUTE_FORCE:   1800,
    AttackType.FTP_BRUTE:     1800,
    AttackType.SMTP_BRUTE:    1800,
    AttackType.HTTP_BRUTE:    1800,
    AttackType.SCANNER:       1800,
    AttackType.DDOS:          1800,

    AttackType.XSS:           0,   # Blok yo'q — faqat alert
}

# Blok qilinadigan hujumlar
SHOULD_BLOCK = {a for a, d in BLOCK_DURATION.items() if d > 0}


@dataclass
class Hit:
    attack_type:    AttackType
    severity:       Severity
    ip:             str
    path:           str
    raw_line:       str
    source_file:    str
    timestamp:      float = field(default_factory=time.time)
    details:        str   = ""
    should_block:   bool  = False
    block_duration: int   = 3600
    source:         str   = "dsips"
    service:        str   = ""


# ── Regex patternlari ─────────────────────────────────────────

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
    r"burpsuite|owasp.?zap|nuclei|whatweb|wapiti|zgrab|skipfish|"
    r"python-requests/|curl/[0-9]|go-http-client|java/[0-9])",
    re.IGNORECASE,
)

# ── Xizmat brute-force patternlari ───────────────────────────

RE_SSH_FAIL = re.compile(
    r"(failed password for|invalid user .+ from|"
    r"connection closed by .+ \[preauth\]|"
    r"disconnected from .+ \[preauth\]|"
    r"pam_unix.*sshd.*auth.*failure)",
    re.IGNORECASE,
)
RE_SSH_IP = re.compile(
    r"(?:from|authenticating)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port",
    re.IGNORECASE,
)

RE_FTP_FAIL = re.compile(
    r"(failed login|incorrect password|authentication failed|"
    r"vsftpd.*failed|proftpd.*failed)",
    re.IGNORECASE,
)

RE_SMTP_FAIL = re.compile(
    r"(sasl (login|auth) failed|authentication failed|"
    r"relay access denied|postfix.*noqueue.*reject|"
    r"exim.*rejected)",
    re.IGNORECASE,
)

RE_HTTP_FAIL = re.compile(r'HTTP/\d\.\d"\s+(401|403)', re.IGNORECASE)

RE_DB_FAIL = re.compile(
    r"(access denied for user|authentication.*failed.*mysql|"
    r"password authentication failed for user|"
    r"redis.*wrongpass|redis.*noauth)",
    re.IGNORECASE,
)

RE_F2B_BAN  = re.compile(
    r"fail2ban\.actions.*(?:WARNING|NOTICE).*Ban\s+(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
RE_F2B_JAIL = re.compile(r"\[([\w-]+)\].*Ban", re.IGNORECASE)

RE_CS_BAN = re.compile(
    r"crowdsec.*(?:ban|added|remediation).*?(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
RE_CS_ALERT = re.compile(
    r"crowdsec.*(?:alert|trigger|detect).*?(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)

RE_MODSEC_BLOCK = re.compile(
    r"(Access denied|ModSecurity.*phase|Inbound Anomaly)",
    re.IGNORECASE,
)
RE_MODSEC_IP   = re.compile(
    r"\[client\s+(\d{1,3}(?:\.\d{1,3}){3})\]",
    re.IGNORECASE,
)
RE_MODSEC_RULE = re.compile(r'\[id "(\d+)"\]')
RE_MODSEC_MSG  = re.compile(r'\[msg "([^"]+)"\]')

RE_WEBLOG = re.compile(
    r'^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+'
    r'"[A-Z]+\s+([^\s"]+)',
    re.IGNORECASE,
)
RE_IP = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')

# ── Cooldown muddatlari ───────────────────────────────────────
# Har bir hujum turi uchun alohida cooldown (soniya)
# Bu qiymat blok muddatidan kam bo'lmasligi kerak (takroriy alert oldini olish uchun)
ALERT_COOLDOWN: Dict[AttackType, int] = {
    AttackType.SSH_BRUTE:     300,   # 5 daqiqa — blok qilingan, ortiqcha alert kerak emas
    AttackType.FTP_BRUTE:     300,
    AttackType.SMTP_BRUTE:    300,
    AttackType.HTTP_BRUTE:    300,
    AttackType.DB_BRUTE:      300,
    AttackType.SQL_INJECTION: 300,
    AttackType.RCE:           300,
    AttackType.CMD_INJECTION: 300,
    AttackType.DIR_TRAVERSAL: 300,
    AttackType.LFI:           300,
    AttackType.SCANNER:       600,   # Scanner ko'p so'rovlar yuboradi — 10 daqiqa
    AttackType.DDOS:          120,   # DDoS tez o'zgaradi — 2 daqiqa
    AttackType.XSS:           120,
    AttackType.FAIL2BAN:      300,
    AttackType.CROWDSEC:      300,
    AttackType.MODSECURITY:   300,
}


class Detector:
    def __init__(self, cfg: Config, blocker, reporter):
        self.cfg      = cfg
        self.blocker  = blocker
        self.reporter = reporter

        # DDoS tracking: ip → timestamps
        self._reqs:  Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=self.cfg.ddos_threshold * 2)
        )
        # Xizmat brute tracking: ip → timestamps
        self._ssh:   Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=20))
        self._ftp:   Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=20))
        self._smtp:  Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=20))
        self._http:  Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=20))
        self._db:    Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=20))

        # FIX: _done endi blocker._blocked bilan sinxronlashadi
        # To'g'ridan-to'g'ri blocker.is_blocked() ishlatiladi
        self._cool:  Dict[str, float] = {}   # cooldown: "ip:attack_type" → timestamp

    # ── Yordamchilar ──────────────────────────────────────────

    def _parse_weblog(self, line: str):
        m = RE_WEBLOG.match(line)
        if m:
            return m.group(1), m.group(2)
        ip = RE_IP.search(line)
        pm = re.search(r'"[A-Z]+\s+(/[^\s"]*)', line)
        return (
            ip.group(1) if ip else "unknown",
            pm.group(1) if pm else line[:200],
        )

    def _white(self, ip: str) -> bool:
        return ip in self.cfg.whitelisted_ips or ip == "unknown"

    def _cooldown(self, ip: str, atype: AttackType) -> bool:
        """
        True = cooldownda, skip qil.
        Har bir hujum turi uchun alohida cooldown vaqti ishlatiladi.
        """
        k = f"{ip}:{atype.value}"
        now = time.time()
        seconds = ALERT_COOLDOWN.get(atype, 300)
        if now - self._cool.get(k, 0) < seconds:
            return True
        self._cool[k] = now
        return False

    def _count_recent(self, q: Deque[float], window: int) -> int:
        now = time.time()
        q.append(now)
        return sum(1 for t in q if t > now - window)

    def _ddos(self, ip: str) -> bool:
        # FIX: cfg.ddos_threshold ishlatiladi (150 ga o'zgartirildi config da)
        return self._count_recent(
            self._reqs[ip], self.cfg.ddos_window
        ) >= self.cfg.ddos_threshold

    def _ssh_brute(self, ip: str) -> bool:
        return self._count_recent(self._ssh[ip], 300) >= 3

    def _ftp_brute(self, ip: str) -> bool:
        return self._count_recent(self._ftp[ip], 300) >= 5

    def _smtp_brute(self, ip: str) -> bool:
        return self._count_recent(self._smtp[ip], 300) >= 5

    def _http_brute(self, ip: str) -> bool:
        return self._count_recent(self._http[ip], 60) >= 10

    def _db_brute(self, ip: str) -> bool:
        return self._count_recent(self._db[ip], 300) >= 5

    def _make_hit(
        self,
        attack_type: AttackType,
        severity: Severity,
        ip: str,
        path: str,
        line: str,
        source: str,
        details: str = "",
        service: str = "",
    ) -> Hit:
        dur = BLOCK_DURATION.get(attack_type, 3600)
        return Hit(
            attack_type    = attack_type,
            severity       = severity,
            ip             = ip,
            path           = path,
            raw_line       = line,
            source_file    = source,
            details        = details,
            should_block   = attack_type in SHOULD_BLOCK,
            block_duration = dur,
            source         = "dsips",
            service        = service,
        )

    # ── Integratsiya parserlari ───────────────────────────────

    def _parse_fail2ban(self, line: str, source: str) -> Optional[Hit]:
        m = RE_F2B_BAN.search(line)
        if not m:
            return None
        ip   = m.group(1)
        jail = RE_F2B_JAIL.search(line)
        jail_name = jail.group(1) if jail else "unknown"
        return Hit(
            attack_type    = AttackType.FAIL2BAN,
            severity       = Severity.HIGH,
            ip             = ip,
            path           = f"jail: {jail_name}",
            raw_line       = line,
            source_file    = source,
            details        = f"Fail2ban ban: [{jail_name}]",
            should_block   = True,
            block_duration = 3600,
            source         = "fail2ban",
            service        = jail_name,
        )

    def _parse_crowdsec(self, line: str, source: str) -> Optional[Hit]:
        m = RE_CS_BAN.search(line)
        if m:
            return Hit(
                attack_type    = AttackType.CROWDSEC,
                severity       = Severity.HIGH,
                ip             = m.group(1),
                path           = "crowdsec decision",
                raw_line       = line,
                source_file    = source,
                details        = "CrowdSec community ban",
                should_block   = True,
                block_duration = 3600,
                source         = "crowdsec",
            )
        m = RE_CS_ALERT.search(line)
        if m:
            return Hit(
                attack_type    = AttackType.CROWDSEC,
                severity       = Severity.MEDIUM,
                ip             = m.group(1),
                path           = "crowdsec alert",
                raw_line       = line,
                source_file    = source,
                details        = "CrowdSec alert",
                should_block   = False,
                block_duration = 0,
                source         = "crowdsec",
            )
        return None

    def _parse_modsec(self, line: str, source: str) -> Optional[Hit]:
        if not RE_MODSEC_BLOCK.search(line):
            return None
        m = RE_MODSEC_IP.search(line)
        if not m:
            return None
        ip   = m.group(1)
        rule = RE_MODSEC_RULE.search(line)
        msg  = RE_MODSEC_MSG.search(line)
        det  = f"Rule {rule.group(1)}" if rule else ""
        if msg:
            det += f": {msg.group(1)[:80]}"
        return Hit(
            attack_type    = AttackType.MODSECURITY,
            severity       = Severity.HIGH,
            ip             = ip,
            path           = "modsecurity block",
            raw_line       = line,
            source_file    = source,
            details        = det or "ModSecurity block",
            should_block   = True,
            block_duration = 3600,
            source         = "modsecurity",
        )

    # ── Asosiy tahlil ─────────────────────────────────────────

    async def analyze(self, line: str, source: str):
        # Integratsiya loglari
        if "fail2ban" in source or ("fail2ban" in line.lower() and "Ban" in line):
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

        # IP ni aniqlash
        ip, path = self._parse_weblog(line)
        if self._white(ip):
            return

        # ── Auth log tahlili (SSH, FTP, SMTP, DB) ─────────────
        if any(x in source for x in ("auth.log", "secure", "syslog")):

            # SSH brute force
            if RE_SSH_FAIL.search(line):
                ssh_ip = RE_SSH_IP.search(line)
                real_ip = ssh_ip.group(1) if ssh_ip else ip
                if real_ip and not self._white(real_ip):
                    self._ssh[real_ip].append(time.time())
                    if self._ssh_brute(real_ip):
                        hit = self._make_hit(
                            AttackType.SSH_BRUTE, Severity.HIGH,
                            real_ip, "SSH", line, source,
                            details="3+ failed SSH login within 5 min",
                            service="ssh",
                        )
                        await self._handle(hit)
                        return

            # FTP brute
            if RE_FTP_FAIL.search(line):
                ftp_ip = RE_IP.search(line)
                real_ip = ftp_ip.group(1) if ftp_ip else ip
                if real_ip and not self._white(real_ip):
                    self._ftp[real_ip].append(time.time())
                    if self._ftp_brute(real_ip):
                        hit = self._make_hit(
                            AttackType.FTP_BRUTE, Severity.HIGH,
                            real_ip, "FTP", line, source,
                            details="5+ failed FTP login",
                            service="ftp",
                        )
                        await self._handle(hit)
                        return

            # SMTP brute
            if RE_SMTP_FAIL.search(line):
                smtp_ip = RE_IP.search(line)
                real_ip = smtp_ip.group(1) if smtp_ip else ip
                if real_ip and not self._white(real_ip):
                    self._smtp[real_ip].append(time.time())
                    if self._smtp_brute(real_ip):
                        hit = self._make_hit(
                            AttackType.SMTP_BRUTE, Severity.HIGH,
                            real_ip, "SMTP", line, source,
                            details="5+ failed SMTP auth",
                            service="smtp",
                        )
                        await self._handle(hit)
                        return

            # DB brute
            if RE_DB_FAIL.search(line):
                db_ip = RE_IP.search(line)
                real_ip = db_ip.group(1) if db_ip else ip
                if real_ip and not self._white(real_ip):
                    self._db[real_ip].append(time.time())
                    if self._db_brute(real_ip):
                        hit = self._make_hit(
                            AttackType.DB_BRUTE, Severity.CRITICAL,
                            real_ip, "Database", line, source,
                            details="5+ failed DB auth",
                            service="database",
                        )
                        await self._handle(hit)
                        return

        # ── Web log tahlili ────────────────────────────────────
        if any(x in source for x in ("access.log", "nginx", "apache")):
            # DDoS tracking — har so'rov uchun
            self._reqs[ip].append(time.time())

            # HTTP brute (401/403)
            if RE_HTTP_FAIL.search(line):
                self._http[ip].append(time.time())
                if self._http_brute(ip):
                    hit = self._make_hit(
                        AttackType.HTTP_BRUTE, Severity.HIGH,
                        ip, path, line, source,
                        details="10+ HTTP 401/403 per minute",
                        service="http",
                    )
                    await self._handle(hit)
                    return

        # ── Web hujumlar (priority tartibida) ─────────────────
        hit = None

        if RE_SQL.search(line):
            hit = self._make_hit(
                AttackType.SQL_INJECTION, Severity.CRITICAL,
                ip, path, line, source,
            )
        elif RE_RCE.search(line):
            hit = self._make_hit(
                AttackType.RCE, Severity.CRITICAL,
                ip, path, line, source,
            )
        elif RE_CMD.search(line):
            hit = self._make_hit(
                AttackType.CMD_INJECTION, Severity.CRITICAL,
                ip, path, line, source,
            )
        elif RE_TRAVERSAL.search(line):
            hit = self._make_hit(
                AttackType.DIR_TRAVERSAL, Severity.HIGH,
                ip, path, line, source,
                details="Path traversal attempt",
            )
        elif RE_LFI.search(line):
            hit = self._make_hit(
                AttackType.LFI, Severity.HIGH,
                ip, path, line, source,
            )
        elif RE_XSS.search(line):
            hit = self._make_hit(
                AttackType.XSS, Severity.MEDIUM,
                ip, path, line, source,
            )
        elif RE_SCANNER.search(line):
            hit = self._make_hit(
                AttackType.SCANNER, Severity.MEDIUM,
                ip, path, line, source,
                details="Recon/scanner tool detected",
            )
        elif self._ddos(ip):
            hit = self._make_hit(
                AttackType.DDOS, Severity.HIGH,
                ip, path, line, source,
                details=f">{self.cfg.ddos_threshold} req/{self.cfg.ddos_window}s",
            )

        if hit:
            await self._handle(hit)

    async def _handle(self, h: Hit):
        # Whitelist tekshiruvi (ikkinchi qatlamda ham)
        if self._white(h.ip):
            return

        # FIX: cooldown — har hujum turi uchun alohida muddat
        if self._cooldown(h.ip, h.attack_type):
            return

        logger.warning(
            f"[{h.severity.upper()}] {h.attack_type.value} | "
            f"{h.ip} | {h.source} | svc={h.service or '-'} | {h.path[:60]}"
        )

        # FIX: blocker.is_blocked() orqali tekshirish — _done o'rniga
        # Bu unblock bo'lgandan keyin qayta blok qilinishiga imkon beradi
        if h.should_block:
            if self.blocker.is_blocked(h.ip):
                # Allaqachon bloklangan — faqat log, Telegram alert yubormaymiz
                logger.debug(f"Allaqachon bloklangan, alert o'tkazib yuborildi: {h.ip}")
                return

            if not self.cfg.dry_run:
                ok = await self.blocker.block(h.ip, h.block_duration, h.attack_type.value)
                if ok:
                    logger.info(f"Bloklandi: {h.ip} | {h.block_duration}s | {h.attack_type.value}")
                else:
                    logger.error(f"Bloklash muvaffaqiyatsiz: {h.ip}")
            else:
                logger.info(f"[DRY RUN] Would block {h.ip} for {h.block_duration}s")

        # Telegram alert — blok qilingan bo'lsa ham, qilinmagan bo'lsa ham yuboriladi
        await self.reporter.send(h)