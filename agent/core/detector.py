"""
DSIPS Detector v4.0 — To'liq nazorat
- Barcha web hujumlar (SQLi, XSS, RCE, CMDi, LFI, Traversal)
- Traversal barcha usullari (....// %2e%2e obfuskatsiya va h.k.)
- SSH/FTP/SMTP/DB brute force
- DDoS / Rate limiting
- Scanner / Recon
- Fail2ban / CrowdSec / ModSecurity integratsiya
- Barcha nginx log fayllari (har bir loyiha)
- Port scanning aniqlash
- Slow loris aniqlash
- User-agent anomaliyalar
"""

import re
import time
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Deque, Optional

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
    PORT_SCAN     = "Port Scan"
    SLOW_LORIS    = "Slow Loris"
    BAD_BOT       = "Bad Bot / Crawler"


BLOCK_DURATION: Dict[AttackType, int] = {
    AttackType.SQL_INJECTION: 86400,
    AttackType.RCE:           86400,
    AttackType.CMD_INJECTION: 86400,
    AttackType.SSH_BRUTE:     86400,
    AttackType.DB_BRUTE:      86400,
    AttackType.FAIL2BAN:      3600,
    AttackType.CROWDSEC:      3600,
    AttackType.MODSECURITY:   3600,
    AttackType.PORT_SCAN:     86400,
    AttackType.DIR_TRAVERSAL: 3600,
    AttackType.LFI:           3600,
    AttackType.BRUTE_FORCE:   3600,
    AttackType.FTP_BRUTE:     3600,
    AttackType.SMTP_BRUTE:    3600,
    AttackType.HTTP_BRUTE:    3600,
    AttackType.SCANNER:       3600,
    AttackType.DDOS:          1800,
    AttackType.SLOW_LORIS:    3600,
    AttackType.BAD_BOT:       1800,
    AttackType.XSS:           0,
}

SHOULD_BLOCK = {a for a, d in BLOCK_DURATION.items() if d > 0}

ALERT_COOLDOWN: Dict[AttackType, int] = {
    AttackType.SSH_BRUTE:     300,
    AttackType.FTP_BRUTE:     300,
    AttackType.SMTP_BRUTE:    300,
    AttackType.HTTP_BRUTE:    300,
    AttackType.DB_BRUTE:      300,
    AttackType.SQL_INJECTION: 300,
    AttackType.RCE:           300,
    AttackType.CMD_INJECTION: 300,
    AttackType.DIR_TRAVERSAL: 120,
    AttackType.LFI:           120,
    AttackType.SCANNER:       600,
    AttackType.DDOS:          60,
    AttackType.XSS:           120,
    AttackType.FAIL2BAN:      300,
    AttackType.CROWDSEC:      300,
    AttackType.MODSECURITY:   300,
    AttackType.PORT_SCAN:     300,
    AttackType.SLOW_LORIS:    300,
    AttackType.BAD_BOT:       600,
}


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


# ══════════════════════════════════════════════════════════════
# REGEX PATTERNLAR
# ══════════════════════════════════════════════════════════════

RE_SQL = re.compile(
    r"(union[\s+]+select|select[\s\+]+.+from|insert\s+into|drop\s+table|"
    r"drop\s+database|truncate\s+table|delete\s+from|"
    r"exec\s*\(|xp_cmdshell|sp_executesql|"
    r"'\s*or\s*'?\d|'\s*or\s*1\s*=\s*1|'\s*or\s*'a'\s*=\s*'a|"
    r"or\s+1\s*=\s*1|and\s+1\s*=\s*2|'\s*--\s*$|';\s*--|"
    r"/\*.*?\*/|#\s*$|--\s*$|"
    r"information_schema|sys\.tables|sysobjects|syscolumns|"
    r"benchmark\s*\(|sleep\s*\(\d|waitfor\s+delay|pg_sleep|"
    r"0x[0-9a-f]{4,}|char\s*\(\d+\)|nchar\s*\(|"
    r"cast\s*\(.+as\s+|convert\s*\(.+,|"
    r"load_file\s*\(|into\s+outfile|into\s+dumpfile|"
    r"concat\s*\(|group_concat|extractvalue\s*\(|updatexml\s*\(|"
    r"mid\s*\(|substr\s*\(|ascii\s*\(|hex\s*\(|unhex\s*\(|"
    r"case\s+when.+then|ifnull\s*\(|nullif\s*\(|"
    r"having\s+\d|order\s+by\s+\d|"
    r"%27|%22|%3b|%2d%2d|%23)",
    re.IGNORECASE,
)

RE_XSS = re.compile(
    r"(<script[\s>]|</script>|javascript\s*:|vbscript\s*:|"
    r"on(load|error|click|mouseover|mouseout|submit|focus|blur|"
    r"change|keyup|keydown|keypress|input|select|dblclick|"
    r"contextmenu|resize|scroll|unload|beforeunload|"
    r"drag|drop|copy|paste|cut)\s*=|"
    r"<iframe[\s>]|<frame[\s>]|<object[\s>]|<embed[\s>]|<applet[\s>]|"
    r"<form[\s>].*action\s*=|<input[\s>].*on\w+\s*=|"
    r"<img[^>]+onerror|<img[^>]+onload|<svg[^>]*on\w+\s*=|"
    r"alert\s*\(|confirm\s*\(|prompt\s*\(|"
    r"document\.(cookie|write|location|domain)|window\.(location|open)|"
    r"eval\s*\(|setTimeout\s*\(|setInterval\s*\(|"
    r"fromcharcode|String\.fromCharCode|atob\s*\(|btoa\s*\(|"
    r"expression\s*\(|url\s*\(javascript|"
    r"&#x[0-9a-f]+;|&#\d+;|%3cscript|%3csvg|"
    r"<\s*script|<\s*/\s*script)",
    re.IGNORECASE,
)

# TRAVERSAL — barcha usullar
RE_TRAVERSAL = re.compile(
    r"(\.\./|\.\.\\|"
    r"\.\.%2f|\.\.%5c|"
    r"\.\.%252f|\.\.%255c|"
    r"%2e%2e%2f|%2e%2e/|\.%2e/|%2e\./|"
    r"%2e%2e%5c|%252e%252e|"
    r"%c0%af|%c1%9c|%c0%2f|%c1%af|"
    r"\.{2,}/|"
    r"/etc/passwd|/etc/shadow|/etc/hosts|"
    r"/etc/group|/etc/crontab|/etc/fstab|"
    r"/etc/ssh/|/etc/nginx/|/etc/apache|"
    r"/proc/self|/proc/version|/proc/cmdline|/proc/environ|"
    r"\.htaccess|\.htpasswd|\.env|\.git/|\.svn/|"
    r"\.bash_history|authorized_keys|"
    r"/boot\.ini|c:\\windows|c:/windows|"
    r"WEB-INF|web\.xml|"
    r"wp-config\.php|"
    r"\.DS_Store)",
    re.IGNORECASE,
)

RE_RCE = re.compile(
    r"(;[\s]*(ls|cat|id|whoami|uname|pwd|ifconfig|ipconfig|"
    r"wget|curl|bash|sh|zsh|ksh|python[23]?|perl|ruby|php|"
    r"node|java|nc|ncat|netcat|socat)\s|"
    r"\|[\s]*(ls|cat|id|whoami|wget|curl|bash|sh|python[23]?|"
    r"perl|ruby|php|node|nc|ncat)\s|"
    r"`[^`]+`|\$\([^)]+\)|\$\{[^}]+\}|"
    r"cmd\.exe|/bin/sh|/bin/bash|/bin/zsh|/usr/bin/python|"
    r"system\s*\(|passthru\s*\(|shell_exec\s*\(|"
    r"popen\s*\(|proc_open\s*\(|exec\s*\(|"
    r"base64_decode\s*\(|str_rot13\s*\(|"
    r"assert\s*\(|preg_replace\s*\(.*\/e|"
    r"python\s+-c\s+['\"]|perl\s+-e\s+['\"]|ruby\s+-e\s+['\"]|"
    r"curl\s+https?://|wget\s+https?://|"
    r"chmod\s+[0-7]{3,4}|chown\s+root|chgrp\s+root|"
    r"nc\s+-[el]|ncat\s+-[el]|netcat\s+-[el]|"
    r">/dev/tcp/|>/dev/udp/|"
    r"mkfifo\s+|mknod\s+.*\s+p\s|"
    r"LD_PRELOAD=|LD_LIBRARY_PATH=)",
    re.IGNORECASE,
)

RE_LFI = re.compile(
    r"(php://filter|php://input|php://stdin|"
    r"data://|data:text/|expect://|phar://|zip://|"
    r"glob://|zlib://|"
    r"file=\.{2,}[/\\]|page=\.{2,}[/\\]|include=\.{2,}[/\\]|"
    r"path=\.{2,}[/\\]|doc=\.{2,}[/\\]|template=\.{2,}[/\\]|"
    r"load=\.{2,}[/\\]|read=\.{2,}[/\\]|fetch=\.{2,}[/\\]|"
    r"display=\.{2,}[/\\]|show=\.{2,}[/\\]|view=\.{2,}[/\\]|"
    r"file=.*%2e%2e|page=.*%2e%2e|include=.*%2e%2e|"
    r"file=https?://|page=https?://|include=https?://|"
    r"load=https?://|fetch=https?://)",
    re.IGNORECASE,
)

RE_CMD = re.compile(
    r"(;[\s]*(rm\s+-[rf]|mkfifo|chmod\s+777|"
    r"crontab\s+-|at\s+now|"
    r"passwd\s+root|useradd|adduser|"
    r"iptables\s+-F|ufw\s+disable|"
    r"dd\s+if=|format\s+c:)|"
    r"&&\s*(rm|wget|curl|chmod|chown|mv|cp|dd)|"
    r">\s*/etc/passwd|>>/etc/|>\s*/root/|"
    r"\|\s*bash|\|\s*sh\s|\|\s*python|\|\s*perl|"
    r"sudo\s+(rm|chmod|chown|bash|sh|python|nc)|"
    r">/dev/tcp/|>&/dev/tcp/|"
    r"eval\s+\$\(|eval\s+`)",
    re.IGNORECASE,
)

RE_SCANNER = re.compile(
    r"(sqlmap|nikto|nmap|masscan|nessus|openvas|acunetix|w3af|"
    r"dirbuster|gobuster|dirb|wfuzz|ffuf|feroxbuster|rustbuster|"
    r"hydra|medusa|ncrack|patator|"
    r"metasploit|msfconsole|meterpreter|"
    r"burpsuite|burp\s*suite|owasp.?zap|"
    r"nuclei|whatweb|wapiti|zgrab|skipfish|"
    r"shodan|censys|fofa|zoomeye|"
    r"python-httpx|python-requests/\d|"
    r"go-http-client|java/\d\.|"
    r"curl/\d\.\d|wget/\d\.\d|"
    r"scrapy|mechanize|httpclient|"
    r"masscan|zmap|unicornscan|"
    r"libwww-perl|lwp-request|"
    r"python/[23]\.\d|ruby/[23]\.\d|"
    r"zgrab|masscan|"
    r"\.git/HEAD|\.git/config|\.git/COMMIT|"
    r"\.svn/entries|\.svn/wc\.db|"
    r"wp-login\.php|wp-admin|wp-cron\.php|"
    r"xmlrpc\.php|wp-includes|wp-content|"
    r"phpmyadmin|pma/|adminer\.php|phpinfo|"
    r"\.well-known/security|"
    r"/\.env$|/\.env\b|"
    r"config\.php|database\.php|db\.php|"
    r"shell\.php|c99\.php|r57\.php|b374k|"
    r"eval\(base64|eval\(gzinflate|"
    r"/actuator/|/api-docs|/swagger|/graphql\?|"
    r"\.bak$|\.old$|\.tmp$|\.swp$|~$|"
    r"backup\.sql|dump\.sql|\.sql\.gz)",
    re.IGNORECASE,
)

# Port scan — syslog / kernel log
RE_PORT_SCAN = re.compile(
    r"(kernel.*DPT=\d+.*SRC=(\d{1,3}\.){3}\d{1,3}|"
    r"iptables.*DROPPED.*SRC=|"
    r"nmap\s+scan|port\s+scan\s+detected|"
    r"SCAN\s+from\s+(\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)

# Slow loris — nginx error log
RE_SLOW_LORIS = re.compile(
    r"(client\s+timed\s+out.*reading\s+client\s+request|"
    r"upstream\s+timed\s+out.*while\s+reading\s+response|"
    r"recv\(\)\s+failed.*client.*timed\s+out)",
    re.IGNORECASE,
)

# Bad bots / crawlers
RE_BAD_BOT = re.compile(
    r"(AhrefsBot|MJ12bot|DotBot|SemrushBot|BLEXBot|"
    r"MegaIndex|Baiduspider|YandexBot|360Spider|"
    r"sogou\s+spider|bingbot.*\d{1,3}\.\d{1,3}|"
    r"zgrab|masscan|nmap|"
    r"HeadlessChrome|PhantomJS|Selenium|"
    r"python-requests|Go-http-client|"
    r"scrapy|curl/\d|wget/\d|"
    r"libwww|lwp-trivial|"
    r"harvest|extract|grab|download|suck|"
    r"EmailCollector|EmailSiphon|WebBandit|"
    r"Xenu|WebZip|WebCopier|HTTrack)",
    re.IGNORECASE,
)

# ── Xizmat brute-force ────────────────────────────────────────

RE_SSH_FAIL = re.compile(
    r"(failed\s+password\s+for|invalid\s+user\s+.+\s+from|"
    r"connection\s+closed\s+by\s+.+\s+\[preauth\]|"
    r"disconnected\s+from\s+.+\s+\[preauth\]|"
    r"pam_unix.*sshd.*auth.*failure|"
    r"authentication\s+failure.*sshd|"
    r"no\s+identification\s+string\s+from|"
    r"did\s+not\s+receive\s+identification\s+string|"
    r"error:\s+maximum\s+authentication\s+attempts\s+exceeded|"
    r"too\s+many\s+authentication\s+failures)",
    re.IGNORECASE,
)
RE_SSH_IP = re.compile(
    r"(?:from|authenticating|address)\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s+port|\s*$)",
    re.IGNORECASE,
)

RE_FTP_FAIL = re.compile(
    r"(failed\s+login|incorrect\s+password|authentication\s+failed|"
    r"vsftpd.*failed|proftpd.*failed|pure-ftpd.*auth|"
    r"530\s+(login|password|user)|"
    r"Login\s+failed\s+for\s+user)",
    re.IGNORECASE,
)

RE_SMTP_FAIL = re.compile(
    r"(sasl\s+(login|auth)\s+failed|authentication\s+failed|"
    r"relay\s+access\s+denied|postfix.*noqueue.*reject|"
    r"exim.*rejected|535.*authentication|"
    r"dovecot.*auth.*failed|"
    r"SASL\s+PLAIN\s+authentication\s+failed|"
    r"lost\s+connection\s+after\s+AUTH)",
    re.IGNORECASE,
)

RE_HTTP_FAIL = re.compile(
    r'(HTTP/\d\.\d"\s+(401|403)|"(401|403)"\s+\d+)',
    re.IGNORECASE,
)

RE_DB_FAIL = re.compile(
    r"(access\s+denied\s+for\s+user|"
    r"authentication.*failed.*mysql|"
    r"password\s+authentication\s+failed\s+for\s+user|"
    r"FATAL.*password\s+authentication\s+failed|"
    r"redis.*wrongpass|redis.*noauth|"
    r"mongod.*authentication.*failed|"
    r"ORA-01017|"
    r"Login\s+failed\s+for\s+user.*SQL)",
    re.IGNORECASE,
)

# Integratsiya
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
    r"(Access\s+denied|ModSecurity.*phase|Inbound\s+Anomaly|"
    r"Outbound\s+Anomaly|Request\s+Rejected)",
    re.IGNORECASE,
)
RE_MODSEC_IP   = re.compile(r"\[client\s+(\d{1,3}(?:\.\d{1,3}){3})\]", re.IGNORECASE)
RE_MODSEC_RULE = re.compile(r'\[id\s+"(\d+)"\]')
RE_MODSEC_MSG  = re.compile(r'\[msg\s+"([^"]+)"\]')

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
            lambda: deque(maxlen=500)
        )
        self._ssh:   Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=20))
        self._ftp:   Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=20))
        self._smtp:  Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=20))
        self._http:  Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=50))
        self._db:    Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=20))
        self._slow:  Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=20))
        self._ports: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=50))

        self._cool:  Dict[str, float] = {}

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

    def _slow_loris(self, ip: str) -> bool:
        return self._count_recent(self._slow[ip], 60) >= 5

    def _port_scan(self, ip: str) -> bool:
        return self._count_recent(self._ports[ip], 60) >= 10

    def _make_hit(self, attack_type, severity, ip, path, line, source,
                  details="", service="") -> Hit:
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

    def _is_web_log(self, source: str) -> bool:
        keywords = ("access.log", "access_log", "nginx", "apache",
                    "httpd", "access", "http", "vhost", "site")
        src = source.lower()
        return any(k in src for k in keywords)

    def _is_auth_log(self, source: str) -> bool:
        keywords = ("auth.log", "auth", "secure", "syslog",
                    "messages", "system.log")
        src = source.lower()
        return any(k in src for k in keywords)

    def _is_error_log(self, source: str) -> bool:
        keywords = ("error.log", "error_log", "nginx/error",
                    "apache/error", "modsec")
        src = source.lower()
        return any(k in src for k in keywords)

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

    async def analyze(self, line: str, source: str):
        # ── Integratsiya loglari ──────────────────────────────
        if "fail2ban" in source.lower() or (
            "fail2ban" in line.lower() and "Ban" in line
        ):
            hit = self._parse_fail2ban(line, source)
            if hit:
                await self._handle(hit)
            return

        if "crowdsec" in source.lower() or "crowdsec" in line.lower():
            hit = self._parse_crowdsec(line, source)
            if hit:
                await self._handle(hit)
            return

        if ("modsec" in source.lower() or "ModSecurity" in line or
                "modsecurity" in line.lower()):
            hit = self._parse_modsec(line, source)
            if hit:
                await self._handle(hit)
            return

        # IP aniqlash
        ip, path = self._parse_weblog(line)
        if self._white(ip):
            return

        # ── Auth log (SSH/FTP/SMTP/DB) ────────────────────────
        if self._is_auth_log(source):

            if RE_SSH_FAIL.search(line):
                ssh_ip = RE_SSH_IP.search(line)
                real_ip = ssh_ip.group(1) if ssh_ip else ip
                if real_ip and not self._white(real_ip):
                    self._ssh[real_ip].append(time.time())
                    if self._ssh_brute(real_ip):
                        await self._handle(self._make_hit(
                            AttackType.SSH_BRUTE, Severity.HIGH,
                            real_ip, "SSH", line, source,
                            details="3+ failed SSH login within 5 min",
                            service="ssh",
                        ))
                        return

            if RE_FTP_FAIL.search(line):
                ftp_ip = RE_IP.search(line)
                real_ip = ftp_ip.group(1) if ftp_ip else ip
                if real_ip and not self._white(real_ip):
                    self._ftp[real_ip].append(time.time())
                    if self._ftp_brute(real_ip):
                        await self._handle(self._make_hit(
                            AttackType.FTP_BRUTE, Severity.HIGH,
                            real_ip, "FTP", line, source,
                            details="5+ failed FTP login within 5 min",
                            service="ftp",
                        ))
                        return

            if RE_SMTP_FAIL.search(line):
                smtp_ip = RE_IP.search(line)
                real_ip = smtp_ip.group(1) if smtp_ip else ip
                if real_ip and not self._white(real_ip):
                    self._smtp[real_ip].append(time.time())
                    if self._smtp_brute(real_ip):
                        await self._handle(self._make_hit(
                            AttackType.SMTP_BRUTE, Severity.HIGH,
                            real_ip, "SMTP", line, source,
                            details="5+ failed SMTP auth within 5 min",
                            service="smtp",
                        ))
                        return

            if RE_DB_FAIL.search(line):
                db_ip = RE_IP.search(line)
                real_ip = db_ip.group(1) if db_ip else ip
                if real_ip and not self._white(real_ip):
                    self._db[real_ip].append(time.time())
                    if self._db_brute(real_ip):
                        await self._handle(self._make_hit(
                            AttackType.DB_BRUTE, Severity.CRITICAL,
                            real_ip, "Database", line, source,
                            details="5+ failed DB auth within 5 min",
                            service="database",
                        ))
                        return

        # ── Port scan (kernel/syslog) ─────────────────────────
        if "syslog" in source.lower() or "kern" in source.lower():
            if RE_PORT_SCAN.search(line):
                scan_ip = RE_IP.search(line)
                real_ip = scan_ip.group(1) if scan_ip else ip
                if real_ip and not self._white(real_ip):
                    self._ports[real_ip].append(time.time())
                    if self._port_scan(real_ip):
                        await self._handle(self._make_hit(
                            AttackType.PORT_SCAN, Severity.HIGH,
                            real_ip, "PORTSCAN", line, source,
                            details="Port scan detected via iptables log",
                            service="network",
                        ))
                        return

        # ── Error log (Slow loris) ────────────────────────────
        if self._is_error_log(source):
            if RE_SLOW_LORIS.search(line):
                if ip and not self._white(ip):
                    self._slow[ip].append(time.time())
                    if self._slow_loris(ip):
                        await self._handle(self._make_hit(
                            AttackType.SLOW_LORIS, Severity.HIGH,
                            ip, path, line, source,
                            details="Slow loris / connection timeout attack",
                            service="http",
                        ))
                        return

        # ── Web log ────────────────────────────────────────────
        if self._is_web_log(source):
            # DDoS tracking
            self._reqs[ip].append(time.time())

            # HTTP brute (401/403)
            if RE_HTTP_FAIL.search(line):
                self._http[ip].append(time.time())
                if self._http_brute(ip):
                    await self._handle(self._make_hit(
                        AttackType.HTTP_BRUTE, Severity.HIGH,
                        ip, path, line, source,
                        details="10+ HTTP 401/403 per minute",
                        service="http",
                    ))
                    return

            # Bad bot
            if RE_BAD_BOT.search(line):
                await self._handle(self._make_hit(
                    AttackType.BAD_BOT, Severity.MEDIUM,
                    ip, path, line, source,
                    details="Malicious bot/crawler detected",
                    service="http",
                ))
                return

        # ── Barcha loglarda web hujumlar ──────────────────────
        hit = None

        if RE_SQL.search(line):
            hit = self._make_hit(
                AttackType.SQL_INJECTION, Severity.CRITICAL,
                ip, path, line, source,
                details="SQL injection attempt",
                service="http",
            )
        elif RE_RCE.search(line):
            hit = self._make_hit(
                AttackType.RCE, Severity.CRITICAL,
                ip, path, line, source,
                details="Remote code execution attempt",
                service="http",
            )
        elif RE_CMD.search(line):
            hit = self._make_hit(
                AttackType.CMD_INJECTION, Severity.CRITICAL,
                ip, path, line, source,
                details="Command injection attempt",
                service="http",
            )
        elif RE_LFI.search(line):
            hit = self._make_hit(
                AttackType.LFI, Severity.HIGH,
                ip, path, line, source,
                details="Local file inclusion attempt",
                service="http",
            )
        elif RE_TRAVERSAL.search(line):
            hit = self._make_hit(
                AttackType.DIR_TRAVERSAL, Severity.HIGH,
                ip, path, line, source,
                details="Directory/path traversal attempt",
                service="http",
            )
        elif RE_XSS.search(line):
            hit = self._make_hit(
                AttackType.XSS, Severity.MEDIUM,
                ip, path, line, source,
                details="Cross-site scripting attempt",
                service="http",
            )
        elif RE_SCANNER.search(line):
            hit = self._make_hit(
                AttackType.SCANNER, Severity.MEDIUM,
                ip, path, line, source,
                details="Recon/scanner tool detected",
                service="http",
            )
        elif self._is_web_log(source) and self._ddos(ip):
            hit = self._make_hit(
                AttackType.DDOS, Severity.HIGH,
                ip, path, line, source,
                details=f">{self.cfg.ddos_threshold} req/{self.cfg.ddos_window}s",
                service="http",
            )

        if hit:
            await self._handle(hit)

    async def _handle(self, h: Hit):
        if self._white(h.ip):
            return

        if self._cooldown(h.ip, h.attack_type):
            return

        logger.warning(
            f"[{h.severity.upper()}] {h.attack_type.value} | "
            f"{h.ip} | {h.source} | svc={h.service or '-'} | {h.path[:60]}"
        )

        if h.should_block:
            if hasattr(self.blocker, 'is_blocked') and self.blocker.is_blocked(h.ip):
                logger.debug(f"Allaqachon bloklangan: {h.ip}")
                return

            if not self.cfg.dry_run:
                ok = await self.blocker.block(h.ip, h.block_duration, h.attack_type.value)
                if ok:
                    logger.info(f"Bloklandi: {h.ip} | {h.block_duration}s")
            else:
                logger.info(f"[DRY RUN] block {h.ip} {h.block_duration}s")

        await self.reporter.send(h)