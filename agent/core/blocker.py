"""
DSIPS IP Blocker v2.0
- HTTP hujumlar: iptables/ipset/ufw
- TCP/UDP flood: iptables rate limiting
- Port scan: iptables recent module
- Fail2ban bilan parallel ishlaydi (conflict yo'q)
"""

import asyncio
import logging
import shutil
import subprocess
import time
from typing import Dict

from agent.config.settings import Config

logger = logging.getLogger("dsips.blocker")


class Blocker:
    def __init__(self, cfg: Config):
        self.cfg      = cfg
        self._blocked: Dict[str, float] = {}
        self._backend = self._detect()
        logger.info(f"Firewall backend: {self._backend}")

    def _detect(self) -> str:
        b = self.cfg.firewall_backend
        if b != "auto":
            return b
        if shutil.which("ipset") and shutil.which("iptables"):
            return "ipset"
        if shutil.which("ufw"):
            r = subprocess.run(["ufw", "status"], capture_output=True, text=True)
            if "active" in r.stdout.lower():
                return "ufw"
        if shutil.which("iptables"):
            return "iptables"
        logger.warning("Firewall topilmadi — bloklash o'chirilgan.")
        return "none"

    async def _run(self, cmd: list) -> bool:
        try:
            p = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(p.communicate(), timeout=10)
            if p.returncode != 0:
                logger.debug(f"CMD: {' '.join(cmd)} → {stderr.decode().strip()}")
                return False
            return True
        except Exception as e:
            logger.error(f"CMD xato: {e}")
            return False

    # ── ipset sozlash ─────────────────────────────────────────
    async def _ipset_init(self):
        """dsips_blocked ipset yaratish va iptables ga ulash."""
        await self._run(["ipset", "create", "dsips_blocked", "hash:ip",
                         "timeout", "0", "maxelem", "65536"])
        exists = await self._run([
            "iptables", "-C", "INPUT", "-m", "set",
            "--match-set", "dsips_blocked", "src", "-j", "DROP"
        ])
        if not exists:
            await self._run([
                "iptables", "-I", "INPUT", "1", "-m", "set",
                "--match-set", "dsips_blocked", "src", "-j", "DROP"
            ])

    # ── TCP/UDP flood himoyasi ────────────────────────────────
    async def setup_flood_protection(self):
        """
        Bir martalik chaqiriladi — server uchun global qoidalar.
        Zarar yetkazmasdan himoya qiladi.
        """
        if self._backend == "none":
            return

        logger.info("Flood himoya qoidalari o'rnatilmoqda...")

        # TCP SYN flood
        await self._run([
            "iptables", "-A", "INPUT", "-p", "tcp", "--syn",
            "-m", "limit", "--limit", "100/s", "--limit-burst", "200",
            "-j", "ACCEPT"
        ])
        await self._run([
            "iptables", "-A", "INPUT", "-p", "tcp", "--syn", "-j", "DROP"
        ])

        # UDP flood
        await self._run([
            "iptables", "-A", "INPUT", "-p", "udp",
            "-m", "limit", "--limit", "100/s", "--limit-burst", "200",
            "-j", "ACCEPT"
        ])
        await self._run([
            "iptables", "-A", "INPUT", "-p", "udp",
            "-m", "state", "--state", "NEW",
            "-j", "DROP"
        ])

        # ICMP flood (ping)
        await self._run([
            "iptables", "-A", "INPUT", "-p", "icmp",
            "-m", "limit", "--limit", "10/s", "--limit-burst", "20",
            "-j", "ACCEPT"
        ])
        await self._run([
            "iptables", "-A", "INPUT", "-p", "icmp", "-j", "DROP"
        ])

        # Port scan — recent module
        await self._run([
            "iptables", "-A", "INPUT", "-m", "recent",
            "--name", "portscan", "--rcheck",
            "--seconds", "60", "--hitcount", "10",
            "-j", "DROP"
        ])
        await self._run([
            "iptables", "-A", "INPUT", "-m", "recent",
            "--name", "portscan", "--set", "-j", "ACCEPT"
        ])

        # Invalid paketlar
        await self._run([
            "iptables", "-A", "INPUT", "-m", "state",
            "--state", "INVALID", "-j", "DROP"
        ])

        # Established/related ruxsat
        await self._run([
            "iptables", "-I", "INPUT", "1", "-m", "state",
            "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"
        ])

        # Localhost ruxsat
        await self._run([
            "iptables", "-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"
        ])

        logger.info("Flood himoya qoidalari o'rnatildi.")

    # ── IP bloklash ───────────────────────────────────────────
    async def block(self, ip: str, duration: int, reason: str = "") -> bool:
        if self._backend == "none":
            return False
        if ip in self._blocked:
            return True
        if ip in self.cfg.whitelisted_ips:
            logger.warning(f"Whitelist — bloklanmaydi: {ip}")
            return False

        ok = False
        if self._backend == "ipset":
            await self._ipset_init()
            ok = await self._run([
                "ipset", "add", "dsips_blocked", ip,
                "timeout", str(duration), "-exist"
            ])
        elif self._backend == "iptables":
            ok = await self._run([
                "iptables", "-I", "INPUT", "1",
                "-s", ip, "-j", "DROP",
                "-m", "comment", "--comment", f"dsips:{reason[:40]}"
            ])
        elif self._backend == "ufw":
            ok = await self._run(["ufw", "deny", "from", ip, "to", "any"])

        if ok:
            self._blocked[ip] = time.time() + duration
            logger.info(f"BLOCKED: {ip} | {duration}s | {reason}")
            if self._backend != "ipset":
                asyncio.create_task(self._expire(ip, duration))
        return ok

    async def unblock(self, ip: str) -> bool:
        if self._backend == "none":
            return False

        ok = False
        if self._backend == "ipset":
            ok = await self._run(["ipset", "del", "dsips_blocked", ip])
        elif self._backend == "iptables":
            ok = await self._run([
                "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"
            ])
        elif self._backend == "ufw":
            ok = await self._run([
                "ufw", "delete", "deny", "from", ip, "to", "any"
            ])

        if ok:
            self._blocked.pop(ip, None)
            logger.info(f"UNBLOCKED: {ip}")
        return ok

    async def _expire(self, ip: str, duration: int):
        await asyncio.sleep(duration)
        if ip in self._blocked:
            await self.unblock(ip)

    def is_blocked(self, ip: str) -> bool:
        exp = self._blocked.get(ip)
        if exp is None:
            return False
        if time.time() > exp:
            del self._blocked[ip]
            return False
        return True

    def list_blocked(self) -> Dict[str, float]:
        now = time.time()
        return {ip: exp for ip, exp in self._blocked.items() if exp > now}
