"""
DSIPS Log Monitor
Async tail-follow on all configured log files.
"""

import asyncio
import logging
from pathlib import Path
from typing import Dict

from agent.config.settings import Config
from agent.core.detector import Detector

logger = logging.getLogger("dsips.monitor")


class Tailer:
    def __init__(self, path: str, cb, poll: float = 0.5):
        self.path = path
        self.cb   = cb
        self.poll = poll
        self._running = False
        self._task = None

    async def _run(self):
        p     = Path(self.path)
        inode = None
        pos   = p.stat().st_size if p.exists() else 0
        logger.info(f"Watching: {self.path}")

        while self._running:
            try:
                if not p.exists():
                    await asyncio.sleep(self.poll); continue

                st = p.stat()
                if inode and st.st_ino != inode:
                    logger.info(f"Rotated: {self.path}")
                    pos = 0
                inode = st.st_ino

                if st.st_size < pos:
                    pos = 0

                if st.st_size > pos:
                    with open(self.path, "r", errors="replace") as f:
                        f.seek(pos)
                        data = f.read()
                        pos  = f.tell()
                    for line in data.splitlines():
                        line = line.strip()
                        if line:
                            await self.cb(line, self.path)

            except PermissionError:
                logger.warning(f"No permission: {self.path}")
                await asyncio.sleep(5)
            except Exception as e:
                logger.error(f"Tailer error ({self.path}): {e}")
                await asyncio.sleep(1)

            await asyncio.sleep(self.poll)

    async def start(self):
        self._running = True
        self._task = asyncio.create_task(self._run())

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try: await self._task
            except asyncio.CancelledError: pass


class Monitor:
    def __init__(self, cfg: Config, detector: Detector):
        self.cfg      = cfg
        self.detector = detector
        self.tailers: Dict[str, Tailer] = {}

    async def start(self):
        files = self.cfg.log_files or [
            "/var/log/nginx/access.log",
            "/var/log/apache2/access.log",
            "/var/log/auth.log",
            "/var/log/syslog",
        ]
        for f in files:
            t = Tailer(f, self.detector.analyze)
            await t.start()
            self.tailers[f] = t

        logger.info(f"Monitoring {len(self.tailers)} log file(s)")

        try:
            while True:
                await asyncio.sleep(60)
        except asyncio.CancelledError:
            pass

    async def stop(self):
        for t in self.tailers.values():
            await t.stop()
