"""
DSIPS Reporter v2.0
- /register dan api_key oladi
- Hit.source ni ham yuboradi (fail2ban/crowdsec/modsecurity/dsips)
"""

import asyncio
import json
import logging
import pathlib
import time
from collections import deque
from typing import Optional

import aiohttp

from agent.config.settings import Config
from agent.core.detector import Hit

logger = logging.getLogger("dsips.reporter")
CONFIG_PATH = pathlib.Path("/etc/dsips/config.json")


class Reporter:
    def __init__(self, cfg: Config):
        self.cfg    = cfg
        self._queue = deque(maxlen=1000)
        self._sess: Optional[aiohttp.ClientSession] = None
        self._task  = asyncio.create_task(self._flush_loop())

    async def _session(self) -> aiohttp.ClientSession:
        if self._sess is None or self._sess.closed:
            self._sess = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            )
        return self._sess

    async def register(self) -> bool:
        """dsips.yescrypt.uz/register dan api_key olish."""
        if self.cfg.api_key:
            return True
        try:
            s = await self._session()
            async with s.get(
                f"{self.cfg.api_url}/register",
                params={"telegram_user_id": self.cfg.telegram_user_id},
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    key = data.get("api_key", "")
                    if key:
                        self.cfg.api_key = key
                        # config.json ga saqlash
                        try:
                            cfg_data = json.loads(CONFIG_PATH.read_text())
                            cfg_data["api_key"] = key
                            CONFIG_PATH.write_text(json.dumps(cfg_data, indent=2))
                        except Exception:
                            pass
                        logger.info("API key olindi va saqlandi.")
                        return True
        except Exception as e:
            logger.debug(f"Register: {e}")
        return False

    def _payload(self, h: Hit) -> dict:
        return {
            "ip":          h.ip,
            "attack":      h.attack_type.value,
            "severity":    h.severity.value,
            "path":        h.path[:500],
            "timestamp":   h.timestamp,
            "server_name": self.cfg.server_name,
            "chat_id":     self.cfg.telegram_user_id,
            "source":      h.source,
            "details":     h.details,
        }

    async def send(self, hit: Hit):
        payload = self._payload(hit)
        if not await self._post(payload):
            self._queue.append(payload)

    async def _post(self, payload: dict) -> bool:
        if not self.cfg.api_key:
            if not await self.register():
                return False
        try:
            s = await self._session()
            async with s.post(
                f"{self.cfg.api_url}/alert",
                json=payload,
                headers={"X-DSIPS-KEY": self.cfg.api_key},
            ) as r:
                if r.status in (200, 201):
                    logger.info(
                        f"Alert → {payload['attack']} | {payload['ip']} "
                        f"[{payload.get('source','dsips')}]"
                    )
                    return True
                body = await r.text()
                logger.warning(f"API {r.status}: {body[:100]}")
                # Key eskirgan bo'lsa — qayta register qilamiz
                if r.status == 403:
                    self.cfg.api_key = ""
                return False
        except Exception as e:
            logger.debug(f"API: {e}")
            return False

    async def _flush_loop(self):
        while True:
            await asyncio.sleep(30)
            if not self._queue:
                continue
            sent = 0
            while self._queue:
                if await self._post(self._queue[0]):
                    self._queue.popleft()
                    sent += 1
                else:
                    break
            if sent:
                logger.info(f"Queued {sent} alert(s) yuborildi.")

    async def health_check(self) -> bool:
        try:
            s = await self._session()
            async with s.get(f"{self.cfg.api_url}/health") as r:
                return r.status == 200
        except Exception:
            return False

    async def close(self):
        if self._task:
            self._task.cancel()
        if self._sess and not self._sess.closed:
            await self._sess.close()
