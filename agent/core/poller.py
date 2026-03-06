"""
DSIPS Command Poller
API dan kelgan block/unblock buyruqlarini bajaradi.
"""

import asyncio
import logging
from typing import Optional
import aiohttp
from agent.config.settings import Config
from agent.core.blocker import Blocker

logger = logging.getLogger("dsips.poller")
POLL_INTERVAL = 10


class CommandPoller:
    def __init__(self, cfg: Config, blocker: Blocker):
        self.cfg     = cfg
        self.blocker = blocker
        self._sess: Optional[aiohttp.ClientSession] = None
        self._task: Optional[asyncio.Task] = None

    async def _session(self) -> aiohttp.ClientSession:
        if self._sess is None or self._sess.closed:
            self._sess = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
        return self._sess

    async def _get_commands(self) -> list:
        if not self.cfg.api_key:
            return []
        try:
            s = await self._session()
            async with s.get(
                f"{self.cfg.api_url}/commands",
                params={
                    "server_name":      self.cfg.server_name,
                    "telegram_user_id": self.cfg.telegram_user_id,
                },
                headers={"X-DSIPS-KEY": self.cfg.api_key},
            ) as r:
                if r.status == 200:
                    return (await r.json()).get("commands", [])
        except Exception as e:
            logger.debug(f"Poll: {e}")
        return []

    async def _confirm(self, cmd_id: str, success: bool):
        try:
            s = await self._session()
            await s.post(
                f"{self.cfg.api_url}/commands/{cmd_id}/done",
                json={"success": success},
                headers={"X-DSIPS-KEY": self.cfg.api_key},
            )
        except Exception:
            pass

    async def _execute(self, cmd: dict):
        action   = cmd.get("action")
        ip       = cmd.get("ip")
        cmd_id   = cmd.get("id","?")
        duration = cmd.get("duration", self.cfg.block_high)

        if not ip:
            return

        logger.info(f"Executing: {action} {ip}")

        if action == "block":
            ok = await self.blocker.block(ip, duration, "Telegram/API")
        elif action == "unblock":
            ok = await self.blocker.unblock(ip)
        else:
            return

        await self._confirm(cmd_id, ok)

    async def _loop(self):
        logger.info("Command poller started.")
        while True:
            try:
                for cmd in await self._get_commands():
                    await self._execute(cmd)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Poller: {e}")
            await asyncio.sleep(POLL_INTERVAL)

    async def start(self):
        self._task = asyncio.create_task(self._loop())

    async def stop(self):
        if self._task:
            self._task.cancel()
            try: await self._task
            except asyncio.CancelledError: pass
        if self._sess and not self._sess.closed:
            await self._sess.close()
