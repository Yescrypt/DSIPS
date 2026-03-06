#!/usr/bin/env python3
"""
DSIPS Agent v2.0
"""

import asyncio
import logging
import os
import signal
import sys

from agent.config.settings import load_config
from agent.core.blocker    import Blocker
from agent.core.detector   import Detector
from agent.core.monitor    import Monitor
from agent.core.poller     import CommandPoller
from agent.core.reporter   import Reporter

os.makedirs("/var/log/dsips", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/dsips/agent.log", mode="a"),
    ],
)
logger = logging.getLogger("dsips.agent")


class Agent:
    def __init__(self):
        self.cfg      = load_config()
        self.blocker  = Blocker(self.cfg)
        self.reporter = Reporter(self.cfg)
        self.detector = Detector(self.cfg, self.blocker, self.reporter)
        self.monitor  = Monitor(self.cfg, self.detector)
        self.poller   = CommandPoller(self.cfg, self.blocker)

    async def run(self):
        logger.info("━" * 52)
        logger.info("  DSIPS Agent v2.0.0")
        logger.info(f"  Server  : {self.cfg.server_name}")
        logger.info(f"  API     : {self.cfg.api_url}")
        logger.info(f"  Dry run : {self.cfg.dry_run}")
        logger.info(f"  Logs    : {len(self.cfg.log_files)} fayl")
        logger.info("━" * 52)

        # API key olish
        if not self.cfg.api_key:
            logger.info("API key olinmoqda...")
            await self.reporter.register()

        # API connection check
        if not await self.reporter.health_check():
            logger.warning("Cloud API ulanmadi — alertlar navbatda saqlanadi.")

        # TCP/UDP flood himoya qoidalari
        if not self.cfg.dry_run:
            await self.blocker.setup_flood_protection()

        # Command poller (Telegram tugmalar)
        await self.poller.start()

        # Log monitoring
        await self.monitor.start()

    async def stop(self):
        logger.info("To'xtatilmoqda...")
        await self.monitor.stop()
        await self.poller.stop()
        await self.reporter.close()
        logger.info("To'xtatildi.")


async def main():
    agent = Agent()
    loop  = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(agent.stop()))
    await agent.run()


if __name__ == "__main__":
    asyncio.run(main())
