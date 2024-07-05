from contextlib import asynccontextmanager
import logging
import typing
import warnings
import os
import sys
import colorlog
import asyncio
import aiosqlite
from datetime import datetime, timedelta
import random
import time


_LOGGER = logging.getLogger("core")


def init_logging(
    flavor: typing.Union[None, str, int],
    allow_color: bool,
    force_color: bool, *,
    other_logs: bool = False
) -> None:
    if flavor is None:
        return

    logging.logThreads = other_logs
    logging.logProcesses = other_logs
    logging.logMultiprocessing = other_logs

    warnings.simplefilter("always", DeprecationWarning)
    logging.captureWarnings(True)

    if len(logging.root.handlers) != 0:
        return

    try:
        if supports_color(allow_color, force_color):
            logging.basicConfig(level=flavor, stream=sys.stdout)
            handler = logging.root.handlers[0]
            handler.setFormatter(
                colorlog.formatter.ColoredFormatter(
                    fmt=(
                        "%(log_color)s%(bold)s%(levelname)-1.1s%(thin)s "
                        "%(asctime)23.23s "
                        "%(bold)s%(name)s: "
                        "%(thin)s%(message)s%(reset)s"
                    ),
                    force_color=True,
                )
            )
        else:
            logging.basicConfig(
                level=flavor,
                stream=sys.stdout,
                format=(
                    "%(levelname)-1.1s "
                    "%(asctime)23.23s "
                    "%(name)s: "
                    "%(message)s"
                ),
            )

    except Exception as ex:
        raise RuntimeError("A problem occurred while trying to setup default logging configuration") from ex


_UNCONDITIONAL_ANSI_FLAGS: typing.Final[typing.FrozenSet[str]] = frozenset(("PYCHARM_HOSTED", "WT_SESSION"))
"""Set of env variables which always indicate that ANSI flags should be included."""


def supports_color(allow_color: bool, force_color: bool) -> bool:
    if not allow_color:
        return False

    is_a_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    clicolor = os.environ.get("CLICOLOR")
    if os.environ.get("CLICOLOR_FORCE", "0") != "0" or force_color:
        return True
    if clicolor is not None and clicolor != "0" and is_a_tty:
        return True
    if clicolor == "0":
        return False
    if os.environ.get("COLORTERM", "").casefold() in ("truecolor", "24bit"):
        return True

    plat = sys.platform
    if plat == "Pocket PC":
        return False

    if plat == "win32":
        color_support = os.environ.get("TERM_PROGRAM") in ("mintty", "Terminus")
        color_support |= "ANSICON" in os.environ
        color_support &= is_a_tty
    else:
        color_support = is_a_tty

    color_support |= bool(os.environ.keys() & _UNCONDITIONAL_ANSI_FLAGS)
    return color_support


def warn_if_not_optimized(suppress: bool) -> None:
    if __debug__ and not suppress:
        _LOGGER.warning(
            "You are running on optimization level 0 (no optimizations), which may slow down your application. "
            "For production, consider using at least level 1 optimization by passing `-O` to the python "
            "interpreter call"
        )


def new_session_prefix():
    _random = random.Random(time.time())
    letters = 'bcdfghjklmnpqrstvwxyz'
    new = []
    for i in range(4):
        new.append(_random.choice(letters))
    return ''.join(new)


class AsyncDatabaseConnectionManager:
    _instance = None
    _lock = asyncio.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AsyncDatabaseConnectionManager, cls).__new__(cls)
            cls._instance.connections = {}
        return cls._instance

    async def get_connection(self, db_name):
        if db_name not in self.connections:
            self.connections[db_name] = {
                "connection": await aiosqlite.connect(db_name),
                "last_used": datetime.now()
            }
        self.connections[db_name]["last_used"] = datetime.now()
        return self.connections[db_name]["connection"]

    @asynccontextmanager
    async def connection_context(self, db_name):
        connection = await self.get_connection(db_name)
        try:
            yield connection
        finally:
            self.connections[db_name]["last_used"] = datetime.now()

    async def close_all_connections(self):
        for conn_info in self.connections.values():
            await conn_info["connection"].close()
        self.connections.clear()

    async def cleanup_connections(self, timeout=600):
        while True:
            await asyncio.sleep(timeout)
            now = datetime.now()
            to_close = []
            for db_name, conn_info in self.connections.items():
                if now - conn_info["last_used"] > timedelta(seconds=timeout):
                    to_close.append(db_name)
            for db_name in to_close:
                await self.connections[db_name]["connection"].close()
                del self.connections[db_name]
