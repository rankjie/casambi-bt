#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import logging
import signal
from typing import Any

from CasambiBt import Casambi, Unit


def _setup_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(levelname)s:%(name)s:%(message)s",
    )


def _unit_to_dict(u: Unit) -> dict[str, Any]:
    state = u.state
    return {
        "deviceId": u.deviceId,
        "name": u.name,
        "online": u.online,
        "is_on": u.is_on,
        "raw_state_hex": None if state is None else state.raw_state.hex(),
        "state": None if state is None else state.as_dict(),
    }


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Connect to a Casambi network and print unit state updates (BLE-driven)."
    )
    parser.add_argument("--address", required=True, help="Network BLE address (MAC).")
    parser.add_argument("--password", required=True, help="Network password.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    args = parser.parse_args()

    _setup_logging(args.debug)
    log = logging.getLogger("local_watch_units")

    casa = Casambi()

    def on_unit(u: Unit) -> None:
        log.info("UNIT_STATE: %s", _unit_to_dict(u))

    casa.registerUnitChangedHandler(on_unit)

    await casa.connect(args.address, args.password, forceOffline=False)

    # Keep process alive to receive BLE notifications. Ctrl+C to stop.
    stop = asyncio.Event()

    def _sig(*_a: object) -> None:
        stop.set()

    try:
        asyncio.get_running_loop().add_signal_handler(signal.SIGINT, _sig)
        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, _sig)
    except NotImplementedError:
        # Some platforms (notably Windows) don't support signal handlers in asyncio.
        pass

    log.info("Connected. Waiting for unit state updates...")
    await stop.wait()


if __name__ == "__main__":
    asyncio.run(main())

