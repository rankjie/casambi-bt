from __future__ import annotations

import unittest

from CasambiBt._casambi import Casambi
from CasambiBt._client import ProtocolMode
from CasambiBt._unit import Scene


class _StubClassicClient:
    protocolMode = ProtocolMode.CLASSIC

    def __init__(self) -> None:
        self.last_build: tuple[int, bytes, int | None] | None = None
        self.sent: list[bytes] = []

    def buildClassicCommand(
        self, ordinal: int, payload: bytes, *, target_id: int | None = None, **_: object
    ) -> bytes:
        self.last_build = (int(ordinal), bytes(payload), None if target_id is None else int(target_id))
        return b"stubcmd"

    async def send(self, cmd: bytes) -> None:
        self.sent.append(bytes(cmd))


class TestClassicScenes(unittest.IsolatedAsyncioTestCase):
    async def test_switch_to_scene_classic_uses_scene_level_command(self) -> None:
        casa = Casambi()
        stub = _StubClassicClient()
        casa._casaClient = stub  # type: ignore[assignment]

        scene = Scene(sceneId=7, name="Test")
        await casa.switchToScene(scene, level=0xFF)

        self.assertEqual(stub.last_build, (1, bytes([0xFF, 0x00, 0x00, 0x01]), 7))
        self.assertEqual(stub.sent, [b"stubcmd"])

