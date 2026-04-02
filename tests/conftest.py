from unittest.mock import AsyncMock, Mock

import pytest

from ps4debug import BaseCommand
from ps4debug.ps4debug import PS4Debug, _Connection
from tests.fakes.socket import FakeReader, FakeWriter, FakePool


@pytest.fixture
def fake_connection():
    reader = FakeReader()
    writer = FakeWriter()
    return reader, writer


@pytest.fixture
def fake_conn():
    """Provides a fake _Connection object with mocked reader and writer."""
    # Mock reader with readexactly
    reader = AsyncMock()
    reader.readexactly = AsyncMock(return_value=b"\x00\x00\x00\x00")

    # Mock writer with buffer tracking
    writer = AsyncMock()
    writer.write = Mock()
    writer.buffer = bytearray()

    def write(data):
        writer.buffer.extend(data)

    writer.write.side_effect = write
    writer.drain = AsyncMock()

    conn = _Connection(client=AsyncMock(), reader=reader, writer=writer)
    return conn


@pytest.fixture
def fake_command():
    class FakeCommand(BaseCommand):
        def model_dump_bytes(self, *_, **__):
            return b"\x00" * 4  # dummy payload

    return FakeCommand(code=0)


@pytest.fixture
def client(fake_connection):
    reader, writer = fake_connection
    return PS4Debug("127.0.0.1", pool=FakePool(reader, writer))
