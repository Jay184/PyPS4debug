import pytest
import asyncio

from ps4debug import PS4Debug
from tests.fakes import FakeWriter, FakeReader, FakePool


@pytest.mark.asyncio
async def test_send_payload_writes_data(monkeypatch):
    reader = FakeReader(b"")
    writer = FakeWriter()

    async def fake_open_connection(host, port):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    client = PS4Debug("127.0.0.1")
    await client.send_payload(b"abc")

    assert writer.written == b"abc"
    assert writer.closed


@pytest.mark.asyncio
async def test_send_payload_file(tmp_path, monkeypatch):
    file = tmp_path / "payload.bin"
    file.write_bytes(b"data")

    called = {}

    async def fake_send(self, data, port=9020):
        called["data"] = data

    monkeypatch.setattr(PS4Debug, "send_payload", fake_send)

    client = PS4Debug("127.0.0.1")
    await client.send_payload_file(file)

    assert called["data"] == b"data"
