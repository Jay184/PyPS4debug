import asyncio
import contextlib
from typing import Annotated
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, Mock

import pytest
from construct import Int64ul
from pydantic_construct import ConstructModel

from ps4debug import PS4Debug, MemoryContext, PS4DebugException, VersionCommand, ResponseCode, DebuggingContext
from ps4debug.ps4debug import _Connection
from tests.fakes import FakeReader, FakeWriter, FakePool


def test_init_sets_defaults():
    client = PS4Debug("127.0.0.1")

    assert client.host == "127.0.0.1"
    assert client.port == 744
    assert client.timeout is not None


def test_encode_c_string_adds_null():
    result = PS4Debug._encode_c_string("test", "utf-8")
    assert result.endswith(b"\x00")


def test_encode_c_string_keeps_existing_null():
    result = PS4Debug._encode_c_string("test\0", "utf-8")
    assert result == b"test\x00"


def test_encode_c_string_rejects_none():
    with pytest.raises(ValueError):
        PS4Debug._encode_c_string(None, "utf-8")


def test_memory_factory():
    client = PS4Debug("127.0.0.1")
    mem = client.memory(123)

    assert isinstance(mem, MemoryContext)
    assert mem.pid == 123


@pytest.mark.asyncio
async def test_connection_uses_pool():
    reader = FakeReader(b"\x00\x00\x00\x00")
    writer = FakeWriter()

    pool = FakePool(reader, writer)
    client = PS4Debug("127.0.0.1", pool=pool)

    async with client._connection() as conn:
        assert isinstance(conn, _Connection)


@pytest.mark.asyncio
async def test_send_raises_on_error_status():
    # Simulate non-success status
    error_code = (1).to_bytes(4, "little")  # depends on enum mapping

    reader = FakeReader(error_code)
    writer = FakeWriter()

    client = PS4Debug("127.0.0.1", pool=FakePool(reader, writer))

    with pytest.raises(ValueError):
        async with client._connection() as conn:
            await conn.send(VersionCommand())




@pytest.mark.asyncio
async def test_read_model_array():
    class FakeModel:
        struct = type("S", (), {"sizeof": lambda: 2})

        @staticmethod
        def model_validate_bytes(b):
            return int.from_bytes(b, "little")

    count = (2).to_bytes(4, "little")
    data = b"\x01\x00\x02\x00"

    reader = FakeReader(count + data)

    result = await PS4Debug._read_model_array(reader, FakeModel)

    assert result == [1, 2]


@pytest.mark.asyncio
async def test_find_rpc_finds_signature(monkeypatch):
    signature = b"\x52\x53\x54\x42\xA3"

    async def fake_read(self, pid, addr, length, connection):
        return b"\x00" * 10 + signature + b"\x00" * 10

    client = PS4Debug("127.0.0.1")

    monkeypatch.setattr(type(client), "_read_memory", fake_read)

    conn = object()  # not used

    addr = await client._find_rpc(1, connection=conn, start=0, end=100, chunk_size=32)

    assert addr == 10


@pytest.mark.asyncio
async def test_get_rpc_caches_result(monkeypatch):
    client = PS4Debug("127.0.0.1")

    calls = {"count": 0}

    async def fake_find(self, pid, connection):
        calls["count"] += 1
        return 1234

    async def fake_install(self, pid, connection):
        return 1234

    monkeypatch.setattr(type(client), "_find_rpc", fake_find)
    monkeypatch.setattr(type(client), "_install_rpc", fake_install)

    # fake connection context
    @asynccontextmanager
    async def fake_conn(self):
        yield object()

    monkeypatch.setattr(type(client), "_connection", fake_conn)

    a = await client.get_rpc(1)
    b = await client.get_rpc(1)

    assert a == b == 1234
    assert calls["count"] == 1


@pytest.mark.asyncio
async def test_send_payload_failure(monkeypatch):
    async def fail(*args, **kwargs):
        raise OSError("boom")

    monkeypatch.setattr(asyncio, "open_connection", fail)

    client = PS4Debug("127.0.0.1")

    with pytest.raises(PS4DebugException):
        await client.send_payload(b"data")


@pytest.mark.asyncio
async def test_read_construct_numeric():
    class FakeConstruct:
        @staticmethod
        def sizeof():
            return 4

        @staticmethod
        def parse(b):
            return int.from_bytes(b, "little")

    reader = FakeReader((123).to_bytes(4, "little"))
    writer = FakeWriter()

    conn = _Connection(
        PS4Debug("127.0.0.1"),
        reader,
        writer,
    )

    result = await PS4Debug._read_construct_numeric(conn, FakeConstruct)

    assert result == 123


@pytest.mark.asyncio
async def test_read_status_checked_raises(fake_conn, fake_command):
    fake_conn.read_status = AsyncMock(return_value=ResponseCode.ERROR)

    with pytest.raises(PS4DebugException):
        await fake_conn.read_status_checked(fake_command)


@pytest.mark.asyncio
async def test_with_timeout_disabled(fake_conn):
    fake_conn._client.timeout = None

    async def coro():
        return 42

    result = await fake_conn._with_timeout(coro())
    assert result == 42


@pytest.mark.asyncio
async def test_with_timeout_expires(fake_conn):
    fake_conn._client.timeout = 0.01

    async def slow():
        await asyncio.sleep(0.1)

    with pytest.raises(PS4DebugException):
        await fake_conn._with_timeout(slow())


@pytest.mark.asyncio
async def test_send_raw_with_data_writes_payload(fake_conn):
    fake_conn.read_status = AsyncMock(return_value=ResponseCode.SUCCESS)

    cmd = VersionCommand()
    data = b"abc"

    result = await fake_conn.send_raw_with_data(cmd, data)

    assert result == ResponseCode.SUCCESS
    assert fake_conn.writer.buffer.endswith(data)


@pytest.mark.asyncio
async def test_send_with_data_calls_send_then_writes(fake_conn):
    fake_conn.send = AsyncMock(return_value=ResponseCode.SUCCESS)
    fake_conn.read_status_checked = AsyncMock(return_value=ResponseCode.SUCCESS)

    cmd = VersionCommand()
    data = b"abc"

    result = await fake_conn.send_with_data(cmd, data)

    assert result == ResponseCode.SUCCESS
    fake_conn.send.assert_called_once()


@pytest.mark.asyncio
async def test_discover_success(monkeypatch):
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    fut.set_result("192.168.0.10")

    class FakeTransport:
        def close(self): pass

    async def fake_endpoint(*args, **kwargs):
        return FakeTransport(), None

    monkeypatch.setattr(loop, "create_datagram_endpoint", fake_endpoint)

    async def fake_wait_for(f, timeout):
        return await fut

    monkeypatch.setattr(asyncio, "wait_for", fake_wait_for)

    client = await PS4Debug.discover()

    assert client.host == "192.168.0.10"


@pytest.mark.asyncio
async def test_discover_timeout(monkeypatch):
    loop = asyncio.get_running_loop()

    class FakeTransport:
        def close(self): pass

    async def fake_endpoint(*args, **kwargs):
        return FakeTransport(), None

    monkeypatch.setattr(loop, "create_datagram_endpoint", fake_endpoint)

    async def fake_wait_for(*args, **kwargs):
        raise TimeoutError

    monkeypatch.setattr(asyncio, "wait_for", fake_wait_for)

    with pytest.raises(PS4DebugException):
        await PS4Debug.discover()


@pytest.mark.asyncio
async def test_debugger_rejects_when_locked():
    client = PS4Debug("127.0.0.1")

    await client._debug_lock.acquire()

    with pytest.raises(PS4DebugException):
        async with client.debugger(1):
            pass


@pytest.mark.asyncio
async def test_debugger_already_debug(monkeypatch):
    client = PS4Debug("127.0.0.1")

    fake_conn = AsyncMock()
    fake_conn.send = AsyncMock(return_value=ResponseCode.ALREADY_DEBUG)

    @asynccontextmanager
    async def fake_connection(self):
        yield fake_conn

    monkeypatch.setattr(type(client), "_connection", fake_connection)

    server_mock = AsyncMock()
    server_mock.close = Mock()
    monkeypatch.setattr(asyncio, "start_server", AsyncMock(return_value=server_mock))

    with pytest.raises(PS4DebugException):
        async with client.debugger(1):
            pass


@pytest.mark.asyncio
async def test_debugger_resume_calls_resume(monkeypatch):
    client = PS4Debug("127.0.0.1")

    fake_conn = AsyncMock()
    fake_conn.send = AsyncMock(return_value=ResponseCode.SUCCESS)

    @asynccontextmanager
    async def fake_connection(self):
        yield fake_conn

    monkeypatch.setattr(type(client), "_connection", fake_connection)

    server_mock = AsyncMock()
    server_mock.close = Mock()
    monkeypatch.setattr(asyncio, "start_server", AsyncMock(return_value=server_mock))

    async with client.debugger(1, resume=True) as ctx:
        # resume_process should be reachable
        assert isinstance(ctx, DebuggingContext)


@pytest.mark.asyncio
async def test_send_payload_file_not_found():
    client = PS4Debug("127.0.0.1")

    with pytest.raises(FileNotFoundError):
        await client.send_payload_file("does_not_exist.bin")


@pytest.mark.asyncio
async def test_send_payload_file_calls_send(monkeypatch, tmp_path):
    file = tmp_path / "p.bin"
    file.write_bytes(b"abc")

    client = PS4Debug("127.0.0.1")

    called = {}

    async def fake_send(self, data, port):
        called["data"] = data

    monkeypatch.setattr(type(client), "send_payload", fake_send)

    await client.send_payload_file(file)

    assert called["data"] == b"abc"


@pytest.mark.asyncio
async def test_find_rpc_returns_none(monkeypatch):
    async def fake_read(*args, **kwargs):
        return b"\x00" * 64

    client = PS4Debug("127.0.0.1")
    monkeypatch.setattr(type(client), "_read_memory", fake_read)

    result = await client._find_rpc(1, connection=object(), start=0, end=64)

    assert result is None


@pytest.mark.asyncio
async def test_call_rejects_large_params():
    client = PS4Debug("127.0.0.1")

    class Big:
        struct = type("S", (), {"sizeof": lambda: 9999})

    with pytest.raises(ValueError):
        await client.call(1, 0x1000, params=Big())


@pytest.mark.asyncio
async def test_call_return_model_too_large(monkeypatch):
    client = PS4Debug("127.0.0.1")

    def fake_conn(self):
        @contextlib.asynccontextmanager
        async def _impl():
            class Ctx:
                async def __aenter__(self): return self
                async def __aexit__(self, *a): pass
                async def send(self, cmd): pass
                async def read_exactly(self, n): return b"\x00" * (4 + 8)
            yield Ctx()
        return _impl()

    monkeypatch.setattr(type(client), "_connection", fake_conn)
    monkeypatch.setattr(type(client), "get_rpc", AsyncMock(return_value=1))

    class SmallResult(ConstructModel):
        a: Annotated[int, Int64ul]
        b: Annotated[int, Int64ul]

    with pytest.raises(ValueError):
        await client.call(1, 0x1000, return_model=SmallResult)


def test_get_rpc_lock_reuses_same_lock():
    client = PS4Debug("127.0.0.1")

    a = client._get_rpc_lock(1)
    b = client._get_rpc_lock(1)

    assert a is b


def test_encode_c_string_encoding_error():
    with pytest.raises(UnicodeEncodeError):
        PS4Debug._encode_c_string("ä", "ascii")
