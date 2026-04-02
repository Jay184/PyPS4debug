import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, Mock

from pydantic_construct import ConstructModel
from ps4debug.core import BaseCommand, ResponseCode
from ps4debug.debugging.context import DebuggingContext, Breakpoint


@pytest.fixture
def fake_ps4debug():
    # Provide a mock PS4Debug with a connection context
    conn = AsyncMock()
    conn.__aenter__.return_value = conn
    conn.__aexit__.return_value = None
    conn.send = AsyncMock(return_value=ResponseCode.SUCCESS)
    conn.send_with_data = AsyncMock(return_value=ResponseCode.SUCCESS)
    conn.read_exactly = AsyncMock(return_value=b"\x00\x00\x00\x00")

    ps4debug = MagicMock()
    ps4debug._connection.return_value = conn
    return ps4debug


@pytest.mark.asyncio
async def test_constructor_and_callbacks(fake_ps4debug):
    ctx = DebuggingContext(fake_ps4debug, pid=1234)
    assert ctx.pid == 1234
    assert isinstance(ctx.breakpoints[0], Breakpoint)
    assert ctx.callback is None

    # register global callback
    async def dummy(event): ...
    ctx.register_callback(dummy)
    assert ctx.callback == dummy
    ctx.register_callback(None)
    assert ctx.callback is None


@pytest.mark.asyncio
async def test_basic_process_commands(fake_ps4debug):
    ctx = DebuggingContext(fake_ps4debug, pid=1)
    assert await ctx.resume_process() == ResponseCode.SUCCESS
    assert await ctx.stop_process() == ResponseCode.SUCCESS
    assert await ctx.kill_process() == ResponseCode.SUCCESS


@pytest.mark.asyncio
async def test_thread_commands(fake_ps4debug):
    ctx = DebuggingContext(fake_ps4debug, pid=1)
    thread_id = 42
    assert await ctx.resume_thread(thread_id) == ResponseCode.SUCCESS
    assert await ctx.stop_thread(thread_id) == ResponseCode.SUCCESS


@pytest.mark.asyncio
async def test_get_threads_returns_empty_on_failure(fake_ps4debug):
    # Make send return an error
    fake_ps4debug._connection.return_value.__aenter__.return_value.send = AsyncMock(return_value=ResponseCode.ERROR)
    ctx = DebuggingContext(fake_ps4debug, pid=1)
    threads = await ctx.get_threads()
    assert threads == []


@pytest.mark.asyncio
async def test_breakpoint_management(fake_ps4debug):
    ctx = DebuggingContext(fake_ps4debug, pid=1)

    # test finding free breakpoint
    free_idx = ctx.find_free_breakpoint()
    assert free_idx is not None
    bp = await ctx.add_breakpoint(0x1000)
    assert isinstance(bp, int)
    # test that slot is now occupied
    assert ctx.breakpoints[bp].enabled
    # test setting breakpoint explicitly
    status = await ctx.set_breakpoint(bp, True, 0x2000, None)
    assert status == ResponseCode.SUCCESS
    assert ctx.breakpoints[bp].address == 0x2000


@pytest.mark.asyncio
async def test_validate_index_raises(fake_ps4debug):
    ctx = DebuggingContext(fake_ps4debug, pid=1)
    with pytest.raises(ValueError):
        ctx._validate_index(-1, 4, "test index")
    with pytest.raises(ValueError):
        ctx._validate_index(4, 4, "test index")


@pytest.mark.asyncio
async def test_read_write_struct_calls(fake_ps4debug):
    class DummyModel(ConstructModel):
        struct = MagicMock()
        struct.sizeof = MagicMock(return_value=4)
        @classmethod
        def model_validate_bytes(cls, b):
            return "ok"

    ctx = DebuggingContext(fake_ps4debug, pid=1)
    val = await ctx._read_struct(BaseCommand(code=0), DummyModel)
    assert val == "ok"

    data = b"abcd"
    status = await ctx._write_struct(BaseCommand(code=0), data)
    assert status == ResponseCode.SUCCESS


@pytest.mark.asyncio
async def test_debug_connected_handles_disconnect(fake_ps4debug):
    ctx = DebuggingContext(fake_ps4debug, pid=1)

    reader = AsyncMock()
    reader.readexactly.side_effect = asyncio.IncompleteReadError(b"", 4)

    writer = AsyncMock()
    writer.close = Mock()

    await ctx.debug_connected(reader, writer)

    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_threads_failure_returns_empty(fake_ps4debug):
    fake_ps4debug._connection.send.return_value = ResponseCode.ERROR

    ctx = DebuggingContext(fake_ps4debug, pid=1)

    threads = await ctx.get_threads()

    assert threads == []


def test_validate_index_invalid_low():
    with pytest.raises(ValueError):
        DebuggingContext._validate_index(-1, 4, "test")


def test_validate_index_invalid_high():
    with pytest.raises(ValueError):
        DebuggingContext._validate_index(4, 4, "test")


def test_get_breakpoint_invalid_index(fake_ps4debug):
    ctx = DebuggingContext(fake_ps4debug, pid=1)

    with pytest.raises(ValueError):
        ctx.get_breakpoint(999)


@pytest.mark.asyncio
async def test_add_breakpoint_no_free_slots(fake_ps4debug):
    ctx = DebuggingContext(fake_ps4debug, pid=1)

    for bp in ctx.breakpoints.values():
        bp.enabled = True

    with pytest.raises(RuntimeError):
        await ctx.add_breakpoint(0x1000)


@pytest.mark.asyncio
async def test_add_breakpoint_set_failure(fake_ps4debug, monkeypatch):
    ctx = DebuggingContext(fake_ps4debug, pid=1)

    async def fail_set(*args, **kwargs):
        return ResponseCode.ERROR

    monkeypatch.setattr(ctx, "set_breakpoint", fail_set)

    with pytest.raises(RuntimeError):
        await ctx.add_breakpoint(0x1000)


@pytest.mark.asyncio
async def test_set_breakpoint_replaces_old_mapping(fake_ps4debug):
    ctx = DebuggingContext(fake_ps4debug, pid=1)

    # simulate existing breakpoint
    ctx.breakpoints[0] = Breakpoint(True, 0x1000, None)
    ctx._bp_by_address[0x1000] = 0

    fake_ps4debug._connection.send.return_value = ResponseCode.SUCCESS

    await ctx.set_breakpoint(0, True, 0x2000, None)

    assert 0x1000 not in ctx._bp_by_address
    assert ctx._bp_by_address[0x2000] == 0


@pytest.mark.asyncio
async def test_set_breakpoint_disabled_removes_mapping(fake_ps4debug):
    ctx = DebuggingContext(fake_ps4debug, pid=1)

    ctx.breakpoints[0] = Breakpoint(True, 0x1000, None)
    ctx._bp_by_address[0x1000] = 0

    fake_ps4debug._connection.send.return_value = ResponseCode.SUCCESS

    await ctx.set_breakpoint(0, False, 0x1000, None)

    assert 0x1000 not in ctx._bp_by_address


@pytest.mark.asyncio
async def test_read_struct(fake_ps4debug):
    class DummyModel(ConstructModel):
        struct = MagicMock()
        struct.sizeof = MagicMock(return_value=4)

        @classmethod
        def model_validate_bytes(cls, b):
            return "ok"

    ctx = DebuggingContext(fake_ps4debug, pid=1)

    fake_ps4debug._connection.read_exactly.return_value = b"\x00" * DummyModel.struct.sizeof()

    result = await ctx._read_struct(BaseCommand(code=0), DummyModel)

    assert result is not None


@pytest.mark.asyncio
async def test_write_struct(fake_ps4debug):
    ctx = DebuggingContext(fake_ps4debug, pid=1)

    fake_ps4debug._connection.send_with_data.return_value = ResponseCode.SUCCESS

    result = await ctx._write_struct(BaseCommand(code=0), b"abc")

    assert result == ResponseCode.SUCCESS
