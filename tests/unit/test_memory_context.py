import pytest
from typing import Annotated

from pydantic_construct import ConstructModel
from construct import Int32ul, Int64ul, Bytes
from ps4debug import MemoryContext, ResponseCode, VMProtection

from tests.fakes import FakeDebugger, FakePS4


class DummyModel(ConstructModel):
    a: Annotated[int, Int32ul]
    b: Annotated[int, Int32ul]


class DummyResult(ConstructModel):
    result: Annotated[int, Int64ul]


class LargeModel(ConstructModel):
    data: Annotated[bytes, Bytes(64)]  # exceeds 48



@pytest.mark.asyncio
async def test_memory_context_allocates_and_frees():
    ps4 = FakePS4()

    async with MemoryContext(ps4, pid=1, length=64) as mem:
        assert mem.address == 0x1000

    assert ps4.allocations == [(1, 64)]
    assert ps4.freed == [(1, 0x1000, 64)]
    assert mem.address is None


def test_view_requires_allocation():
    ps4 = FakePS4()
    mem = MemoryContext(ps4, pid=1)

    with pytest.raises(RuntimeError):
        mem.view()


@pytest.mark.asyncio
async def test_resolve_out_of_bounds():
    ps4 = FakePS4()

    async with MemoryContext(ps4, pid=1, length=10) as mem:
        with pytest.raises(ValueError):
            await mem.read(5, offset=8)  # 8 + 5 > 10


@pytest.mark.asyncio
async def test_write_out_of_bounds():
    dbg = FakeDebugger()

    async with MemoryContext(dbg, pid=1, length=8) as mem:
        with pytest.raises(ValueError):
            await mem.write(b"\x00" * 16)


@pytest.mark.asyncio
async def test_read_out_of_bounds():
    dbg = FakeDebugger()

    async with MemoryContext(dbg, pid=1, length=8) as mem:
        with pytest.raises(ValueError):
            await mem.read(16)


@pytest.mark.asyncio
async def test_write_and_read():
    dbg = FakeDebugger()

    async with MemoryContext(dbg, pid=1, length=32) as mem:
        data = b"\x01\x02\x03\x04"
        await mem.write(data)

        result = await mem.read(4)
        assert result == data


@pytest.mark.asyncio
async def test_write_and_read_model():
    dbg = FakeDebugger()

    model = DummyModel(a=1, b=2)

    async with MemoryContext(dbg, pid=1, length=32) as mem:
        await mem.write_model(model)

        result = await mem.read_model(DummyModel)
        assert result is not None
        assert result.a == 1
        assert result.b == 2


@pytest.mark.asyncio
async def test_write_model():
    class FakeModel:
        def model_dump_bytes(self):
            return b"\x05\x00"

    ps4 = FakePS4()

    async with MemoryContext(ps4, pid=1, length=16) as mem:
        await mem.write_model(FakeModel())

        assert ps4.memory[0x1000] == b"\x05\x00"


@pytest.mark.asyncio
async def test_access_before_enter_fails():
    dbg = FakeDebugger()
    mem = MemoryContext(dbg, pid=1, length=32)

    with pytest.raises(RuntimeError):
        await mem.read(4)


@pytest.mark.asyncio
async def test_end_address():
    dbg = FakeDebugger()

    async with MemoryContext(dbg, pid=1, length=32) as mem:
        assert mem.end_address == mem.address + 32

    assert mem.end_address is None


def test_resolve_negative_offset():
    ps4 = FakePS4()
    mem = MemoryContext(ps4, pid=1)

    mem.address = 0x1000

    with pytest.raises(ValueError):
        mem._resolve(-1)


@pytest.mark.asyncio
async def test_change_protection():
    ps4 = FakePS4()

    async with MemoryContext(ps4, pid=1, length=16) as mem:
        result = await mem.change_protection(VMProtection.READ)

        assert result == ResponseCode.SUCCESS


@pytest.mark.asyncio
async def test_call_delegates():
    ps4 = FakePS4()

    async with MemoryContext(ps4, pid=1, length=16) as mem:
        result = await mem.call()

        assert result == b"result"
