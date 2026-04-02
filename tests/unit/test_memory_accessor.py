import pytest

from ps4debug import MemoryView, MemoryAccessor
from tests.fakes import FakePS4


@pytest.mark.asyncio
async def test_accessor_get():
    ps4 = FakePS4()
    ps4.memory[0x1000] = b"\x2A\x00\x00\x00"

    view = MemoryView(ps4, pid=1, base=0x1000)

    accessor = view.uint32()

    value = await accessor

    assert value == 42


@pytest.mark.asyncio
async def test_accessor_set():
    ps4 = FakePS4()

    view = MemoryView(ps4, pid=1, base=0x1000)

    accessor = view.uint32()

    await accessor.set(42)

    assert ps4.memory[0x1000] == (42).to_bytes(4, "little")


@pytest.mark.asyncio
async def test_accessor_call_alias():
    ps4 = FakePS4()
    view = MemoryView(ps4, pid=1, base=0x1000)

    await view.uint32()(123)

    assert ps4.memory[0x1000] == (123).to_bytes(4, "little")


@pytest.mark.asyncio
async def test_accessor_rejects_wrong_size():
    ps4 = FakePS4()

    view = MemoryView(ps4, pid=1, base=0x1000)

    accessor = MemoryAccessor(
        view,
        offset=0,
        size=4,
        reader=lambda b: b,
        writer=lambda v: b"\x00",  # wrong size
    )

    with pytest.raises(ValueError):
        await accessor.set(b"bad")
