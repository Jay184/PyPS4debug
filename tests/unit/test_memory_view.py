import pytest

from ps4debug import MemoryView
from tests.fakes import FakePS4

from hypothesis import given
import hypothesis.strategies as st


def test_view_offset():
    ps4 = FakePS4()

    view = MemoryView(ps4, pid=1, base=0x1000)
    new_view = view.offset(0x10)

    assert new_view.base == 0x1010
    assert new_view is not view


@pytest.mark.asyncio
async def test_bytes_accessor():
    ps4 = FakePS4()
    ps4.memory[0x1000] = b"abcd"

    view = MemoryView(ps4, pid=1, base=0x1000)

    result = await view.bytes(4)

    assert result == b"abcd"

@pytest.mark.asyncio
async def test_boolean_accessor():
    ps4 = FakePS4()
    ps4.memory[0x1000] = b"\x01"

    view = MemoryView(ps4, pid=1, base=0x1000)

    result = await view.boolean()

    assert result is True


@pytest.mark.asyncio
async def test_model_accessor():
    class FakeModel:
        struct = type("S", (), {"sizeof": lambda: 2})

        @staticmethod
        def model_validate_bytes(b):
            return int.from_bytes(b, "little")

        def model_dump_bytes(self):
            return b"\x02\x00"

    ps4 = FakePS4()
    ps4.memory[0x1000] = b"\x01\x00"

    view = MemoryView(ps4, pid=1, base=0x1000)

    value = await view.model(FakeModel)

    assert value == 1


@pytest.mark.asyncio
async def test_string_accessor():
    ps4 = FakePS4()
    ps4.memory[0x1000] = b"test\x00"

    view = MemoryView(ps4, pid=1, base=0x1000)

    result = await view.string(5)

    assert result == "test"


@pytest.mark.asyncio
async def test_read_variable_text():
    ps4 = FakePS4()

    ps4.memory[0x1000] = b"hello "
    ps4.memory[0x1006] = b"world\x00extra"

    view = MemoryView(ps4, pid=1, base=0x1000)

    result = await view.read_variable_text(chunk_size=6)

    assert result == "hello world"


@given(st.integers(min_value=0, max_value=2**32 - 1))
@pytest.mark.asyncio
async def test_uint32_roundtrip(value):
    ps4 = FakePS4()
    view = MemoryView(ps4, pid=1, base=0x1000)

    accessor = view.uint32()

    await accessor.set(value)
    result = await accessor

    assert result == value