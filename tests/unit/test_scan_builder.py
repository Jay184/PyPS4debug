import pytest
import re
from unittest.mock import Mock, AsyncMock

from ps4debug.memory.scanner.builder import ScanBuilder, ScanBuilderState
from ps4debug.memory.scanner.base import TypeSpec
from ps4debug.core import ScanValueType


def test_int8_sets_state():
    builder = ScanBuilder()
    builder.int8()
    state = builder._state
    assert state.value_type.name == "INT8"
    assert state.type_spec.little.__class__.__name__ == "FormatField"
    assert state.type_spec.big.__class__.__name__ == "FormatField"
    assert state.type_spec.little.fmtstr == "<b"
    assert state.type_spec.big.fmtstr == ">b"


def test_exact_sets_state():
    builder = ScanBuilder()
    builder.exact(42)
    state = builder._state
    assert state.compare_type.name == "EXACT"
    assert state.value == 42
    assert state.extra is None


def test_between_sets_state():
    builder = ScanBuilder()
    builder.between(10, 20)
    state = builder._state
    assert state.compare_type.name == "SMALLER_THAN"
    assert state.value == 10
    assert state.extra == 20


def test_bounds_valid():
    builder = ScanBuilder().bounds(0, 100)
    state = builder._state
    assert state.bounds == (0, 100)


def test_bounds_invalid_raises():
    builder = ScanBuilder()
    with pytest.raises(ValueError):
        builder.bounds(10, 5)
    with pytest.raises(ValueError):
        builder.bounds(-1, 5)


def test_byteorder_sets_state():
    builder = ScanBuilder().byteorder("big")
    assert builder._state.byteorder == "big"


def test_only_module_sets_pattern():
    builder = ScanBuilder().only_module(r"test.*")
    assert isinstance(builder._state.module_pattern, re.Pattern)
    assert builder._state.module_pattern.match("test123")


def test_reset_returns_new_state():
    builder = ScanBuilder().int32().exact(5)
    builder.reset()
    state = builder._state
    assert state.value_type is None
    assert state.compare_type is None
    assert state.value is None
    assert state.extra is None


@pytest.mark.asyncio
async def test_execute_raises_without_session():
    builder = ScanBuilder()
    import pytest
    with pytest.raises(RuntimeError):
        await builder.execute()


@pytest.mark.asyncio
async def test_execute_delegates_to_session():
    session = AsyncMock()
    builder = ScanBuilder(session)
    await builder.execute()
    session.execute.assert_awaited_once_with(builder._state)


def test_core_type_property():
    from ps4debug.memory.scanner.base import TypeSpec
    from construct import Int32sl, Int32sb

    ts = TypeSpec(Int32sl, Int32sb)
    state = ScanBuilderState(type_spec=ts, byteorder="little")
    assert state.core_type == Int32sl
    state.byteorder = "big"
    assert state.core_type == Int32sb


@pytest.mark.asyncio
async def test_scan_builder_setters_and_state():
    # Mock session with async execute methods
    mock_session = Mock()
    mock_session.execute = AsyncMock(return_value={"0x1000": 42})
    async def async_gen(state):
        yield 0x1000, 42
    mock_session.execute_iter = Mock(return_value=async_gen(Mock()))

    builder = ScanBuilder(mock_session)

    # Test all numeric setters
    builder.int8()
    assert builder._state.value_type == ScanValueType.INT8
    assert isinstance(builder._state.type_spec, TypeSpec)

    builder.uint8()
    builder.int16()
    builder.uint16()
    builder.int32()
    builder.uint32()
    builder.int64()
    builder.uint64()
    builder.float()
    builder.double()
    builder.string("utf-8")
    builder.byte_array()

    # Test all comparison setters
    builder.exact(10)
    builder.fuzzy(3.14)
    builder.bigger(5)
    builder.smaller(2)
    builder.between(1, 10)
    builder.increased(7)
    builder.increased_by(5, 10)
    builder.decreased(3)
    builder.decreased_by(3, 1)
    builder.changed(4)
    builder.unchanged(4)
    builder.unknown_initial_value()

    # Test byteorder
    builder.byteorder("big")
    assert builder._state.byteorder == "big"
    builder.byteorder("little")
    assert builder._state.byteorder == "little"

    # Test bounds with valid and invalid ranges
    builder.bounds(0, 10)
    with pytest.raises(ValueError):
        builder.bounds(10, 0)
    with pytest.raises(ValueError):
        builder.bounds(-1, 5)

    # Test module pattern
    builder.only_module("test_module")
    pattern = re.compile("regex")
    builder.only_module(pattern)
    assert builder._state.module_pattern.pattern == pattern.pattern

    # Test pause
    builder.pause(True)
    builder.pause(False)

    # Test reset
    builder.reset()
    assert isinstance(builder._state, ScanBuilderState)

    # Test execute methods
    result = await builder.execute()
    assert result == {"0x1000": 42}

    # Test execute_iter
    results = []
    async for addr, value in builder.execute_iter():
        results.append((addr, value))
    assert results == [(0x1000, 42)]


@pytest.mark.asyncio
async def test_unbounded_builder_execution():
    builder = ScanBuilder(None)
    with pytest.raises(RuntimeError):
        await builder.execute()

        async for _ in builder.execute_iter():
            pytest.fail("execute_iter should raise RuntimeError when unbounded")