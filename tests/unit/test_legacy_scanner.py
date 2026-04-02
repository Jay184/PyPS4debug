import pytest
from unittest.mock import AsyncMock, Mock
from construct import Int64ul
from construct.core import GreedyString, Int64ub

from ps4debug.memory.scanner.base import TypeSpec
from ps4debug.memory.scanner.legacy import LegacyScanner
from ps4debug.memory.scanner.builder import ScanBuilderState
from ps4debug.core import ScanValueType, ScanCompareType
from tests.fakes import FakeConnCtx


@pytest.mark.asyncio
async def test_legacy_scan_end_flag():
    # One valid address, then the end flag
    fake_conn = AsyncMock()
    fake_conn.read_exactly.side_effect = [
        Int64ul.build(0x1000),
        Int64ul.build(0xFFFFFFFFFFFFFFFF),
    ]

    ps4_mock = Mock()
    ps4_mock._connection.return_value = FakeConnCtx(fake_conn)

    scanner = LegacyScanner(ps4=ps4_mock, pid=1234)
    state = ScanBuilderState(
        value_type=ScanValueType.UINT64,
        compare_type=ScanCompareType.EXACT,
        value=42,
        extra=None,
        bounds=None,
        pause_process=False,
        type_spec=TypeSpec(Int64ul, Int64ul),
    )

    results = [addr async for addr, val in scanner._scan(state)]
    assert results == [0x1000]


@pytest.mark.asyncio
async def test_legacy_scan_bounds_filtering():
    # Addresses below bounds, inside bounds, then end flag
    fake_conn = AsyncMock()
    fake_conn.read_exactly.side_effect = [
        Int64ul.build(0x1000),  # below bounds
        Int64ul.build(0x2000),  # inside bounds
        Int64ul.build(0xFFFFFFFFFFFFFFFF),  # end flag
    ]

    ps4_mock = Mock()
    ps4_mock._connection.return_value = FakeConnCtx(fake_conn)

    scanner = LegacyScanner(ps4=ps4_mock, pid=1234)

    state = ScanBuilderState(
        value_type=ScanValueType.UINT64,
        compare_type=ScanCompareType.EXACT,
        value=42,
        extra=None,
        bounds=(0x1800, 0x3000),
        pause_process=False,
        type_spec=TypeSpec(Int64ul, Int64ub),
    )

    results = [addr async for addr, val in scanner._scan(state)]
    assert results == [0x2000]


def test_build_scan_buffer_variable_length(monkeypatch):
    scanner = LegacyScanner(ps4=None, pid=0)
    state = ScanBuilderState(
        value_type=ScanValueType.STRING,
        compare_type=ScanCompareType.EXACT,
        value="abc",
        extra="extra",
        type_spec=TypeSpec(GreedyString("utf-8"), GreedyString("utf-8")),
    )

    # Track arguments passed to _build_value
    called_args = {}

    def fake_build_value(value, query, *, pad=False):
        called_args.update({"value": value, "pad": pad})
        return b"FAKE"

    monkeypatch.setattr(LegacyScanner, "_build_value", fake_build_value)

    buf = scanner._build_scan_buffer(state)
    assert buf == b"FAKEFAKE"
    # Ensure padding was correctly applied to value, not extra
    assert called_args["value"] in ("abc", "extra")


def test_build_scan_buffer_numeric(monkeypatch):
    scanner = LegacyScanner(ps4=None, pid=0)
    state = ScanBuilderState(
        value_type=ScanValueType.UINT64,
        compare_type=ScanCompareType.EXACT,
        value=123,
        extra=456,
        type_spec=TypeSpec(Int64ul, Int64ub),
    )

    called_args = {}

    def fake_build_value(value, query, *, pad=False):
        called_args.update({"value": value, "pad": pad})
        return b"NUM"

    monkeypatch.setattr(LegacyScanner, "_build_value", fake_build_value)

    buf = scanner._build_scan_buffer(state)
    assert buf == b"NUMNUM"
    assert called_args["value"] in (123, 456)
