import asyncio
from unittest.mock import AsyncMock

import pytest
from construct import Int32ul, Int32ub

from ps4debug import ScanCompareType
from ps4debug.memory.scanner.base import TypeSpec
from ps4debug.memory.scanner.local import LocalScanner
from ps4debug.memory.scanner.builder import ScanBuilderState
from ps4debug.memory.scanner.session import ScanValueType
from ps4debug.core import ProcessMap, VMProtection


@pytest.mark.asyncio
async def test_localscanner_initialization():
    scanner = LocalScanner(ps4=AsyncMock(), pid=42, chunk_size=1024, max_workers=2)
    assert scanner.pid == 42
    assert scanner._chunk_size == 1024
    assert scanner._max_workers == 2
    assert scanner.initial == {}
    assert scanner.previous == {}


def test_resolve_regions_basic():
    maps = [
        ProcessMap(start=0, end=1000, prot=VMProtection.READ, name="module1", offset=0),
        ProcessMap(start=2000, end=3000, prot=VMProtection.NONE, name="module2", offset=0),  # not readable
    ]
    state = ScanBuilderState(bounds=None, module_pattern=None, value=None, extra=None,
                             value_type=ScanValueType.UINT32, compare_type=ScanCompareType.EXACT,
                             type_spec=TypeSpec(Int32ul, Int32ub))
    regions = LocalScanner._resolve_regions(state, maps)
    assert regions == [(0, 1000)]


def test_resolve_regions_bounds_and_module_pattern():
    import re
    maps = [
        ProcessMap(start=0, end=1000, prot=VMProtection.READ, name="module1", offset=0),
        ProcessMap(start=1000, end=2000, prot=VMProtection.READ, name="module2", offset=0),
    ]
    state = ScanBuilderState(bounds=(500, 1500), module_pattern=re.compile("module1"),
                             value=None, extra=None,
                             value_type=ScanValueType.UINT32, compare_type=ScanCompareType.EXACT,
                             type_spec=TypeSpec(Int32ul, Int32ub))
    regions = LocalScanner._resolve_regions(state, maps)
    assert regions == [(500, 1000)]  # intersection applied


def test_iter_chunks_basic():
    regions = [(0, 10)]
    chunks = list(LocalScanner._iter_chunks(regions, chunk_size=4, value_size=2))
    expected = [
        (0, 0, 4),
        (4, 3, 5),
        (8, 7, 3),
    ]
    assert chunks == expected


def test_compare_value_matches_and_not():
    scanner = LocalScanner(ps4=None, pid=0)
    state = ScanBuilderState(
        value=10,
        value_type=ScanValueType.UINT32,
        compare_type=ScanCompareType.EXACT,
        type_spec=TypeSpec(Int32ul, Int32ub),
        extra=None,
    )

    # initial and previous empty
    assert scanner._compare_value(0, 10, state) is True
    assert scanner._compare_value(0, 5, state) is False


@pytest.mark.asyncio
async def test_scan_regions_mocked():
    calls = []

    async def fake_worker(addr, size):
        calls.append((addr, size))
        return bytes([1] * size)

    regions = [(0, 8)]
    results = []
    async for base, read, buf in LocalScanner.scan_regions(
        regions, fake_worker, chunk_size=4, alignment=2, concurrency=2
    ):
        results.append((base, read, buf))

    total_len = sum(len(b) for _, _, b in results)
    # overlap causes total_len > region size
    assert total_len >= 8
    assert all(isinstance(b, bytes) for _, _, b in results)


@pytest.mark.asyncio
async def test_scan_skeleton_with_mocked_memory():
    memory = {
        0: b"\x01\x00\x00\x00\x02\x00\x00\x00"
    }

    async def fake_read(pid, addr, size):
        return memory[addr]

    ps4_mock = AsyncMock()
    ps4_mock.read_memory.side_effect = fake_read
    ps4_mock.get_process_maps.return_value = [
        ProcessMap(start=0, end=8, prot=VMProtection.READ, name="module", offset=0)
    ]

    scanner = LocalScanner(ps4=ps4_mock, pid=1)
    state = ScanBuilderState(
        value=1,
        value_type=ScanValueType.UINT32,
        compare_type=ScanCompareType.EXACT,
        type_spec=TypeSpec(Int32ul, Int32ub),
        extra=None,
        bounds=None,
        module_pattern=None,
    )
    results = [addr async for addr, val in scanner._scan(state)]
    assert results == [0]  # first value matches 1


@pytest.mark.asyncio
async def test_refresh_filters_and_yields():
    ps4 = AsyncMock()

    # memory: addr -> bytes
    memory = {
        0x1000: Int32ul.build(10),
        0x2000: Int32ul.build(5),
    }

    async def fake_read(pid, addr, size):
        return memory[addr]

    ps4.read_memory.side_effect = fake_read

    scanner = LocalScanner(ps4, pid=1)
    scanner.previous = {0x1000: 8, 0x2000: 5}  # previous values

    state = ScanBuilderState(
        value=10,
        value_type=ScanValueType.INT32,
        compare_type=ScanCompareType.EXACT,
        type_spec=TypeSpec(Int32ul, Int32ub),
    )

    results = [addr async for addr, _ in scanner._refresh(state)]
    assert results == [0x1000]
