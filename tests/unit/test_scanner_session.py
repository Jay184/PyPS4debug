import pytest

from construct import Int32ul, Int32ub

from ps4debug.memory.scanner.base import TypeSpec
from ps4debug.memory.scanner.builder import ScanBuilderState, ScanBuilder
from ps4debug.memory.scanner.session import ScanSession
from tests.fakes import FakeSession


@pytest.fixture
def valid_query():
    builder = ScanBuilder()

    # Minimal valid configuration:
    # - type_spec + value_type set via int32()
    # - compare_type + value set via exact()
    builder.int32().exact(123)

    return builder._state


@pytest.fixture
def valid_query_no_value():
    builder = ScanBuilder()
    builder.int32().unknown_initial_value()
    return builder._state


@pytest.fixture
def valid_query_between():
    builder = ScanBuilder()
    builder.int32().between(10, 20)
    return builder._state


def test_validate_missing_fields():
    q = ScanBuilderState()

    with pytest.raises(ValueError):
        ScanSession.validate(q)


def test_validate_success():
    q = ScanBuilder().int32().exact(5)
    ScanSession.validate(q._state)


@pytest.mark.asyncio
async def test_executor_runs_execute():
    session = FakeSession()

    async with session.executor() as builder:
        builder.int32().exact(5)

    # after context exit → execute() should have run
    assert session.scan_called is True


def test_reset_clears_state():
    session = FakeSession()
    session.initial = {1: 2}
    session.previous = {3: 4}

    session.reset()

    assert session.initial == {}
    assert session.previous == {}


def test_update_sets_initial_once():
    session = FakeSession()

    session.update({1: 10})
    assert session.initial == {1: 10}
    assert session.previous == {1: 10}

    session.update({2: 20})
    # initial must NOT change
    assert session.initial == {1: 10}
    assert session.previous == {2: 20}


import pytest

@pytest.mark.asyncio
async def test_execute_collects_results():
    class DummyCompare:
        def validate(self, *_, **__):
            pass

    session = FakeSession()
    q = ScanBuilderState()
    q.type_spec = TypeSpec(Int32ul, Int32ub)
    q.value_type = object()
    q.compare_type = DummyCompare()  # see below

    result = await session.execute(q)

    assert result == {0: 0, 1: 10, 2: 20}


@pytest.mark.asyncio
async def test_execute_iter_uses_scan_first(valid_query):
    session = FakeSession()

    results = [x async for x in session.execute_iter(valid_query)]

    assert session.scan_called is True
    assert session.refresh_called is False


@pytest.mark.asyncio
async def test_execute_iter_uses_refresh_after_initial(valid_query):
    session = FakeSession()

    # first run populates initial
    await session.execute(valid_query)

    # second run should use refresh
    results = [x async for x in session.execute_iter(valid_query)]

    assert session.refresh_called is True


@pytest.mark.asyncio
async def test_execute_iter_updates_after_completion(valid_query):
    session = FakeSession()

    results = {}
    async for addr, val in session.execute_iter(valid_query):
        results[addr] = val

    assert session.previous == results
    assert session.initial == results


def test_build_value_fixed_type():
    q = ScanBuilderState()
    q.value_type = ...  # non-variable

    q.type_spec = TypeSpec(Int32ul, Int32ub)

    data = ScanSession._build_value(5, q)
    assert data == Int32ul.build(5)


def test_build_value_none_with_padding():
    q = ScanBuilderState()
    q.value_type = ...
    q.type_spec = TypeSpec(Int32ul, Int32ub)

    data = ScanSession._build_value(None, q, pad=True)
    assert data == b"\x00" * 4


@pytest.mark.asyncio
async def test_execute_iter_updates_on_partial_iteration(valid_query):
    session = FakeSession()

    agen = session.execute_iter(valid_query)

    i = 0
    async for addr, val in agen:
        if i == 1:
            await agen.aclose()
            break
        i += 1

    # generator closed → update should still have happened
    assert session.previous != {}
