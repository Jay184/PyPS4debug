import asyncio
from typing import Any, AsyncGenerator

import pytest

from ps4debug.socket_pool import SocketPool


@pytest.fixture
async def socket_pool() -> AsyncGenerator[SocketPool, Any]:
    pool = SocketPool("127.0.0.1", 8888, limit=2)
    yield pool
    await pool.close()


@pytest.fixture(scope="session", autouse=True)
async def tcp_server():
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 8888)
    yield
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_acquire_and_release(socket_pool: SocketPool):
    async with socket_pool.get_socket() as (reader, writer):
        assert reader is not None
        assert writer is not None

    assert socket_pool._pool.qsize() == 1


@pytest.mark.asyncio
async def test_connection_limit(socket_pool: SocketPool):
    tasks = []

    async def use_socket():
        async with socket_pool.get_socket():
            await asyncio.sleep(0.1)

    for _ in range(socket_pool._limit * 2):
        tasks.append(asyncio.create_task(use_socket()))

    await asyncio.gather(*tasks)

    assert socket_pool._created <= socket_pool._limit


@pytest.mark.asyncio
async def test_reuse(socket_pool: SocketPool):
    async with socket_pool.get_socket() as (_, writer1):
        pass

    async with socket_pool.get_socket() as (_, writer2):
        pass

    assert writer1 is writer2


@pytest.mark.asyncio
async def test_drops_closed_connection(socket_pool: SocketPool):
    async with socket_pool.get_socket() as (_, writer):
        writer.close()

    # Next acquire should create a new one
    async with socket_pool.get_socket() as (_, new_writer):
        assert new_writer is not writer


@pytest.mark.asyncio
async def test_start_populates_pool(socket_pool: SocketPool):
    await socket_pool.start()

    assert socket_pool._pool.qsize() == socket_pool._limit
    assert socket_pool._created == socket_pool._limit


@pytest.mark.asyncio
async def test_exception_reduces_created(socket_pool: SocketPool):
    async with socket_pool.get_socket() as (_, writer):
        pass

    initial_created = socket_pool._created

    with pytest.raises(RuntimeError):
        async with socket_pool.get_socket():
            raise RuntimeError()

    assert socket_pool._created == initial_created - 1


@pytest.mark.asyncio
async def test_waits_when_pool_exhausted(socket_pool: SocketPool):
    acquired = asyncio.Event()

    async def hold_socket():
        async with socket_pool.get_socket():
            acquired.set()
            await asyncio.sleep(0.2)

    async def wait_for_socket():
        await acquired.wait()
        async with socket_pool.get_socket():
            return True

    t1 = asyncio.create_task(hold_socket())
    t2 = asyncio.create_task(wait_for_socket())

    await asyncio.gather(t1, t2)

    assert t2.result() is True


@pytest.mark.asyncio
async def test_close_closes_all_connections(socket_pool: SocketPool):
    await socket_pool.start()

    writers = []
    while not socket_pool._pool.empty():
        _, writer = await socket_pool._pool.get()
        writers.append(writer)

    for writer in writers:
        await socket_pool._pool.put((None, writer))  # reinsert for close()

    await socket_pool.close()

    for writer in writers:
        assert writer.is_closing()


@pytest.mark.asyncio
async def test_no_over_creation_under_race(socket_pool: SocketPool):
    async def worker():
        async with socket_pool.get_socket():
            await asyncio.sleep(0.01)

    tasks = [asyncio.create_task(worker()) for _ in range(50)]
    await asyncio.gather(*tasks)

    assert socket_pool._created <= socket_pool._limit
