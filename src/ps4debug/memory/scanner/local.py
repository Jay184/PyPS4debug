from typing import AsyncGenerator, Any, TYPE_CHECKING, Callable, Coroutine, Generator
import asyncio
import contextlib

from .builder import ScanBuilderState
from .session import ScanSession
from .registry import compare_function

from ps4debug.core import ProcessMap, VMProtection

if TYPE_CHECKING:
    from ps4debug import PS4Debug


class LocalScanner(ScanSession):
    def __init__(
        self,
        ps4: "PS4Debug",
        pid: int, *,
        chunk_size: int = 512_000,
        max_workers: int = 8,
    ) -> None:
        """
        Initialize a memory scanner for a specific process.

        Args:
            ps4: Instance of the PS4Debug client.
            pid: Process ID of the target process to scan.
            chunk_size: Amount of bytes to process at once.
        """
        super().__init__(ps4, pid)
        self._chunk_size = chunk_size
        self._max_workers = max_workers

    async def _refresh(self, query: ScanBuilderState) -> AsyncGenerator[tuple[int, Any], None]:
        value_bytes = self._build_value(query.value, query, pad=True)
        value_size = len(value_bytes)

        semaphore = asyncio.Semaphore(self._max_workers)
        pending = set()
        it = iter(self.previous.keys())

        async def run(addr: int) -> tuple[int, Any] | None:
            async with semaphore:
                with contextlib.suppress(Exception):
                    data = await self._ps4.read_memory(self.pid, addr, value_size)

                    if len(data) != value_size:
                        return None

                    curr = query.core_type.parse(data)

                    if self._compare_value(addr, curr, query):
                        return addr, curr
                return None

        cm = self.paused() if query.pause_process else contextlib.nullcontext()

        async with cm:
            # prime
            for _ in range(self._max_workers):
                try:
                    address = next(it)
                except StopIteration:
                    break
                pending.add(asyncio.create_task(run(address)))

            while pending:
                done, _ = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                pending -= done

                for task in done:
                    res = await task

                    if res:
                        yield res

                    try:
                        next_addr = next(it)
                        pending.add(asyncio.create_task(run(next_addr)))
                    except StopIteration:
                        pass

    async def _scan(self, query: ScanBuilderState) -> AsyncGenerator[tuple[int, Any], None]:
        async def _worker(addr: int, size: int) -> bytes:
            return await self._ps4.read_memory(self.pid, addr, size)

        maps = await self._ps4.get_process_maps(self.pid)
        # noinspection PyProtectedMember
        regions = self._resolve_regions(query, maps)

        value_bytes = self._build_value(query.value, query, pad=True)
        value_size = len(value_bytes)

        alignment = value_size
        step = alignment if query.aligned else 1

        cm = self.paused() if query.pause_process else contextlib.nullcontext()

        async with cm:
            async for base_addr, read_addr, buffer in self.scan_regions(
                regions,
                _worker,
                chunk_size=self._chunk_size,
                alignment=alignment,
                concurrency=self._max_workers,
            ):
                offset = base_addr - read_addr
                view = memoryview(buffer)[offset:]

                for i in range(0, len(view) - value_size + 1, step):
                    data = view[i:i + value_size]
                    current = query.core_type.parse(data)

                    if self._compare_value(base_addr + i, current, query):
                        yield base_addr + i, current

    def _compare_value(self, addr: int, current: Any, state: ScanBuilderState) -> bool:
        fn = compare_function[state.compare_type.name]  # Raises KeyError when not registered

        prev = self.previous.get(addr)
        init = self.initial.get(addr)

        return fn(
            current=current,
            value=state.value,
            previous=prev,
            initial=init,
            extra=state.extra,
        )

    @classmethod
    async def scan_regions(
        cls,
        regions: list[tuple[int, int]],
        worker: Callable[[int, int], Coroutine[Any, Any, bytes]],
        chunk_size: int,
        alignment: int,
        concurrency: int = 4,
    ) -> AsyncGenerator[tuple[int, int, bytes]]:
        semaphore = asyncio.Semaphore(concurrency)
        pending = set()

        async def run(base_addr_: int, read_addr_: int, read_size_: int) -> tuple[int, int, bytes]:
            async with semaphore:
                data = await worker(read_addr_, read_size_)
                return base_addr_, read_addr_, data

        chunk_iter = cls._iter_chunks(regions, chunk_size, alignment)

        # Prime initial tasks
        for _ in range(concurrency):
            try:
                base_addr, read_addr, read_size = next(chunk_iter)
            except StopIteration:
                break

            task = asyncio.create_task(run(base_addr, read_addr, read_size))
            pending.add(task)

        while pending:
            done, _ = await asyncio.wait(
                pending,
                return_when=asyncio.FIRST_COMPLETED,
            )

            pending -= done

            for task in done:
                result = await task
                yield result

                # Schedule next chunk
                try:
                    base_addr, read_addr, read_size = next(chunk_iter)
                    new_task = asyncio.create_task(run(base_addr, read_addr, read_size))
                    pending.add(new_task)
                except StopIteration:
                    pass

    @staticmethod
    def _resolve_regions(
        state: ScanBuilderState,
        maps: list[ProcessMap],
    ) -> list[tuple[int, int]]:
        regions = []

        for m in maps:
            if not (m.prot & VMProtection.READ):
                continue

            if state.module_pattern and not state.module_pattern.search(m.name):
                continue

            start, end = m.start, m.end

            if state.bounds:
                b_start, b_end = state.bounds

                # intersection
                start = max(start, b_start)
                end = min(end, b_end)

                if start >= end:
                    continue

            regions.append((start, end))

        return regions

    @staticmethod
    def _iter_chunks(
        regions: list[tuple[int, int]],
        chunk_size: int,
        value_size: int,
    ) -> Generator[tuple[int, int, int], None, None]:
        overlap = value_size - 1

        for start, end in regions:
            if start % value_size != 0:
                start += value_size - (start % value_size)

            current = start

            first = True
            while current < end:
                size = min(chunk_size, end - current)
                size -= size % value_size

                if size <= 0:
                    break

                if first:
                    read_start = current
                    read_size = size
                    first = False
                else:
                    read_start = max(current - overlap, start)
                    read_size = (current + size) - read_start

                yield current, read_start, read_size

                current += size
