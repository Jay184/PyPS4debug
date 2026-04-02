from typing import TYPE_CHECKING, Any, AsyncContextManager, Self, AsyncGenerator
from abc import ABCMeta, abstractmethod
import contextlib

from construct import SizeofError
from ps4debug import ScanValueType

if TYPE_CHECKING:
    from ps4debug import PS4Debug

from .builder import ScanBuilder, ScanBuilderState


class ScanSession(metaclass=ABCMeta):
    __slots__ = ("pid", "initial", "previous", "_ps4")

    def __init__(self, ps4: "PS4Debug", pid: int):
        self.pid = pid

        self._ps4 = ps4

        self.initial: dict[int, Any] = {}
        self.previous: dict[int, Any] = {}

    def query(self) -> ScanBuilder:
        return ScanBuilder(self)

    def executor(self) -> AsyncContextManager[ScanBuilder, None]:
        @contextlib.asynccontextmanager
        async def _impl():
            builder = self.query()
            yield builder
            # noinspection PyProtectedMember
            await self.execute(builder._state)

        # Fixes type-hinting issues
        return _impl()

    def reset(self) -> Self:
        self.initial = {}
        self.previous = {}
        return self

    def update(self, current: dict[int, Any]) -> None:
        if not self.initial:
            self.initial = current.copy()
        self.previous = current

    async def execute(self, query: ScanBuilderState) -> dict[int, Any]:
        addresses = {}

        async for addr, value in self.execute_iter(query):
            addresses[addr] = value

        return addresses

    async def execute_iter(self, query: ScanBuilderState) -> AsyncGenerator[tuple[int, Any], None]:
        self.validate(query)
        addresses = {}

        it = self._refresh(query) if self.initial else self._scan(query)

        try:
            async for addr, value in it:
                addresses[addr] = value
                yield addr, value
        finally:
            # Only update state once the iteration is done (or if generator is closed)
            self.update(addresses)

    @contextlib.asynccontextmanager
    async def paused(self):
        async with self._ps4.debugger(self.pid, resume=False) as dbg:
            await dbg.stop_process()  # Explicit

            try:
                yield dbg
            finally:
                await dbg.resume_process()

    @staticmethod
    def validate(query: ScanBuilderState) -> None:
        if query.type_spec is None:
            raise ValueError("Value type not set")

        if query.core_type is None:
            raise ValueError("Value type not set")

        if query.value_type is None:
            raise ValueError("Value type not set")

        if query.compare_type is None:
            raise ValueError("Compare type not set")

        value = query.value
        extra = query.extra

        query.compare_type.validate(
            query.value_type,
            has_scan=value is not None,
            has_extra=extra is not None,
        )

    @abstractmethod
    def _scan(self, query: ScanBuilderState) -> AsyncGenerator[tuple[int, Any], None]:
        ...

    @abstractmethod
    def _refresh(self, query: ScanBuilderState) -> AsyncGenerator[tuple[int, Any], None]:
        ...

    @staticmethod
    def _build_value(value: Any, query: ScanBuilderState, *, pad: bool = False) -> bytes:
        """
        Build the raw bytes.

        Returns:
            Raw bytes to send for the scan.

        Raises:
            RuntimeError: If numeric type does not have fixed size.
        """
        ctype = query.core_type

        if not ctype:
            raise RuntimeError("Type not set")

        if query.value_type in ScanValueType.variable_types():
            return ctype.build(value)

        try:
            value_size = ctype.sizeof()
        except SizeofError:
            raise RuntimeError("Numeric type must have fixed size")

        empty_value = b"\x00" * value_size if pad else b""

        value_bytes = (
            ctype.build(value)
            if value is not None
            else empty_value
        )

        return value_bytes
