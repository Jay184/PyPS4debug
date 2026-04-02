from typing import TYPE_CHECKING, AsyncGenerator, Any
import contextlib

from construct import Int64ul

from ps4debug.core import ScanMemoryCommand

from .session import ScanSession
from .builder import ScanBuilderState

if TYPE_CHECKING:
    from ps4debug import PS4Debug


class LegacyScanner(ScanSession):
    def __init__(self, ps4: "PS4Debug", pid: int) -> None:
        """
        Initialize a memory scanner for a specific process.

        This memory scanner uses the ps4debug endpoint.
        The server does not send the value of the addresses that match the query, nor does it keep an internal state.
        It simply rescans the entire memory space.

        Module patterns will be ignored in this scanner because ps4debug does not support it.
        Bounds will be checked locally after receiving the result.

        Args:
            ps4: Instance of the PS4Debug client.
            pid: Process ID of the target process to scan.
        """
        super().__init__(ps4, pid)

    async def _refresh(self, query: ScanBuilderState) -> AsyncGenerator[tuple[int, Any], None]:
        # ps4debug does not support this. Fallback to full scan
        return self._scan(query)

    async def _scan(self, query: ScanBuilderState) -> AsyncGenerator[tuple[int, Any], None]:
        """
        Scan process memory for matching addresses.

        Returns:
            List of matching addresses.

        Raises:
            ValueError: If parameters are invalid.
            PS4DebugException: If the scan fails.
        """
        if None in (self.pid, query.value_type, query.compare_type):
            raise ValueError("Incomplete scan query")

        buffer = self._build_scan_buffer(query)

        command = ScanMemoryCommand(
            pid=self.pid,
            value_type=query.value_type,
            compare_type=query.compare_type,
            data_length=len(buffer),
        )

        # noinspection PyProtectedMember
        async with self._ps4._connection() as conn:
            await conn.send_with_data(command, buffer)

            # Scanning starts now. The end flag signals the scan has reached the end
            end_flag = 0xFFFFFFFFFFFFFFFF

            cm = self.paused() if query.pause_process else contextlib.nullcontext()

            async with cm:
                while True:
                    raw = await conn.read_exactly(Int64ul.sizeof())
                    addr = Int64ul.parse(raw)

                    if addr == end_flag:
                        break

                    if query.bounds:
                        start, end = query.bounds
                        if addr < start or addr >= end:
                            continue

                    yield addr, None

    @classmethod
    def _build_scan_buffer(cls, state: ScanBuilderState) -> bytes:
        """
        Build the raw scan buffer to send to the server.

        The server requires:
            - value must occupy sizeof(value_type)
            - extra data is optional and only appended if necessary
            - variable-length types (strings/byte arrays) ignore extra values

        Returns:
            Raw bytes to send for the scan.

        Raises:
            ValueError: If value type, compare type, or construct type is missing.
            RuntimeError: If numeric type does not have fixed size.
        """
        value = state.value
        extra = state.extra

        value_bytes = cls._build_value(value, state, pad=True)
        extra_bytes = cls._build_value(extra, state, pad=False)

        return value_bytes + extra_bytes
