from typing import TYPE_CHECKING, Callable, TypeVar, Coroutine, Any
from asyncio import Event, StreamReader, StreamWriter, IncompleteReadError
from dataclasses import dataclass
import asyncio

from construct import Int32ul
from pydantic_construct import ConstructModel

from ps4debug.core import (
    MAX_BREAKPOINTS,
    MAX_WATCHPOINTS,
    BaseCommand,
    ResponseCode,
    ThreadInfo,
    Registers64,
    FPRegisters,
    DebugRegisters,
    WatchPointLengthType,
    WatchPointBreakType,
    DebuggerInterrupt,
    ResumeThreadCommand,
    StopThreadCommand,
    ResumeProcessCommand,
    StopProcessCommand,
    KillProcessCommand,
    ListThreadsCommand,
    ThreadInfoCommand,
    SetRegistersCommand,
    GetRegistersCommand,
    SetFloatRegistersCommand,
    GetFloatRegistersCommand,
    SetDebugRegistersCommand,
    GetDebugRegistersCommand,
    SetBreakpointCommand,
    SetWatchpointCommand,
    SingleStepCommand,
)

from .event import BreakpointEventArgs

if TYPE_CHECKING:
    from ps4debug.ps4debug import PS4Debug


T = TypeVar("T", bound="ConstructModel")

BreakpointCallback = Callable[[BreakpointEventArgs], Coroutine[Any, Any, None]]


@dataclass
class Breakpoint:
    enabled: bool = False
    address: int = 0
    callback: BreakpointCallback | None = None


class DebuggingContext:
    """High-level interface for remote debugging operations."""
    def __init__(self, ps4debug: "PS4Debug", pid: int):
        self.ps4debug = ps4debug
        self.pid = pid

        self._stop_event = Event()
        self.callback: BreakpointCallback | None = None

        self.breakpoints: dict[int, Breakpoint] = {
            i: Breakpoint() for i in range(MAX_BREAKPOINTS)
        }

        # Reverse lookup: address -> index
        self._bp_by_address: dict[int, int] = {}
        self._read_timeout: float | None = 5.0

    def register_callback(self, func: BreakpointCallback | None) -> None:
        """Register a global breakpoint callback.

        This callback is executed before per-breakpoint callbacks.

        Args:
            func: Async callback or None to clear it.
        """
        self.callback = func

    async def resume_process(self) -> ResponseCode:
        """Resume execution of the debugged process."""
        # noinspection PyProtectedMember
        async with self.ps4debug._connection() as conn:
            return await conn.send(ResumeProcessCommand())

    async def stop_process(self) -> ResponseCode:
        """Pause execution of the debugged process."""
        # noinspection PyProtectedMember
        async with self.ps4debug._connection() as conn:
            return await conn.send(StopProcessCommand())

    async def kill_process(self) -> ResponseCode:
        """Terminate the debugged process."""
        # noinspection PyProtectedMember
        async with self.ps4debug._connection() as conn:
            return await conn.send(KillProcessCommand())

    async def resume_thread(self, thread_id: int) -> ResponseCode:
        """Resume execution of a thread in the debugged process."""
        # TODO This does not work yet on the server's side but eventually it should so we allow the call already but it will always fail.
        # noinspection PyProtectedMember
        async with self.ps4debug._connection() as conn:
            return await conn.send(
                ResumeThreadCommand(thread_id=thread_id)
            )

    async def stop_thread(self, thread_id: int) -> ResponseCode:
        """Pause execution of a thread in the debugged process."""
        # TODO This does not work yet on the server's side but eventually it should so we allow the call already but it will always fail.
        # noinspection PyProtectedMember
        async with self.ps4debug._connection() as conn:
            return await conn.send(
                StopThreadCommand(thread_id=thread_id)
            )

    async def get_threads(self) -> list[int]:
        """Retrieve all thread IDs.

        Returns:
            List of thread IDs, or empty list on failure.
        """
        # noinspection PyProtectedMember
        async with self.ps4debug._connection() as conn:
            status = await conn.send(ListThreadsCommand())

            if status != ResponseCode.SUCCESS:
                return []

            count_bytes = await conn.read_exactly(4)
            count = Int32ul.parse(count_bytes)
            data = await conn.read_exactly(count * 4)

        return list(Int32ul[count].parse(data))

    async def get_thread_info(self, thread_id: int) -> ThreadInfo:
        """Retrieve detailed information for a thread."""
        # noinspection PyProtectedMember
        async with self.ps4debug._connection() as conn:
            await conn.send(ThreadInfoCommand(thread_id=thread_id))
            data = await conn.read_exactly(ThreadInfo.struct.sizeof())

        return ThreadInfo.model_validate_bytes(data)

    async def get_registers(self, thread_id: int) -> Registers64 | None:
        return await self._read_struct(
            GetRegistersCommand(thread_id=thread_id),
            Registers64,
        )

    async def set_registers(
        self,
        thread_id: int,
        registers: Registers64,
    ) -> ResponseCode:
        return await self._write_struct(
            SetRegistersCommand(thread_id=thread_id, size=Registers64.struct.sizeof()),
            registers.model_dump_bytes(),
        )

    async def get_fp_registers(self, thread_id: int) -> FPRegisters | None:
        return await self._read_struct(
            GetFloatRegistersCommand(thread_id=thread_id),
            FPRegisters,
        )

    async def set_fp_registers(
        self,
        thread_id: int,
        registers: FPRegisters,
    ) -> ResponseCode:
        return await self._write_struct(
            SetFloatRegistersCommand(thread_id=thread_id, size=Registers64.struct.sizeof()),
            registers.model_dump_bytes(),
        )

    async def get_debug_registers(self, thread_id: int) -> DebugRegisters | None:
        return await self._read_struct(
            GetDebugRegistersCommand(thread_id=thread_id),
            DebugRegisters,
        )

    async def set_debug_registers(
        self,
        thread_id: int,
        registers: DebugRegisters,
    ) -> ResponseCode:
        return await self._write_struct(
            SetDebugRegistersCommand(thread_id=thread_id, size=Registers64.struct.sizeof()),
            registers.model_dump_bytes(),
        )

    def get_breakpoint(
        self,
        index: int,
    ) -> Breakpoint:
        """Get breakpoint configuration."""
        self._validate_index(index, MAX_BREAKPOINTS, "breakpoint index")
        return self.breakpoints[index]

    def find_free_breakpoint(self) -> int | None:
        for i, bp in self.breakpoints.items():
            if not bp.enabled:
                return i
        return None

    async def add_breakpoint(
        self,
        address: int,
        callback: BreakpointCallback | None = None,
    ) -> int:
        index = self.find_free_breakpoint()
        if index is None:
            raise RuntimeError("No free breakpoint slots available")

        status = await self.set_breakpoint(index, True, address, callback)

        if status != ResponseCode.SUCCESS:
            raise RuntimeError(f"Failed to set breakpoint: {status}")

        return index

    async def set_breakpoint(
        self,
        index: int,
        enabled: bool,
        address: int,
        on_hit: BreakpointCallback | None,
    ) -> ResponseCode:
        """Configure a software breakpoint.

        Args:
            index: Breakpoint slot index.
            enabled: Whether the breakpoint is active.
            address: Target address.
            on_hit: Async callback when triggered.

        Returns:
            ResponseCode
        """
        self._validate_index(index, MAX_BREAKPOINTS, "breakpoint index")

        # noinspection PyProtectedMember
        async with self.ps4debug._connection() as conn:
            command = SetBreakpointCommand(
                index=index,
                enabled=enabled,
                address=address,
            )
            status = await conn.send(command)

        if status == ResponseCode.SUCCESS:
            old = self.breakpoints[index]

            # remove old mapping if needed
            if old.enabled and self._bp_by_address.get(old.address) == index:
                self._bp_by_address.pop(old.address, None)

            self.breakpoints[index] = Breakpoint(enabled, address, on_hit)

            if enabled:
                self._bp_by_address[address] = index

        return status or ResponseCode.ERROR

    async def set_watchpoint(
        self,
        index: int,
        enabled: bool,
        address: int,
        length: WatchPointLengthType = WatchPointLengthType.LEN_1,
        watch_type: WatchPointBreakType = WatchPointBreakType.READ_WRITE,
    ) -> ResponseCode:
        """Configure a hardware watchpoint."""
        self._validate_index(index, MAX_WATCHPOINTS, "watchpoint index")

        # noinspection PyProtectedMember
        async with self.ps4debug._connection() as conn:
            command = SetWatchpointCommand(
                index=index,
                enabled=enabled,
                length=length,
                type=watch_type,
                address=address,
            )
            return await conn.send(command)

    async def single_step(self) -> ResponseCode:
        """Execute a single instruction."""
        # noinspection PyProtectedMember
        async with self.ps4debug._connection() as conn:
            return await conn.send(SingleStepCommand())

    async def debug_connected(
        self,
        reader: StreamReader,
        writer: StreamWriter,
    ) -> None:
        """Handle incoming debug events."""
        length = DebuggerInterrupt.struct.sizeof()

        try:
            while not self._stop_event.is_set():
                read_coro = reader.readexactly(length)

                if self._read_timeout:
                    read_coro = asyncio.wait_for(read_coro, timeout=self._read_timeout)

                data = await read_coro
                interrupt = DebuggerInterrupt.model_validate_bytes(data)

                index = self._bp_by_address.get(interrupt.regs.rip)
                if index is None:
                    continue

                event = BreakpointEventArgs(self, index, interrupt)
                tasks = []

                if self.callback:
                    tasks.append(self.callback(event))

                bp = self.breakpoints[index]
                if bp.callback:
                    tasks.append(bp.callback(event))

                if tasks:
                    await asyncio.gather(*tasks)

                if event.resume:
                    await self.resume_process()

        except (IncompleteReadError, TimeoutError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    def stop(self) -> None:
        """Signal the debug loop to stop."""
        self._stop_event.set()

    @staticmethod
    def _validate_index(index: int, max_value: int, name: str) -> None:
        if not (0 <= index < max_value):
            raise ValueError(f"{name} must be between 0 and {max_value - 1}, got {index}")

    async def _read_struct(
        self,
        command: BaseCommand,
        model: type[T],
    ) -> T | None:
        # noinspection PyProtectedMember
        async with self.ps4debug._connection() as conn:
            await conn.send(command)
            data = await conn.read_exactly(model.struct.sizeof())
            return model.model_validate_bytes(data)

    async def _write_struct(
        self,
        command: BaseCommand,
        data: bytes,
    ) -> ResponseCode:
        # noinspection PyProtectedMember
        async with self.ps4debug._connection() as conn:
            return await conn.send_with_data(command, data)
