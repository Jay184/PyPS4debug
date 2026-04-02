from typing import Self, TypeVar, Protocol, Awaitable, Coroutine
from pathlib import Path
from contextlib import AbstractAsyncContextManager

import asyncio
import contextlib

from pydantic_construct import ConstructModel
from construct import Int32ul, Int64ul

from .debugging import DebuggingContext
from .memory import MemoryContext, LocalScanner, MemoryView
from .find_device_protocol import FindDeviceProtocol
from .exceptions import PS4DebugException
from .socket_pool import SocketPool
from .core import (
    ResponseCode,
    VMProtection,
    NotificationType,
    Process,
    ProcessInfo,
    ProcessMap,
    CallResult,
    BaseCommand,
    VersionCommand,
    ListProcessesCommand,
    ReadMemoryCommand,
    WriteMemoryCommand,
    ProcessMapsCommand,
    InstallRPCCommand,
    CallCommand,
    LoadELFCommand,
    ChangeMemoryProtectionCommand,
    ProcessInfoCommand,
    AllocateMemoryCommand,
    FreeMemoryCommand,
    AttachDebuggerCommand,
    DetachDebuggerCommand,
    GetKernelBaseCommand,
    ReadKernelMemoryCommand,
    WriteKernelMemoryCommand,
    RebootCommand,
    PrintCommand,
    NotificationCommand,
    ConsoleInfoCommand,
)


T = TypeVar("T")
TModel = TypeVar("TModel", bound="ConstructModel")


DISCOVERY_MAGIC = 0xFFFFAAAA
DEFAULT_DISCOVERY_TIMEOUT = 20.0
DEFAULT_TIMEOUT = 15.0
MAX_CONCURRENCY = 8


class Parsable(Protocol):
    def sizeof(self) -> int:
        ...

    def parse(self, b: bytes) -> int:
        ...


class _Connection:
    """Represents a single active connection to the ps4debug server.

    This class encapsulates low-level protocol operations over a single
    TCP connection. It is not meant to be used directly by users.
    """

    def __init__(
        self,
        client: "PS4Debug",
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._client = client
        self.reader = reader
        self.writer = writer

    async def send_raw(self, command: BaseCommand) -> None:
        """Send a command without reading a response."""
        self.writer.write(command.model_dump_bytes())
        await self.writer.drain()

    async def send(self, command: BaseCommand) -> ResponseCode:
        """Send a command and wait for a status response."""
        await self.send_raw(command)
        return await self.read_status_checked(command)

    async def send_raw_with_data(
        self,
        command: BaseCommand,
        data: bytes,
    ) -> ResponseCode:
        """Send a command without reading a response, followed by a payload, then read status."""
        await self.send_raw(command)

        self.writer.write(data)
        await self.writer.drain()

        return await self.read_status_checked(command)

    async def send_with_data(
        self,
        command: BaseCommand,
        data: bytes,
    ) -> ResponseCode:
        """Send a command followed by a payload, then read status."""
        await self.send(command)

        self.writer.write(data)
        await self.writer.drain()

        return await self.read_status_checked(command)

    async def read_exactly(self, n: int) -> bytes:
        """Read exactly `n` bytes."""
        return await self._with_timeout(self.reader.readexactly(n))

    async def read_status(self) -> ResponseCode:
        """Read a raw status code."""
        data = await self.read_exactly(4)
        return ResponseCode.decode(data)

    async def read_status_checked(
        self,
        command: BaseCommand,
    ) -> ResponseCode:
        """Read status and raise if necessary."""
        status = await self.read_status()

        if status.should_raise():
            raise PS4DebugException(
                f"{command.__class__.__name__} failed: {status.name}"
            )

        return status

    async def _with_timeout(self, coro: Coroutine[T, None, None] | Awaitable[T]) -> T:
        if self._client.timeout is None:
            return await coro

        try:
            return await asyncio.wait_for(coro, self._client.timeout)
        except asyncio.TimeoutError as e:
            raise PS4DebugException("Operation timed out") from e


class PS4Debug:
    """Client for interacting with a PS4 running the ps4debug payload.

    This class provides high-level APIs for process control, memory access,
    and debugging via a TCP socket interface.
    """

    __slots__ = ("host", "port", "pool", "timeout", "_debug_lock", "_rpc_cache", "_rpc_lock")

    def __init__(
        self,
        host: str,
        port: int = 744,
        *,
        pool: SocketPool | None = None,
        timeout: float | None = DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize the PS4Debug client.

        Args:
            host: IP address or hostname of the PS4.
            port: TCP port of the ps4debug service.
            pool: Optional preconfigured SocketPool (useful for testing).

        Raises:
            ValueError: If host is empty.
        """
        self.host = host
        self.port = port

        self.pool = pool or SocketPool(host, port, limit=MAX_CONCURRENCY)
        self.timeout = timeout

        self._debug_lock = asyncio.Lock()
        self._rpc_cache: dict[int, int] = {}
        self._rpc_lock: dict[int, asyncio.Lock] = {}

    @classmethod
    async def discover(
        cls,
        port: int = 744,
        timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
    ) -> Self:
        """Discover a PS4 on the local network.

        Args:
            port: Target debug port.
            timeout: Maximum time to wait for a response.

        Returns:
            Initialized PS4Debug instance.

        Raises:
            PS4DebugException: If no device is found.
        """
        loop = asyncio.get_running_loop()
        response_future: asyncio.Future[str] = loop.create_future()

        transport, _ = await loop.create_datagram_endpoint(
            lambda: FindDeviceProtocol(DISCOVERY_MAGIC, response_future),
            local_addr=("0.0.0.0", 1010),
            allow_broadcast=True,
        )

        try:
            host = await asyncio.wait_for(
                response_future, timeout or DEFAULT_DISCOVERY_TIMEOUT
            )
        except TimeoutError as exc:
            raise PS4DebugException("No system found on the network") from exc
        finally:
            transport.close()

        return cls(host=host, port=port)

    async def send_payload(
        self,
        data: bytes,
        *,
        port: int = 9020,
    ) -> None:
        """Send a raw payload to the target host.

        Args:
            data: Raw payload bytes.
            port: Target port (e.g. 9020 or 9090).

        Raises:
            PS4DebugException: If the transfer fails.
        """
        try:
            reader, writer = await asyncio.open_connection(self.host, port)

            try:
                writer.write(data)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        except Exception as exc:
            raise PS4DebugException(f"Failed to send payload to {self.host}:{port}") from exc

    async def send_payload_file(
        self,
        file_path: Path | str,
        *,
        port: int = 9020,
    ) -> None:
        """Load a payload from disk and send it.

        Args:
            file_path: Path to payload file.
            port: Target port.

        Raises:
            OSError: If file cannot be read.
            PS4DebugException: If sending fails.
            FileNotFoundError: Unable to read the file.
        """
        file_path = Path(file_path) if isinstance(file_path, str) else file_path

        if not file_path.is_file():
            raise FileNotFoundError(f"{file_path} does not exist")

        data = Path(file_path).read_bytes()
        await self.send_payload(data, port=port)

    def memory(self, pid: int, length: int = 4096) -> MemoryContext:
        """Create a memory context manager for a process.

        Args:
            pid: Process ID.
            length: Number of bytes to allocate.

        Returns:
            MemoryContext instance.
        """
        return MemoryContext(self, pid, length)

    def debugger(
        self,
        pid: int,
        *,
        port: int = 755,
        resume: bool = False,
    ) -> AbstractAsyncContextManager[DebuggingContext]:
        """Create a debugging session for a process.

        Args:
            pid: Process ID.
            port: Local port for receiving debug events.
            resume: Whether to resume the process after attaching.

        Yields:
            DebuggingContext instance.

        Raises:
            PS4DebugException: If attaching fails.
        """
        @contextlib.asynccontextmanager
        async def _impl():
            if self._debug_lock.locked():
                raise PS4DebugException("A debugging session is already active")

            async with self._debug_lock:
                context = DebuggingContext(self, pid)

                server = await asyncio.start_server(
                    context.debug_connected,
                    host="0.0.0.0",
                    port=port,
                )

                try:
                    async with self._connection() as conn:
                        command = AttachDebuggerCommand(pid=pid)
                        status = await conn.send(command)

                    # Handle protocol-level conflict
                    if status == ResponseCode.ALREADY_DEBUG:
                        raise PS4DebugException("Target is already being debugged")

                    if resume:
                        await context.resume_process()

                    yield context

                finally:
                    # Always attempt detach
                    with contextlib.suppress(Exception):
                        async with self._connection() as conn:
                            command = DetachDebuggerCommand()
                            await conn.send_raw(command)

                    context.stop()
                    server.close()

                    await server.wait_closed()

        # This fixes typing issues around the decorator.
        return _impl()

    def scan(self, pid: int) -> LocalScanner:
        """
        Returns a builder object for constructing and executing memory scan queries
        on the target PlayStation 4 process.

        The returned `LocalScanner` instance allows a fluent interface for specifying:
        - Process ID
        - Value type (uint8, uint16, uint32, int32, float, string, etc.)
        - Comparison type (exact, increased, decreased, fuzzy, etc.)
        - Scan values or extra values for special comparisons

        Example usage:
            results = (
                await ps4.scan(pid=1234)
                    .query()
                    .uint32()
                    .exact(42)
                    .execute()
            )

        Args:
            pid: Process ID.

        Returns:
            MemoryScanner: A new builder instance attached to this PS4Debug session.
        """
        return LocalScanner(self, pid)

    def view(self, pid: int, address: int) -> MemoryView:
        """Create a memory view for an arbitrary address.

        This is a convenience factory for constructing a :class:`MemoryView`
        without requiring a :class:`MemoryContext`. It does not perform any
        allocation or validation of the target memory.

        Args:
            pid: Target process ID.
            address: Base address for the memory view.

        Returns:
            MemoryView bound to the given process and address.

        Example:
            view = client.view(pid, 0x100000)
            value = await view.uint32(0x10)
        """
        return MemoryView(self, pid, address)

    async def get_version(self) -> str:
        """Retrieve the ps4debug version string.

        Returns:
            ASCII version string.

        Raises:
            PS4DebugException: If the request fails or response is invalid.
        """
        async with self._connection() as conn:
            await conn.send_raw(VersionCommand())

            length = await self._read_construct_numeric(conn, Int32ul)
            data = await conn.read_exactly(length)
            return data.decode("ascii")

    async def reboot(self) -> None:
        """Reboot the console."""
        async with self._connection() as conn:
            await conn.send(RebootCommand())

    async def get_console_info(self) -> bool:
        """Retrieve information about the console.

        This function is not implemented in ps4debug yet:

        https://github.com/jogolden/ps4debug/blob/master/debugger/source/console.c#L80

        For now, this will return a boolean indicating a successful response.

        Returns:
            Console information response.

        Raises:
            PS4DebugException: If the request fails or response is invalid.
        """
        async with self._connection() as conn:
            status = await conn.send(ConsoleInfoCommand())
            return status is ResponseCode.SUCCESS

    async def print(
        self,
        text: str,
        encoding: str = "utf-8",
    ) -> ResponseCode:
        """Print text to the console.

        Args:
            text: Text to print.
            encoding: Encoding used for the text.

        Returns:
            ResponseCode from the server.

        Raises:
            ValueError: If text is None.
            PS4DebugException: If the command fails.
        """
        data = self._encode_c_string(text, encoding)

        async with self._connection() as conn:
            command = PrintCommand(length=len(data))
            return await conn.send_raw_with_data(command, data)

    async def notify(
        self,
        text: str,
        notification_type: NotificationType = NotificationType.CUSTOM,
        encoding: str = "utf-8",
    ) -> ResponseCode:
        """Send a system notification.

        Args:
            text: Message text.
            notification_type: Notification type.
            encoding: Encoding used for the text.

        Returns:
            ResponseCode from the server.

        Raises:
            ValueError: If text is None.
            PS4DebugException: If the command fails.
        """
        data = self._encode_c_string(text, encoding)

        async with self._connection() as conn:
            command = NotificationCommand(
                message_type=notification_type,
                length=len(data),
            )

            return await conn.send_raw_with_data(command, data)

    async def get_processes(self) -> list[Process]:
        """Retrieve running processes.

        Returns:
            List of Process instances.

        Raises:
            PS4DebugException: If the command fails.
        """
        async with self._connection() as conn:
            await conn.send(ListProcessesCommand())
            return await self._read_model_array(conn.reader, Process)

    async def get_process_info(self, pid: int) -> ProcessInfo:
        """Retrieve information about a process.

        Args:
            pid: Process ID.

        Returns:
            ProcessInfo instance.

        Raises:
            PS4DebugException: If the command fails.
        """
        async with self._connection() as conn:
            command = ProcessInfoCommand(pid=pid)
            await conn.send(command)
            return await self._read_model(conn.reader, ProcessInfo)

    async def get_process_maps(self, pid: int) -> list[ProcessMap]:
        """Retrieve memory maps of a process.

        Args:
            pid: Process ID.

        Returns:
            List of ProcessMap instances.

        Raises:
            PS4DebugException: If the command fails.
        """
        async with self._connection() as conn:
            command = ProcessMapsCommand(pid=pid)
            await conn.send(command)
            return await self._read_model_array(conn.reader, ProcessMap)

    async def allocate_memory(
        self,
        pid: int,
        length: int = 4096,
    ) -> int:
        """Allocate memory in a remote process.

        Args:
            pid: Process ID.
            length: Size in bytes.

        Returns:
            Starting address of the allocated memory.

        Raises:
            PS4DebugException: If the allocation fails.
        """
        async with self._connection() as conn:
            command = AllocateMemoryCommand(
                pid=pid,
                length=length,
            )
            await conn.send(command)
            return await self._read_construct_numeric(conn, Int64ul)

    async def free_memory(
        self,
        pid: int,
        address: int,
        length: int = 4096,
    ) -> ResponseCode:
        """Free allocated memory in a remote process.

        Args:
            pid: Process ID.
            address: Starting address.
            length: Size in bytes.

        Returns:
            ResponseCode from the server.

        Raises:
            PS4DebugException: If the operation fails.
        """
        async with self._connection() as conn:
            command = FreeMemoryCommand(
                pid=pid,
                address=address,
                length=length,
            )
            return await conn.send(command)

    async def change_protection(
        self,
        pid: int,
        address: int,
        length: int,
        prot: VMProtection,
    ) -> ResponseCode:
        """Change memory protection flags.

        Args:
            pid: Process ID.
            address: Start address.
            length: Size in bytes.
            prot: Protection flags.

        Returns:
            ResponseCode from the server.

        Raises:
            PS4DebugException: If the operation fails.
        """
        async with self._connection() as conn:
            command = ChangeMemoryProtectionCommand(
                pid=pid,
                address=address,
                length=length,
                protection=prot,
            )
            return await conn.send(command)

    async def get_rpc(self, pid: int) -> int:
        """Get or install RPC stub for a process.

        Ensures only one stub exists per process and caches the result.

        Args:
            pid: Process ID.

        Returns:
            Address of the RPC stub.

        Raises:
            PS4DebugException: If installation fails.
        """
        # Fast path (no lock)
        if pid in self._rpc_cache:
            return self._rpc_cache[pid]

        lock = self._get_rpc_lock(pid)

        async with lock:
            # Double-check after acquiring lock
            if pid in self._rpc_cache:
                return self._rpc_cache[pid]

            async with self._connection() as conn:
                address = await self._find_rpc(pid, connection=conn)

                if address is None:
                    address = await self._install_rpc(pid, connection=conn)

            self._rpc_cache[pid] = address
            return address

    async def call(
        self,
        pid: int,
        address: int,
        params: ConstructModel | None = None,
        return_model: type[TModel] | None = None,
        rpc_stub: int | None = None,
    ) -> TModel | bytes | None:
        """Execute code using structured parameters.

        Args:
            pid: Process ID.
            address: Target function address.
            params: ConstructModel instance describing input parameters.
            return_model: Optional ConstructModel type for parsing the result.
            rpc_stub: Optional pre-resolved RPC stub address.

        Returns:
            Parsed result model, raw bytes if no model is provided,
            or None if the call failed.
        """
        max_size = CallCommand.struct.registers.sizeof()
        buffer = bytearray(max_size)

        if params:
            struct_size = params.struct.sizeof()

            if struct_size > max_size:
                raise ValueError(f"Parameter payload too large ({struct_size} bytes), max is {max_size}")

            payload = params.model_dump_bytes()
            param_size = len(payload)

            # Ensure fixed-size buffer (pad if needed)
            buffer[:param_size] = payload

        rpc_stub = rpc_stub or await self.get_rpc(pid)

        command = CallCommand(
            pid=pid,
            rpc_address=rpc_stub,
            address=address,
            registers=buffer,
        )

        async with self._connection() as conn:
            await conn.send(command)
            result_bytes = await conn.read_exactly(CallResult.struct.sizeof())

        result = CallResult.model_validate_bytes(result_bytes)

        if return_model is None:
            return result.rax

        return_model_size = return_model.struct.sizeof()
        if return_model_size > len(result.rax):
            raise ValueError(
                f"Return model expects {return_model_size} bytes, "
                f"but only {len(result.rax)} available"
            )

        return return_model.model_validate_bytes(result.rax)

    async def send_elf(
        self,
        pid: int,
        elf: bytes,
    ) -> ResponseCode:
        """Send an ELF payload to the target process.

        Args:
            pid: Process ID.
            elf: Raw ELF bytes.

        Returns:
            ResponseCode from the server.

        Raises:
            PS4DebugException: If the command fails.
        """
        async with self._connection() as conn:
            command = LoadELFCommand(
                pid=pid,
                size=len(elf)
            )
            return await conn.send_with_data(command, elf)


    async def send_elf_file(
        self,
        pid: int,
        file_path: Path | str,
    ) -> ResponseCode:
        """Load an ELF file from disk and send it.

        Args:
            pid: Process ID.
            file_path: Path to ELF file.

        Returns:
            ResponseCode from the server.

        Raises:
            OSError: If file cannot be read.
            PS4DebugException: If sending fails.
            FileNotFoundError: Unable to read the file.
        """
        file_path = Path(file_path) if isinstance(file_path, str) else file_path

        if not file_path.is_file():
            raise FileNotFoundError(f"{file_path} does not exist")

        data = Path(file_path).read_bytes()
        return await self.send_elf(pid, data)

    async def read_memory(
        self,
        pid: int,
        address: int,
        length: int,
    ) -> bytes:
        """Read raw memory from a process.

        Args:
            pid: Process ID.
            address: Starting address.
            length: Number of bytes to read.

        Returns:
            Bytes read from memory.

        Raises:
            PS4DebugException: If the read fails.
        """
        async with self._connection() as conn:
            return await self._read_memory(pid, address, length, connection=conn)

    async def write_memory(
        self,
        pid: int,
        address: int,
        value: bytes,
    ) -> ResponseCode:
        """Write raw bytes into process memory.

        Args:
            pid: Process ID.
            address: Starting address.
            value: Data to write.

        Returns:
            ResponseCode.SUCCESS on success.

        Raises:
            PS4DebugException: If the write fails.
        """
        async with self._connection() as conn:
            return await self._write_memory(
                pid,
                address,
                value,
                connection=conn,
            )

    async def get_kernel_base(self) -> int:
        """Retrieve the base address of the kernel.

        Returns:
            Kernel base address.

        Raises:
            PS4DebugException: If the request fails.
        """
        async with self._connection() as conn:
            await conn.send(GetKernelBaseCommand())
            return await self._read_construct_numeric(conn, Int64ul)

    async def read_kernel_memory(
        self,
        address: int,
        length: int,
    ) -> bytes:
        """Read kernel memory.

        Args:
            address: Starting address.
            length: Number of bytes.

        Returns:
            Bytes read from kernel memory.

        Raises:
            PS4DebugException: If the read fails.
        """
        async with self._connection() as conn:
            return await self._read_kernel_memory(
                address,
                length,
                connection=conn,
            )

    async def write_kernel_memory(
        self,
        address: int,
        value: bytes,
    ) -> ResponseCode:
        """Write to kernel memory.

        Warning:
            This operation can destabilize or crash the system.

        Args:
            address: Starting address.
            value: Data to write.

        Returns:
            ResponseCode.SUCCESS on success.

        Raises:
            PS4DebugException: If the write fails.
        """
        async with self._connection() as conn:
            return await self._write_kernel_memory(
                address,
                value,
                connection=conn,
            )

    def _connection(self) -> AbstractAsyncContextManager[_Connection]:
        """Acquire a connection from the pool."""
        @contextlib.asynccontextmanager
        async def _impl():
            async with self.pool.get_socket() as (reader, writer):
                yield _Connection(self, reader, writer)

        # This fixes typing issues around the decorator.
        return _impl()

    def _get_rpc_lock(self, pid: int) -> asyncio.Lock:
        if pid not in self._rpc_lock:
            self._rpc_lock[pid] = asyncio.Lock()
        return self._rpc_lock[pid]

    async def _install_rpc(
        self,
        pid: int,
        *,
        connection: _Connection,
    ) -> int:
        """Install RPC stub into process memory."""
        command = InstallRPCCommand(pid=pid)
        await connection.send(command)
        return await self._read_construct_numeric(connection, Int64ul)

    async def _find_rpc(
        self,
        pid: int,
        *,
        connection: _Connection,
        start: int = 0x4000,
        end: int = 0x00FFFFFF,
        chunk_size: int = 0x8000,
    ) -> int | None:
        """Search for existing RPC stub in memory."""
        signature = b"\x52\x53\x54\x42\xA3"
        sig_len = len(signature)
        overlap = sig_len - 1
        address = start

        while address < end - overlap:
            read_size = min(chunk_size, end - address)

            data = await self._read_memory(
                pid,
                address,
                read_size,
                connection=connection,
            )

            idx = data.find(signature)
            if idx != -1:
                return address + idx

            address += read_size - overlap

        return None

    @staticmethod
    async def _read_memory(
        pid: int,
        address: int,
        length: int,
        *,
        connection: _Connection,
    ) -> bytes:
        command = ReadMemoryCommand(
            pid=pid,
            address=address,
            length=length,
        )
        await connection.send(command)
        return await connection.read_exactly(length)

    @staticmethod
    async def _write_memory(
        pid: int,
        address: int,
        value: bytes,
        *,
        connection: _Connection,
    ) -> ResponseCode:
        command = WriteMemoryCommand(
            pid=pid,
            address=address,
            length=len(value),
        )
        return await connection.send_with_data(command, value)

    @staticmethod
    async def _read_kernel_memory(
        address: int,
        length: int,
        *,
        connection: _Connection,
    ) -> bytes:
        command = ReadKernelMemoryCommand(
            address=address,
            length=length,
        )
        await connection.send(command)
        return await connection.read_exactly(length)

    @staticmethod
    async def _write_kernel_memory(
        address: int,
        value: bytes,
        *,
        connection: _Connection,
    ) -> ResponseCode:
        command = WriteKernelMemoryCommand(
            address=address,
            length=len(value),
        )
        return await connection.send_with_data(command, value)

    @staticmethod
    async def _read_model(
        reader: asyncio.StreamReader,
        model: type[TModel],
    ) -> TModel:
        """Read a single ConstructModel instance."""
        size = model.struct.sizeof()
        data = await reader.readexactly(size)
        return model.model_validate_bytes(data)

    @staticmethod
    async def _read_model_array(
        reader: asyncio.StreamReader,
        model: type[TModel],
    ) -> list[TModel]:
        """Read an array of ConstructModel instances."""
        count_bytes = await reader.readexactly(Int32ul.sizeof())
        count = Int32ul.parse(count_bytes)
        model_size = model.struct.sizeof()

        data = await reader.readexactly(count * model_size)

        return [
            model.model_validate_bytes(data[i:i + model_size])
            for i in range(0, len(data), model_size)
        ]

    @staticmethod
    def _encode_c_string(text: str, encoding: str) -> bytes:
        """Encode a null-terminated string."""
        if text is None:
            raise ValueError("text must not be None")

        if not text.endswith("\0"):
            text += "\0"

        return text.encode(encoding)

    @staticmethod
    async def _read_construct_numeric(conn: _Connection, construct_type: Parsable) -> int:
        data = await conn.read_exactly(construct_type.sizeof())
        return construct_type.parse(data)
