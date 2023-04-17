from __future__ import annotations
from typing import Callable, Coroutine
from .core import ResponseCode, BreakpointEvent
from .exceptions import PS4DebugException
import ps4debug.core as core
import ps4debug.commands as commands
import socket
import struct
import functools
import asyncio
import contextlib
import construct


class AllocatedMemoryContext(object):
    """Context for handling memory allocation and freeing."""

    def __init__(self, ps4debug, pid, length, address):
        """
        Create a new allocated memory context.
        @param ps4debug: PS4Debug instance.
        @param pid: process id.
        @param length: length in bytes.
        """
        super(AllocatedMemoryContext, self).__init__()
        self.ps4debug = ps4debug
        self.pid = pid
        self.length = length
        self.address = address

    async def change_protection(self, prot: core.VMProtection) -> ResponseCode:
        """
        Changes the protection flags.
        @param prot: New protection flags.
        @return: Response code.
        """
        return await self.ps4debug.change_protection(self.pid, self.address, self.length, prot)

    async def call(self, *args, **kwargs) -> tuple | None:
        """
        Executes a remote procedure and returns the rax register it ended with.
        Parameters are limited to 48 bytes and are split across rdi, rsi, rdx, rcx, rbx and rax in that order.
        If no rpc stub is given, a new one will be allocated
        @param args: Your parameters to send to the remote procedure
        @param kwargs: Additional options
        @keyword parameter_format: Struct format of the parameters.
            Defaults to x 8 byte integers with x being the amount of parameters you provide
        @keyword output_format: Struct format of the result. Defaults to one 8 byte integer.
        @keyword rpc_stub: RPC stub previously written by the install_rpc method.
        @return: rax register unpacked with the output_format or None if the command failed.
            Do note that the result will always be a tuple, even if the result is only one element.
        """
        return await self.ps4debug.call(self.pid, self.address, *args, **kwargs)

    async def read(self, length: int, offset: int = 0) -> bytearray | bytes | None:
        """
        Reads the raw memory in bytes.
        @param offset: Offset from the starting address of this memory section.
        @param length: Length in bytes.
        @return: The bytes read or None if the command failed.
        """
        return await self.ps4debug.read_memory(self.pid, self.address + offset, length)

    async def write(self, value: bytearray | bytes, offset: int = 0) -> ResponseCode:
        """
        Writes the raw memory in bytes to an address.
        @param offset: Offset from the starting address of this memory section.
        @param value: Bytes to write.
        @return: Response code.
        """
        return await self.ps4debug.write_memory(self.pid, self.address + offset, value)


class DebuggingContext(object):
    """Context for debugging operations."""
    max_breakpoints = 10
    max_watchpoints = 4

    def __init__(self, ps4debug, pid: int):
        super(DebuggingContext, self).__init__()
        self.ps4debug: PS4Debug = ps4debug
        self.pid = pid

        self.stop_flag = asyncio.Event()
        self.callback = None
        self.breakpoints = {i: (False, 0, None) for i in range(self.max_breakpoints)}

    def register_callback(self, func: Callable[[core.BreakpointEvent], None]) -> bool:
        """
        Registers an asynchronous callback for all breakpoints. This callback is executed before the individual ones.
        @param func: Asynchronous callback when a breakpoint is hit
        @return: True if successful, False otherwise
        """
        if func is not None and not asyncio.iscoroutinefunction(func):
            return False

        self.callback = func
        return True

    async def resume_process(self) -> ResponseCode:
        """
        Resumes all processes on the remote system.
        @return: Response code
        """
        data = construct.Int32ul.build(0)
        return await self.ps4debug.send_command(commands.DEBUG_STOPGO, data)

    async def stop_process(self) -> ResponseCode:
        """
        Stops all processes on the remote system.
        @return: Response code
        """
        data = construct.Int32ul.build(1)
        return await self.ps4debug.send_command(commands.DEBUG_STOPGO, data)

    async def kill_process(self) -> ResponseCode:
        """
        Kills the debugging process.
        @return: Response code
        """
        data = construct.Int32ul.build(2)
        return await self.ps4debug.send_command(commands.DEBUG_STOPGO, data)

    async def get_threads(self) -> list[int]:
        """
        Retrieves a list of threads in the debugging process
        @return: List of thread ids.
        """
        async with self.ps4debug.pool.get_socket() as (reader, writer):
            status = await self.ps4debug.send_command(commands.DEBUG_THREADS, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return []

            count = await reader.readexactly(4)
            count = int.from_bytes(count, 'little')

            data = await reader.readexactly(count * 4)
        return list(construct.Int32ul[count].parse(data))

    async def get_thread_info(self, thread_id: int) -> core.ThreadInfo:
        """
        Get information about a specific thread
        @param thread_id: Thread id
        @return: ThreadInfo
        """
        id_bytes = int.to_bytes(4, thread_id, 'little')

        async with self.ps4debug.pool.get_socket() as (reader, writer):
            await self.ps4debug.send_command(commands.DEBUG_THRINFO, id_bytes, reader=reader, writer=writer)
            data = await reader.readexactly(core.ThreadInfo.sizeof())

        return core.ThreadInfo.parse(data)

    async def resume_thread(self, thread_id: int) -> ResponseCode:
        """
        Continues a thread's execution.
        @param thread_id: Thread id
        @return: Response code
        """
        # TODO not yet working
        data = construct.Int32ul.build(thread_id)
        return await self.ps4debug.send_command(commands.DEBUG_RESUMETHR, data)

    async def stop_thread(self, thread_id: int) -> ResponseCode:
        """
        Stops a thread's execution.
        @param thread_id: Thread id
        @return: Response code
        """
        # TODO not yet working
        data = construct.Int32ul.build(thread_id)
        return await self.ps4debug.send_command(commands.DEBUG_STOPTHR, data)

    async def get_registers(self, thread_id: int) -> core.Registers64:
        """
        Get the registers of the thread.
        @param thread_id: Thread id
        @return: Registers
        """
        async with self.ps4debug.pool.get_socket() as (reader, writer):
            data = construct.Int32ul.build(thread_id)
            status = await self.ps4debug.send_command(commands.DEBUG_GETREGS, data, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return

            data = await reader.readexactly(core.Registers64.sizeof())
            return core.Registers64.parse(data)

    async def set_registers(self, thread_id: int, registers: core.Registers64) -> ResponseCode:
        """
        Manipulates the remote thread's registers.
        @param thread_id: Thread id
        @param registers: Full registers to write to the thread
        @return: Response code
        """
        async with self.ps4debug.pool.get_socket() as (reader, writer):
            data = core.SetRegisterPayload.build({'thread_id': thread_id, 'size': core.Registers64.sizeof()})
            status = await self.ps4debug.send_command(commands.DEBUG_SETREGS, data, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return status

            writer.write(core.Registers64.build(registers))
            await writer.drain()
            return await self.ps4debug.get_status(reader=reader)

    async def get_fp_registers(self, thread_id: int) -> core.FPRegisters:
        """
        Get the registers of the thread.
        @param thread_id: Thread id
        @return: Registers
        """
        async with self.ps4debug.pool.get_socket() as (reader, writer):
            data = construct.Int32ul.build(thread_id)
            status = await self.ps4debug.send_command(commands.DEBUG_GETFPREGS, data, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return

            data = await reader.readexactly(core.FPRegisters.sizeof())
            return core.FPRegisters.parse(data)

    async def set_fp_registers(self, thread_id: int, registers: core.FPRegisters) -> ResponseCode:
        """
        Manipulates the remote thread's registers.
        @param thread_id: Thread id
        @param registers: Full registers to write to the thread
        @return: Response code
        """
        async with self.ps4debug.pool.get_socket() as (reader, writer):
            data = core.SetRegisterPayload.build({'thread_id': thread_id, 'size': core.FPRegisters.sizeof()})
            status = await self.ps4debug.send_command(commands.DEBUG_SETFPREGS, data, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return status

            writer.write(core.FPRegisters.build(registers))
            await writer.drain()
            return await self.ps4debug.get_status(reader=reader)

    async def get_debug_registers(self, thread_id: int) -> core.DebugRegisters:
        """
        Get the registers of the thread.
        @param thread_id: Thread id
        @return: Registers
        """
        async with self.ps4debug.pool.get_socket() as (reader, writer):
            data = construct.Int32ul.build(thread_id)
            status = await self.ps4debug.send_command(commands.DEBUG_GETDBGREGS, data, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return

            data = await reader.readexactly(core.DebugRegisters.sizeof())
            return core.DebugRegisters.parse(data)

    async def set_debug_registers(self, thread_id: int, registers: core.DebugRegisters) -> ResponseCode:
        """
        Manipulates the remote thread's registers.
        @param thread_id: Thread id
        @param registers: Full registers to write to the thread
        @return: Response code
        """
        async with self.ps4debug.pool.get_socket() as (reader, writer):
            data = core.SetRegisterPayload.build({'thread_id': thread_id, 'size': core.DebugRegisters.sizeof()})
            status = await self.ps4debug.send_command(commands.DEBUG_SETDBGREGS, data, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return status

            writer.write(core.DebugRegisters.build(registers))
            await writer.drain()
            return await self.ps4debug.get_status(reader=reader)

    def get_breakpoint(self, index: int):
        assert 0 <= index < self.max_breakpoints
        return self.breakpoints[index]

    async def set_breakpoint(self, index: int, enabled: bool, address: int,
                             on_hit: Callable[[core.BreakpointEvent], None]) -> ResponseCode:
        """
        Sets a software breakpoint.
        @param index: Software breakpoint to use. 0 to 9 are valid.
        @param enabled: If False, disables the breakpoint
        @param address: Address to tie the breakpoint to
        @param on_hit: Asynchronous callback when this breakpoint is hit
        @return: Response code
        """
        if on_hit is not None and not asyncio.iscoroutinefunction(on_hit):
            return ResponseCode.ERROR

        assert 0 <= index < self.max_breakpoints
        data = core.SetBreakpointPayload.build({'index': index, 'enabled': enabled, 'address': address})
        status = await self.ps4debug.send_command(commands.DEBUG_BREAKPT, data)

        if status == ResponseCode.SUCCESS:
            self.breakpoints[index] = (enabled, address, on_hit)

        return status

    async def set_watchpoint(self, index: int, enabled: bool, address: int,
                             length: core.WatchPointLengthType = core.WatchPointLengthType.DBREG_DR7_LEN_1,
                             type_: core.WatchPointBreakType = core.WatchPointBreakType.DBREG_DR7_RDWR) -> ResponseCode:
        """
        Sets a hardware breakpoint to track a specific address for access/writes or executions.
        @param index: Hardware breakpoint to use. 0 to 3 are valid.
        @param enabled: If False, disables the breakpoint
        @param address: Address to tie the breakpoint to
        @param length: Length in bytes
        @param type_: Breakpoint type
        @return: Response code
        """
        assert 0 <= index < self.max_watchpoints
        data = core.SetWatchpointPayload.build({
            'index': index,
            'enabled': enabled,
            'length': length.value,
            'type': type_.value,
            'address': address,
        })
        return await self.ps4debug.send_command(commands.DEBUG_WATCHPT, data)

    async def single_step(self) -> ResponseCode:
        """
        Performs a single step in the remote process.
        @return: Response code
        """
        return await self.ps4debug.send_command(commands.DEBUG_SINGLESTEP)

    async def debug_connected(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        length = core.DebuggerInterrupt.sizeof()

        while not self.stop_flag.is_set():
            try:
                data = await reader.readexactly(length)
                assert len(data) == length

                interrupt = core.DebuggerInterrupt.parse(data)
                index = next(i for i, b in self.breakpoints.items() if b[0] and b[1] == interrupt.regs.rip)
                event = core.BreakpointEvent(self, index, interrupt)

                if self.callback is not None:
                    await self.callback(event)

                if self.breakpoints[index][2] is not None:
                    await self.breakpoints[index][2](event)

                if event.resume:
                    await self.resume_process()

            except asyncio.IncompleteReadError:
                writer.close()
                return


class SocketPool(object):
    """Pools a set amount of sockets using semaphores."""

    def __init__(self, host: str, port: int, max_: int = 10):
        super(SocketPool, self).__init__()
        self.host = host
        self.port = port
        self.max_ = max_
        self.pool = []
        self.semaphore = asyncio.Semaphore(max_)

    @property
    def full(self) -> bool:
        """Returns true if all sockets are in use"""
        return self.semaphore.locked()

    @contextlib.asynccontextmanager
    async def get_socket(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Get the next available socket reader/writer from the pool."""
        async with self.semaphore:
            try:
                reader, writer = self.pool.pop()
            except IndexError:
                reader, writer = await asyncio.open_connection(self.host, self.port)

            try:
                yield reader, writer
            finally:
                self.pool.append((reader, writer))

    def __del__(self):
        for _, writer in self.pool:
            writer.close()


class PS4Debug(object):
    """Offers functions to communicate with the ps4debug payload."""

    def __init__(self, host: str = None, port: int = 744):
        """
        Create a new PS4Debug instance.
        @param host: IP address or hostname of the PS4. If this is unset the network will be searched for a PS4.
        @param port: Port. defaults to 744 for ps4debug, set this if port forwarding is in use.
        """
        host = host or self.find_ps4()
        if not host:
            raise PS4DebugException('No host given and no PS4 found in network')

        self.debug_server = None
        self.pool = SocketPool(host, port, 8)

    async def __recv_all(self, length, reader: asyncio.StreamReader | None = None) -> bytearray:
        if reader is None:
            async with self.pool.get_socket() as (reader, _):
                return await self.__recv_all(length, reader=reader)

        received = 0
        data = bytearray()

        while received < length:
            packet = await reader.read(length - received)
            if reader.at_eof():
                break
            received += len(packet)
            data.extend(packet)

        if received != length:
            raise PS4DebugException(f'Unable to receive {length} bytes.')

        return data

    async def __read_type(self, pid, address, structure):
        return (await self.read_struct(pid, address, structure))[0]

    async def __write_type(self, pid, address, value, structure):
        return await self.write_struct(pid, address, structure, value)

    @classmethod
    def find_ps4(cls) -> str | None:
        """
        Attempts to find the IP address of the PlayStation 4 system in the same network.
        @return: String or None
        """
        # TODO make async
        magic = 0xFFFFAAAA
        data = magic.to_bytes(4, 'little')
        port = 1010

        # interfaces = socket.getaddrinfo(host=socket.gethostname(), port=None, family=socket.AF_INET)
        # all_ips = [ip[-1][0] for ip in interfaces]
        # for ip in all_ips:

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(20.0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # sock.bind((ip, 0))
        sock.sendto(data, ('255.255.255.255', port))
        result, sender = sock.recvfrom(4)
        sock.close()

        result = int.from_bytes(result, 'little')
        ps4_ip, _ = sender

        return ps4_ip if result == magic else None

    @staticmethod
    async def send_ps4debug(host: str, port: int = 9020, file_path: str = 'ps4debug.bin'):
        """
        Sends the ps4debug 1.0.15 by ctn and golden to the PlayStation 4 system.
        @param host: Host to send the payload to.
        @param port: Port to send the payload to. Usually 9020 or 9090 (GoldHEN).
        @param file_path: File path to the ps4debug.bin file.
        @return: None
        """
        with open(file_path, 'rb') as f:
            content = f.read()

        reader, writer = await asyncio.open_connection(host, port)
        writer.write(content)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    @contextlib.asynccontextmanager
    async def memory(self, pid, length: int = 4096) -> AllocatedMemoryContext:
        """
        Context manager to manage allocated memory
        @param pid: Process id
        @param length: Length in bytes to allocate
        @return: A context to manage the allocated memory
        """
        address = await self.allocate_memory(pid, length)
        yield AllocatedMemoryContext(self, pid, length, address)
        await self.free_memory(pid, address, length)

    @contextlib.asynccontextmanager
    async def debugger(self, pid, port: int = 755, resume: bool = False) -> DebuggingContext:
        """
        Returns a debugging context to use for debugging a process
        @param port: Port the server should listen to debug events on.
        @param pid: Process id
        @param resume: If true, will automatically resume the processes.
        @return: Debugging context
        """
        context = DebuggingContext(self, pid)

        if self.debug_server is None:
            self.debug_server = await asyncio.start_server(context.debug_connected, '0.0.0.0', port)

        pid_bytes = pid.to_bytes(4, 'little')
        status = await self.send_command(commands.DEBUG_ATTACH, pid_bytes)

        if status != ResponseCode.SUCCESS:
            return

        if resume:
            await context.resume_process()

        yield context

        status = await self.send_command(commands.DEBUG_DETACH)

        if status == ResponseCode.SUCCESS:
            context.stop_flag.set()

            async with self.debug_server:
                self.debug_server.close()
                await self.debug_server.wait_closed()
                self.debug_server = None

    async def get_status(self, reader: asyncio.StreamReader | None = None) -> ResponseCode:
        """
        Returns the ps4debug status code. Do not use when not necessary as it blocks the IO.
        @param reader: StreamReader instance. If None, a new one is created.
        @return: Response code
        """
        status_bytes = await self.__recv_all(4, reader=reader)
        return ResponseCode.from_bytes(status_bytes)

    async def send_command(self, code: int, payload: bytes | bytearray | None = None, status: bool = True,
                           reader: asyncio.StreamReader | None = None,
                           writer: asyncio.StreamWriter | None = None) -> ResponseCode | None:
        """
        Sends a raw ps4debug command to the system.
        @param code: Command
        @param payload: Extra data
        @param status: If True, calls get_status and returns the status.
        @param reader: StreamReader instance. If None, a new one is created.
        @param writer: StreamWriter instance. If None, a new one is created.
        @return:
        """
        if reader is None or writer is None:
            async with self.pool.get_socket() as (new_reader, new_writer):
                return await self.send_command(code, payload, status,
                                               reader=reader or new_reader,
                                               writer=writer or new_writer)

        payload_length = len(payload) if payload else 0
        header = core.PS4DebugCommandHeader.build({'code': code, 'length': payload_length})

        writer.write(header)
        if payload and len(payload):
            writer.write(payload)
        await writer.drain()

        return await self.get_status(reader=reader) if status else None

    async def reboot(self):
        """
        Reboots the system.
        @return: None
        """
        await self.send_command(commands.CONSOLE_REBOOT)

    async def get_version(self) -> str:
        """
        Gets the remote ps4debug version running on the PS4.
        @return: Version string
        """
        async with self.pool.get_socket() as (reader, writer):
            await self.send_command(commands.VERSION, status=False, reader=reader, writer=writer)

            length = construct.Int32ul.parse(await self.__recv_all(4, reader=reader))
            version = await self.__recv_all(length, reader=reader)
        return version.decode('ascii')

    async def get_console_info(self) -> ResponseCode:
        """
        Retrieves the console information
        @return: Response code
        """
        async with self.pool.get_socket() as (reader, writer):
            return await self.send_command(commands.CONSOLE_INFO, reader=reader, writer=writer)

    async def print(self, text: str, encoding: str = 'utf8') -> ResponseCode:
        """
        Prints a message to the console
        @param text: Text to print
        @param encoding: Encoding to use
        @return: Response code
        """
        if text is None:
            return ResponseCode.DATA_NULL

        text += '' if text.endswith('\0') else '\0'
        text = text.encode(encoding)
        text_length = len(text).to_bytes(4, 'little')

        async with self.pool.get_socket() as (reader, writer):
            await self.send_command(commands.CONSOLE_PRINT, text_length, status=False, reader=reader, writer=writer)
            writer.write(text)
            await writer.drain()

            return await self.get_status(reader=reader)

    async def notify(self, text: str, notification_type: int = 222, encoding: str = 'utf8') -> ResponseCode:
        """
        Send a notification popup to
        @param text: Text to display
        @param notification_type: Type of notification to display. 222 represents the text without any formatting.
        @param encoding: Encoding to use
        @return: Response code
        """
        if text is None:
            return ResponseCode.DATA_NULL

        text += '' if text.endswith('\0') else '\0'
        text = text.encode(encoding)
        payload = core.NotifyPayload.build({
            'type': notification_type,
            'length': len(text)
        })

        async with self.pool.get_socket() as (reader, writer):
            await self.send_command(commands.CONSOLE_NOTIFY, payload, status=False, reader=reader, writer=writer)
            writer.write(text)
            await writer.drain()

            return await self.get_status(reader=reader)

    async def get_processes(self) -> list[core.Process]:
        """
        Retrieves a list of processes running on the system.
        @return: List of Process instances. The list will be empty if the command failed.
        """
        async with self.pool.get_socket() as (reader, writer):
            entry_size = core.Process.sizeof()
            status = await self.send_command(commands.PROC_LIST, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return []

            count = construct.Int32ul.parse(await self.__recv_all(4, reader=reader))
            data = await self.__recv_all(count * entry_size, reader=reader)

        return list(construct.Array(count, core.Process).parse(data))

    async def get_process_info(self, pid: int) -> core.ProcessInfo:
        """
        Retrieves information about a running process.
        @param pid: Process id
        @return: ProcessInfo instance or None if unsuccessful
        """
        async with self.pool.get_socket() as (reader, writer):
            entry_size = core.ProcessInfo.sizeof()
            data = construct.Int32ul.build(pid)
            status = await self.send_command(commands.PROC_INFO, data, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return

            data = await self.__recv_all(entry_size, reader=reader)
        return core.ProcessInfo.parse(data)

    async def get_process_maps(self, pid: int) -> list[core.ProcessMap]:
        """
        Retrieves all memory maps in the running process.
        @param pid: Process id
        @return: List of ProcessMap instances. The list will be empty if the command failed.
        """
        async with self.pool.get_socket() as (reader, writer):
            entry_size = 58
            payload = pid.to_bytes(4, 'little')
            status = await self.send_command(commands.PROC_MAPS, payload, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return []

            count = construct.Int32ul.parse(await self.__recv_all(4, reader=reader))
            data = await self.__recv_all(count * entry_size, reader=reader)

        maps = list(construct.Array(count, core.ProcessMap).parse(data))
        return maps

    async def allocate_memory(self, pid: int, length: int = 4096) -> int | None:
        """
        Allocates memory in the remote process.
        @param pid: Process id
        @param length: Length in bytes
        @return: The starting address of your memory section or None if the command failed.
        """
        async with self.pool.get_socket() as (reader, writer):
            payload = core.AllocateMemoryPayload.build({'pid': pid, 'length': length})
            status = await self.send_command(commands.PROC_ALLOC, payload, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return

            address = construct.Int64ul.parse(await self.__recv_all(8, reader=reader))
        return address

    async def free_memory(self, pid: int, address: int, length: int = 4096) -> ResponseCode:
        """
        Frees a previously allocated memory section in the remote process.
        @param pid: Process id
        @param address: Starting address of the memory section
        @param length: Length in bytes
        @return: Response code
        """
        async with self.pool.get_socket() as (reader, writer):
            payload = core.FreeMemoryPayload.build({'pid': pid, 'address': address, 'length': length})
            return await self.send_command(commands.PROC_FREE, payload, reader=reader, writer=writer)

    async def change_protection(self, pid: int, address: int, length: int, prot: core.VMProtection) -> ResponseCode:
        """
        Changes the protection flags of a memory section.
        @param pid: Process id
        @param address: Starting address of the memory section
        @param length: Length in bytes
        @param prot: New protection flags
        @return: Response code
        """
        async with self.pool.get_socket() as (reader, writer):
            payload = core.ChangeMemoryProtectionPayload.build({
                'pid': pid,
                'address': address,
                'length': length,
                'prot': prot.value,
            })
            return await self.send_command(commands.PROC_PROTECT, payload, reader=reader, writer=writer)

    async def install_rpc(self, pid: int,
                          reader: asyncio.StreamReader | None = None,
                          writer: asyncio.StreamWriter | None = None) -> int | None:
        """
        Writes a small program to the process' memory to allow execution of remote procedures
        @param pid: Process id
        @param reader: StreamReader to use, leave empty to create a new one.
        @param writer: StreamWriter to use, leave empty to create a new one.
        @return: The starting address of the RPC stub or None if the command failed.
        """
        if reader is None or writer is None:
            async with self.pool.get_socket() as (new_reader, new_writer):
                return await self.install_rpc(pid, reader=reader or new_reader, writer=writer or new_writer)

        pid_bytes = pid.to_bytes(4, 'little')
        status = await self.send_command(commands.PROC_INSTALL, pid_bytes, reader=reader, writer=writer)

        if status != ResponseCode.SUCCESS:
            return

        return construct.Int64ul.parse(await self.__recv_all(8, reader=reader))

    async def find_rpc(self, pid: int, start: int = 0x4000, end: int = 0xFFFFFFFF, step: int = 0x4000,
                       reader: asyncio.StreamReader | None = None,
                       writer: asyncio.StreamWriter | None = None) -> int | None:
        """
        Attempts to find the RPC-stub in the remote memory.
        @param pid: Process id
        @param start: Start address
        @param end: End address.
        @param step: Increment between search.
        @param reader: StreamReader to use, leave empty to create a new one.
        @param writer: StreamWriter to use, leave empty to create a new one.
        @return: Address of the RPC-stub if successful, otherwise None.
        """
        if reader is None or writer is None:
            async with self.pool.get_socket() as (new_reader, new_writer):
                return await self.find_rpc(pid, start, end, step,
                                           reader=reader or new_reader,
                                           writer=writer or new_writer)

        search = b'\x52\x53\x54\x42\xA3'
        address = start
        while address < end:
            bytes_ = await self.read_memory(pid, address, len(search), reader=reader, writer=writer)
            if bytes_ == search:
                return address
            address += step
        return

    async def get_rpc(self, pid: int,
                      reader: asyncio.StreamReader | None = None,
                      writer: asyncio.StreamWriter | None = None) -> int | None:
        """
        Finds or installs the RPC-stub and returns the address
        @param pid: Process id
        @param reader: StreamReader to use, leave empty to create a new one.
        @param writer: StreamWriter to use, leave empty to create a new one.
        @return: Address of the RPC-stub or None if unsuccessful
        """
        if reader is None or writer is None:
            async with self.pool.get_socket() as (new_reader, new_writer):
                return await self.get_rpc(pid, reader=reader or new_reader, writer=writer or new_writer)

        return (await self.find_rpc(pid, reader=reader, writer=writer) or
                await self.install_rpc(pid, reader=reader, writer=writer))

    async def call(self, pid: int, address: int, *args, **kwargs) -> tuple | None:
        """
        Executes a remote procedure and returns the rax register it ended with.
        Parameters are limited to 48 bytes and are split across rdi, rsi, rdx, rcx, rbx and rax in that order.
        If no rpc stub is given, a new one will be allocated
        @param pid: Process id
        @param address: Address to start remote execution on
        @param args: Your parameters to send to the remote procedure
        @param kwargs: Additional options
        @keyword parameter_format: Struct format of the parameters.
            Defaults to x 8 byte integers with x being the amount of parameters you provide
        @keyword output_format: Struct format of the result. Defaults to one 8 byte integer.
        @keyword rpc_stub: RPC stub previously written by the install_rpc method.
        @return: rax register unpacked with the output_format or None if the command failed.
            Do note that the result will always be a tuple, even if the result is only one element.
        """
        async with self.pool.get_socket() as (reader, writer):
            parameter_format = kwargs.get('parameter_format', f'<{len(args)}Q')
            output_format = kwargs.get('output_format', '<Q')
            rpc_stub = kwargs.get('rpc_stub')
            rpc_stub = rpc_stub or await self.get_rpc(pid, reader=reader, writer=writer)

            assert struct.calcsize(parameter_format) <= core.CallPayload.parameters.sizeof()
            assert struct.calcsize(output_format) <= core.CallResult.rax.sizeof()

            parameters = bytearray(core.CallPayload.parameters.sizeof())
            struct.pack_into(parameter_format, parameters, 0, *args)

            data = core.CallPayload.build({
                'pid': pid,
                'rpc_stub': rpc_stub,
                'address': address,
                'parameters': parameters,
            })

            status = await self.send_command(commands.PROC_CALL, data, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return

            result = await self.__recv_all(core.CallResult.sizeof(), reader=reader)
            result = core.CallResult.parse(result)

            missing_bytes = 8 - struct.calcsize(output_format)
            output_format += 'x' * missing_bytes

            rax = bytearray(result.rax)
            rax = struct.unpack_from(output_format, rax, 0)
            return rax

    async def load_elf(self, pid: int, elf_path: str) -> ResponseCode:
        """
        Loads an ELF file and sends it to the PS4 to load.
        @param pid: Process id
        @param elf_path: Path to the ELF file
        @return: Response code
        """
        with open(elf_path, 'rb') as file:
            elf_bytes = file.read()

        async with self.pool.get_socket() as (reader, writer):
            payload = core.LoadELFPayload.build({
                'pid': pid,
                'length': len(elf_bytes)
            })
            status = await self.send_command(commands.PROC_ELF, payload, reader=reader, writer=writer)

            if status == ResponseCode.SUCCESS:
                writer.write(elf_bytes)
                await writer.drain()
                status = await self.get_status(reader=reader)

        return status

    async def read_memory(self, pid: int, address: int, length: int,
                          reader: asyncio.StreamReader | None = None,
                          writer: asyncio.StreamWriter | None = None) -> bytearray | bytes | None:
        """
        Reads the raw memory in bytes.
        @param pid: Process id.
        @param address: Starting address.
        @param length: Length in bytes.
        @param reader: StreamReader to use, leave empty to create one.
        @param writer: StreamWriter to use, leave empty to create one.
        @return: The bytes read or None if the command failed.
        """
        if reader is None or writer is None:
            async with self.pool.get_socket() as (new_reader, new_writer):
                return await self.read_memory(pid, address, length,
                                              reader=reader or new_reader,
                                              writer=writer or new_writer)

        payload = core.MemoryPayload.build({
            'pid': pid,
            'address': address,
            'length': length,
        })
        status = await self.send_command(commands.PROC_READ, payload, reader=reader, writer=writer)

        if status != ResponseCode.SUCCESS:
            return

        return await self.__recv_all(length, reader=reader)

    async def read_struct(self, pid: int, address: int,
                          structure: str | struct.Struct | construct.Struct) -> tuple | construct.Container | None:
        """
        Reads a struct from memory.
        @param pid: Process id.
        @param address: Starting address.
        @param structure: The Struct instance or a struct format string.
        @return: Your desired struct or None if the command failed.
            The return value will always be packed in a tuple regardless of length.
        """
        if isinstance(structure, construct.Struct):
            data = await self.read_memory(pid, address, structure.sizeof())
            return structure.parse(data) if data is not None else None
        elif isinstance(structure, struct.Struct):
            data = await self.read_memory(pid, address, structure.size)
            return structure.unpack(data) if data is not None else None
        elif isinstance(structure, str):
            data = await self.read_memory(pid, address, struct.calcsize(structure))
            return struct.unpack(structure, data) if data is not None else None

    async def read_text(self, pid: int, address: int, encoding: str = 'ascii', **kwargs) -> str | None:
        """
        Reads a string from memory.
        @param pid: Process id.
        @param address: Starting address.
        @param encoding: Encoding to use.
        @param kwargs: Additional options.
        @keyword length: Length of the string. If unset memory will be read until a terminating null byte is found.
        @keyword chunk_size: Used if length is unset. The chunk determines how much memory is read at a time.
        @return: Decoded string or None if the command failed
        """
        async with self.pool.get_socket() as (reader, writer):
            length = kwargs.get('length')
            if length:
                data = await self.read_memory(pid, address, length, reader=reader, writer=writer)
                return data.decode(encoding)

            chunk_size = kwargs.get('chunk_size', 64)
            chunk = await self.read_memory(pid, address, chunk_size, reader=reader, writer=writer)
            data = chunk

            while b'\x00' not in chunk:
                chunk = await self.read_memory(pid, address + len(data), chunk_size, reader=reader, writer=writer)
                data += chunk

            data = data[:data.index(b'\0')]
            return data.decode(encoding)

    async def write_memory(self, pid: int, address: int, value: bytearray | bytes,
                           reader: asyncio.StreamReader | None = None,
                           writer: asyncio.StreamWriter | None = None) -> ResponseCode:
        """
        Writes the raw memory in bytes to an address.
        @param pid: Process id.
        @param address: Starting address.
        @param value: Bytes to write.
        @param reader: StreamReader to use, leave empty to create one.
        @param writer: StreamWriter to use, leave empty to create one.
        @return: Response code.
        """
        if reader is None or writer is None:
            async with self.pool.get_socket() as (new_reader, new_writer):
                return await self.write_memory(pid, address, value,
                                               reader=reader or new_reader,
                                               writer=writer or new_writer)

        payload = core.MemoryPayload.build({
            'pid': pid,
            'address': address,
            'length': len(value),
        })
        status = await self.send_command(commands.PROC_WRITE, payload, reader=reader, writer=writer)

        if status != ResponseCode.SUCCESS:
            return status

        writer.write(value)
        await writer.drain()
        return await self.get_status(reader=reader)

    async def write_struct(self, pid: int, address: int,
                           structure: str | struct.Struct | construct.Struct, *value) -> ResponseCode:
        """
        Writes a struct to an address.
        @param pid: Process id.
        @param address: Starting address.
        @param structure: The Struct instance or a struct format string.
        @param value: Struct data to write
        @return: Response code.
        """
        data = None

        if isinstance(structure, construct.Struct):
            data = structure.build(*value)
        elif isinstance(structure, struct.Struct):
            data = structure.pack(*value)
        elif isinstance(structure, str):
            data = struct.pack(structure, *value)

        async with self.pool.get_socket() as (reader, writer):
            return await self.write_memory(pid, address, data, reader=reader, writer=writer)

    async def write_text(self, pid: int, address: int, value: str,
                         encoding: str = 'ascii',
                         null_terminated: bool = True) -> ResponseCode:
        """
        Writes a text to an address.
        @param pid: Process id.
        @param address: Starting address.
        @param value: String to write.
        @param encoding: Encoding to use.
        @param null_terminated: Automatically append trailing null character.
        @return: Response code.
        """
        async with self.pool.get_socket() as (reader, writer):
            if value is None:
                return ResponseCode.DATA_NULL

            value += '' if value.endswith('\0') or not null_terminated else '\0'
            value = value.encode(encoding)

            return await self.write_memory(pid, address, value, reader=reader, writer=writer)

    async def get_kernel_base(self) -> int | None:
        """
        Retrieves the base address of the kernel.
        @return: Base address of the kernel if successful, None otherwise
        """
        async with self.pool.get_socket() as (reader, writer):
            status = await self.send_command(commands.KERN_BASE, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return

            return construct.Int64ul.parse(await self.__recv_all(8, reader=reader))

    async def read_kernel_memory(self, address: int, length: int) -> bytearray | None:
        """
        Read kernel memory.
        @param address: Address to read from
        @param length: Length in bytes
        @return: Bytes if successful, otherwise None
        """
        async with self.pool.get_socket() as (reader, writer):
            data = core.KernelMemoryPayload.build({
                'address': address,
                'length': length,
            })
            status = await self.send_command(commands.KERN_READ, data, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return

            return await self.__recv_all(length, reader=reader)

    async def write_kernel_memory(self, address: int, value: bytearray | bytes) -> ResponseCode:
        """
        Write to kernel memory. Be cautious when using this!
        @param address: Starting address.
        @param value: Bytes to write.
        @return: Response code
        """
        async with self.pool.get_socket() as (reader, writer):
            data = core.KernelMemoryPayload.build({
                'address': address,
                'length': len(value),
            })
            status = await self.send_command(commands.KERN_WRITE, data, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return status

            writer.write(value)
            await writer.drain()

            return await self.get_status(reader=reader)

    # Wrappers
    read_bool: Callable[[int, int], Coroutine[bool]] = functools.partialmethod(__read_type, structure='<?')
    read_char: Callable[[int, int], Coroutine[str]] = functools.partialmethod(__read_type, structure='<c')
    read_byte: Callable[[int, int], Coroutine[int]] = functools.partialmethod(__read_type, structure='<b')
    read_ubyte: Callable[[int, int], Coroutine[int]] = functools.partialmethod(__read_type, structure='<B')
    read_int16: Callable[[int, int], Coroutine[int]] = functools.partialmethod(__read_type, structure='<h')
    read_uint16: Callable[[int, int], Coroutine[int]] = functools.partialmethod(__read_type, structure='<H')
    read_int32: Callable[[int, int], Coroutine[int]] = functools.partialmethod(__read_type, structure='<i')
    read_uint32: Callable[[int, int], Coroutine[int]] = functools.partialmethod(__read_type, structure='<I')
    read_int64: Callable[[int, int], Coroutine[int]] = functools.partialmethod(__read_type, structure='<q')
    read_uint64: Callable[[int, int], Coroutine[int]] = functools.partialmethod(__read_type, structure='<Q')
    read_float: Callable[[int, int], Coroutine[float]] = functools.partialmethod(__read_type, structure='<f')
    read_double: Callable[[int, int], Coroutine[float]] = functools.partialmethod(__read_type, structure='<d')

    write_bool: Callable[[int, int, bool], Coroutine[ResponseCode]] = functools.partialmethod(__write_type, structure='<?')
    write_char: Callable[[int, int, str], Coroutine[ResponseCode]] = functools.partialmethod(__write_type, structure='<c')
    write_byte: Callable[[int, int, int], Coroutine[ResponseCode]] = functools.partialmethod(__write_type, structure='<b')
    write_ubyte: Callable[[int, int, int], Coroutine[ResponseCode]] = functools.partialmethod(__write_type, structure='<B')
    write_int16: Callable[[int, int, int], Coroutine[ResponseCode]] = functools.partialmethod(__write_type, structure='<h')
    write_uint16: Callable[[int, int, int], Coroutine[ResponseCode]] = functools.partialmethod(__write_type, structure='<H')
    write_int32: Callable[[int, int, int], Coroutine[ResponseCode]] = functools.partialmethod(__write_type, structure='<i')
    write_uint32: Callable[[int, int, int], Coroutine[ResponseCode]] = functools.partialmethod(__write_type, structure='<I')
    write_int64: Callable[[int, int, int], Coroutine[ResponseCode]] = functools.partialmethod(__write_type, structure='<q')
    write_uint64: Callable[[int, int, int], Coroutine[ResponseCode]] = functools.partialmethod(__write_type, structure='<Q')
    write_float: Callable[[int, int, float], Coroutine[ResponseCode]] = functools.partialmethod(__write_type, structure='<f')
    write_double: Callable[[int, int, float], Coroutine[ResponseCode]] = functools.partialmethod(__write_type, structure='<d')

    async def scan_uint8(self, pid: int, compare_type: core.ScanCompareType,
                         value: int, value2: int | None = None) -> list[int]:
        """
        Scans the memory remotely for certain addresses.
        @param pid: Process id
        @param compare_type: Method of comparing the values
        @param value: Unsigned byte [0;255]
        @param value2: Only required for certain compare types like BiggerThan.
        @return: List of matching addresses
        """
        scan_value_type = 0
        value_type_size = 1
        values_required = core.ScanCompareType.parameters(compare_type)

        if values_required == 2 and value2 is None:
            raise PS4DebugException('This compare type requires two values but only one was given.')

        header_struct = struct.Struct('<i2Bi')
        values_struct = struct.Struct('<' + 'B' * values_required)

        header = header_struct.pack(pid, scan_value_type, compare_type.value, value_type_size * values_required)
        values = values_struct.pack(*[value, value2][:values_required])

        async with self.pool.get_socket() as (reader, writer):
            status = await self.send_command(commands.PROC_SCAN, header, reader=reader, writer=writer)

            if status != ResponseCode.SUCCESS:
                return []

            writer.write(values)
            await writer.drain()
            status = await self.get_status(reader=reader)

            if status != ResponseCode.SUCCESS:
                return []

            addresses = []
            end = 2 ** 64 - 1

            reader: asyncio.StreamReader
            address = int.from_bytes(await reader.readexactly(8), 'little')
            print(address)

            while address < end:
                addresses.append(address)
                print(address)
                address = int.from_bytes(await reader.readexactly(8), 'little')
                print(len(addresses))

            return addresses

    async def __scan_uint8(self, pid: int, search_value: int, start_address: int, stop_address: int,
                             chunk_size: int = 4096) -> set[int]:
        value_struct = struct.Struct('<b')

        async def __scan(_start, _stop) -> set[int]:
            async with self.pool.get_socket() as (reader, writer):
                addresses = set()

                for chunk_address in range(_start, _stop, chunk_size):
                    chunk = await self.read_memory(pid, chunk_address, chunk_size, reader=reader, writer=writer)

                    for i in range(len(chunk)):
                        chunk_value = value_struct.unpack(chunk[i:i + value_struct.size])[0]
                        chunk_value_address = chunk_address + i

                        if chunk_value == search_value:
                            addresses.add(chunk_value_address)
                            all_addresses = (_stop - _start)
                            found_addresses = (chunk_address - _start)
                            print(found_addresses / all_addresses * 100)

                return addresses

        task_count = 5
        task_stride = (stop_address - start_address) // task_count

        parts = [(start_address + i * task_stride, start_address + (i + 1) * task_stride) for i in range(task_count)]
        tasks = [asyncio.create_task(__scan(a, b)) for a, b in parts]

        results = await asyncio.gather(*tasks)
        return set().union(*results)
