from .core import ResponseCode
from .exceptions import PS4DebugException
import ps4debug.core as core
import ps4debug.commands as commands
import socket
import struct
import functools
import asyncio


class AllocatedMemoryContext(object):
    """Context for handling memory allocation and freeing."""

    def __init__(self, ps4debug, pid, length):
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

    async def __aenter__(self):
        self.address = await self.ps4debug.allocate_memory(self.pid, self.length)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.ps4debug.free_memory(self.pid, self.address, self.length)

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
    def __init__(self, ps4debug, pid: int, port: int = 755, resume: bool = False):
        super(DebuggingContext, self).__init__()
        self.ps4debug: PS4Debug = ps4debug
        self.port = port
        self.pid = pid
        self.__resume = resume

    async def __aenter__(self):
        self.server = await asyncio.start_server(self.__connected, '0.0.0.0', 755)
        await self.ps4debug.attach_debugger(self.pid, self.__resume)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.ps4debug.detach_debugger()
        async with self.server:
            self.server.close()
            await self.server.wait_closed()

    async def resume(self):
        await self.ps4debug.resume_process()

    async def stop(self):
        await self.ps4debug.stop_process()

    async def __connected(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        print(addr)
        while True:
            data = await reader.read(4)
            print(f"Received {data}")
            if reader.at_eof():
                break


class PS4Debug(object):
    """Offers standard ps4debug methods."""
    magic = 0xFFAABBCC
    max_breakpoints = 10
    max_watchpoints = 4

    def __init__(self, host: str = None, port: int = 744):
        """
        Create a new PS4Debug instance.
        @param host: IP address or hostname of the PS4. If this is unset the network will be searched for a PS4.
        @param port: Port. defaults to 744 for ps4debug, set this if port forwarding is in use.
        """
        host = host or self.find_ps4()
        if not host:
            raise PS4DebugException('No host given and no PS4 found in network')

        self.endpoint = (host, port)
        self.connected = False
        self.reader: asyncio.StreamReader
        self.writer: asyncio.StreamWriter

        # Structs
        self.__header_struct = struct.Struct('<3I')
        self.__notify_struct = struct.Struct('<2I')
        self.__process_struct = struct.Struct('<32sI')
        self.__process_map_struct = struct.Struct('<32s3QH')
        self.__process_info_struct = struct.Struct('<i40s64s16s64s')
        self.__allocate_struct = struct.Struct('<2I')
        self.__free_struct = struct.Struct('<iQI')
        self.__change_prot_struct = struct.Struct('<iQ2I')
        self.__call_header_struct = struct.Struct('<i2Q')
        self.__memory_header_struct = struct.Struct('<iQI')
        self.__elf_struct = struct.Struct('<2I')

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, type_, value, traceback):
        await self.disconnect()

    async def __recv_int32(self):
        data = await self.__recv_all(4)
        data = int.from_bytes(data, 'little')
        return data

    async def __recv_int64(self):
        data = await self.__recv_all(8)
        data = int.from_bytes(data, 'little')
        return data

    async def __recv_all(self, length):
        received = 0
        data = bytearray()

        while received < length:
            packet = await self.reader.read(length - received)
            if self.reader.at_eof():
                break
            received += len(packet)
            data.extend(packet)

        if received != length:
            raise PS4DebugException(f'Unable to receive {length} bytes.')

        return data

    def __create_header(self, code, payload_length):
        """
        Creates the PS4Debug header (magic, command, payload length)
        @param code: PS4 debug command constant
        @param payload_length: Amount of parameters for the command
        @return: Bytes of the header
        """
        header = self.__header_struct.pack(self.magic, code, payload_length)
        return header

    async def __read_type(self, pid, address, structure):
        return (await self.read_struct(pid, address, structure))[0]

    async def __write_type(self, pid, address, value, structure):
        return await self.write_struct(pid, address, structure, value)

    @classmethod
    def find_ps4(cls) -> str | None:
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

    @classmethod
    def send_ps4debug(cls, host: str, port: int = 9020, file_path: str = 'ps4debug.bin'):
        # TODO make async
        with open(file_path, 'rb') as f:
            content = f.read()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30.0)
            sock.connect((host, port))
            sock.sendall(content)
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

    def memory(self, pid, length) -> AllocatedMemoryContext:
        """
        Context manager to manage allocated memory
        @param pid: Process id
        @param length: Length in bytes to allocate
        @return: A context to manage the allocated memory
        """
        return AllocatedMemoryContext(self, pid, length)

    def debugger(self, pid: int, debug_port: int = 755, resume: bool = False) -> DebuggingContext:
        """
        Returns a debugging context to use for debugging a process
        @param debug_port: Port the server should listen to debug events on.
        @param pid: Process id
        @param resume: If true, will automatically resume the processes.
        @return: Debugging context
        """
        return DebuggingContext(self, pid, debug_port, resume)

    async def get_status(self) -> ResponseCode:
        status_bytes = await self.__recv_all(4)
        return ResponseCode.from_bytes(status_bytes)

    async def send_command(self, code, payload=None, status=True) -> ResponseCode | None:
        payload_length = len(payload) if payload else 0
        header = self.__create_header(code, payload_length)

        self.writer.write(header)
        await self.writer.drain()  # Might not needed
        if payload and len(payload):
            self.writer.write(payload)
            await self.writer.drain()

        return await self.get_status() if status else None

    async def connect(self):
        """
        Connects to the PS4
        @return: None
        """
        host, port = self.endpoint
        self.reader, self.writer = await asyncio.open_connection(host, port)
        self.connected = True

    async def disconnect(self):
        """
        Disconnects from the PS4
        @return: None
        """
        self.writer.close()
        await self.writer.wait_closed()
        self.connected = False

    async def reboot(self):
        """
        Reboots the system.
        @return: None
        """
        await self.send_command(commands.CONSOLE_REBOOT)
        await self.disconnect()

    async def get_version(self) -> str:
        """
        Gets the remote ps4debug version running on the PS4.
        @return: Version string
        """
        await self.send_command(commands.VERSION, status=False)

        length = await self.__recv_int32()
        version = await self.__recv_all(length)
        return version.decode('ascii')

    async def get_console_info(self) -> ResponseCode:
        """
        Retrieves the console information
        @return: Response code
        """
        return await self.send_command(commands.CONSOLE_INFO)

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

        await self.send_command(commands.CONSOLE_PRINT, text_length, status=False)
        self.writer.write(text)
        await self.writer.drain()

        return await self.get_status()

    async def notify(self, text: str, notification_type: int = 222, encoding: str = 'utf8') -> ResponseCode:
        """
        Send a notification popup to
        @param text: Text to print
        @param notification_type: Type of notification to display. 222 represents the text without any formatting.
        @param encoding: Encoding to use
        @return: Response code
        """
        if text is None:
            return ResponseCode.DATA_NULL

        text += '' if text.endswith('\0') else '\0'
        text = text.encode(encoding)
        payload = self.__notify_struct.pack(notification_type, len(text))

        await self.send_command(commands.CONSOLE_NOTIFY, payload, status=False)
        self.writer.write(text)
        await self.writer.drain()

        return await self.get_status()

    async def get_processes(self) -> list[core.Process]:
        """
        Retrieves a list of processes running on the system.
        @return: List of Process instances. The list will be empty if the command failed.
        """

        def parse_entry(entry_bytes) -> core.Process:
            name, pid = self.__process_struct.unpack(entry_bytes)
            name = name.rstrip(b'\x00').decode('ascii')
            return core.Process(name=name, pid=pid)

        entry_size = 36
        status = await self.send_command(commands.PROC_LIST)

        if status != ResponseCode.SUCCESS:
            return []

        count = await self.__recv_int32()
        data = await self.__recv_all(count * entry_size)

        return [parse_entry(data[i:i + entry_size]) for i in range(0, count * entry_size, entry_size)]

    async def get_process_info(self, pid: int) -> core.ProcessInfo | None:
        """
        Retrieves information about a running process.
        @param pid: Process id
        @return: ProcessInfo instance or None if unsuccessful
        """

        entry_size = 188
        pid_bytes = pid.to_bytes(4, 'little')
        status = await self.send_command(commands.PROC_INFO, pid_bytes)

        if status != ResponseCode.SUCCESS:
            return

        data = await self.__recv_all(entry_size)

        pid, name, path, title_id, content_id = self.__process_info_struct.unpack(data)
        name = name[:name.index(0)].decode('ascii')
        path = path[:path.index(0)].decode('ascii')
        title_id = title_id[:title_id.index(0)].decode('ascii')
        content_id = content_id[:content_id.index(0)].decode('ascii')

        return core.ProcessInfo(pid=pid, name=name, path=path, title_id=title_id, content_id=content_id)

    async def get_process_maps(self, pid: int) -> list[core.ProcessMap]:
        """
        Retrieves all memory maps in the running process.
        @param pid: Process id
        @return: List of ProcessMap instances. The list will be empty if the command failed.
        """

        def parse_entry(entry_bytes) -> core.ProcessMap:
            name, start, end, offset, prot = self.__process_map_struct.unpack(entry_bytes)
            name_end = name.index(0)
            name = entry_bytes[:name_end].decode('ascii')
            return core.ProcessMap(name=name, start=start, end=end, offset=offset, prot=prot)

        entry_size = 58
        payload = pid.to_bytes(4, 'little')
        status = await self.send_command(commands.PROC_MAPS, payload)

        if status != ResponseCode.SUCCESS:
            return []

        count = await self.__recv_int32()
        data = await self.__recv_all(count * entry_size)

        return [parse_entry(data[i:i + entry_size]) for i in range(0, count * entry_size, entry_size)]

    async def allocate_memory(self, pid: int, length: int) -> int | None:
        """
        Allocates memory in the remote process.
        @param pid: Process id
        @param length: Length in bytes
        @return: The starting address of your memory section or None if the command failed.
        """
        payload = self.__allocate_struct.pack(pid, length)
        status = await self.send_command(commands.PROC_ALLOC, payload)

        if status != ResponseCode.SUCCESS:
            return

        address = await self.__recv_int64()
        return address

    async def free_memory(self, pid: int, address: int, length: int) -> ResponseCode:
        """
        Frees a previously allocated memory section in the remote process.
        @param pid: Process id
        @param address: Starting address of the memory section
        @param length: Length in bytes
        @return: Response code
        """
        payload = self.__free_struct.pack(pid, address, length)
        return await self.send_command(commands.PROC_FREE, payload)

    async def change_protection(self, pid: int, address: int, length: int, prot: core.VMProtection) -> ResponseCode:
        """
        Changes the protection flags of a memory section.
        @param pid: Process id
        @param address: Starting address of the memory section
        @param length: Length in bytes
        @param prot: New protection flags
        @return: Response code
        """
        payload = self.__change_prot_struct.pack(pid, address, length, prot.value)
        return await self.send_command(commands.PROC_PROTECT, payload)

    async def install_rpc(self, pid: int) -> int | None:
        """
        Writes a small program to the process' memory to allow execution of remote procedures
        @param pid: Process id
        @return: The starting address of the RPC stub or None if the command failed.
        """
        pid_bytes = pid.to_bytes(4, 'little')
        status = await self.send_command(commands.PROC_INSTALL, pid_bytes)

        if status != ResponseCode.SUCCESS:
            return

        return await self.__recv_int64()

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
        packet_size = 68
        result_size = 12

        parameter_format = kwargs.get('parameter_format', f'<{len(args)}Q')
        output_format = kwargs.get('output_format', '<Q')
        rpc_stub = kwargs.get('rpc_stub', self.install_rpc(pid))

        header_size = self.__call_header_struct.size
        payload_buffer = bytearray(packet_size)

        assert struct.calcsize(parameter_format) <= len(payload_buffer)
        assert struct.calcsize(output_format) <= 8

        self.__call_header_struct.pack_into(payload_buffer, 0, pid, rpc_stub, address)
        struct.pack_into(parameter_format, payload_buffer, header_size, *args)

        status = await self.send_command(commands.PROC_CALL, payload_buffer)

        if status != ResponseCode.SUCCESS:
            return

        missing_bytes = 8 - struct.calcsize(output_format)
        result = await self.__recv_all(result_size)

        pid = int.from_bytes(result[:4], 'little')
        rax = struct.unpack(output_format + 'x' * missing_bytes, result[4:])
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

        payload = self.__elf_struct.pack(pid, len(elf_bytes))
        status = await self.send_command(commands.PROC_ELF, payload)

        if status == ResponseCode.SUCCESS:
            self.writer.write(elf_bytes)
            await self.writer.drain()
            status = self.get_status()

        return status

    async def read_memory(self, pid: int, address: int, length: int) -> bytearray | bytes | None:
        """
        Reads the raw memory in bytes.
        @param pid: Process id.
        @param address: Starting address.
        @param length: Length in bytes.
        @return: The bytes read or None if the command failed.
        """
        payload = self.__memory_header_struct.pack(pid, address, length)
        status = await self.send_command(commands.PROC_READ, payload)

        if status != ResponseCode.SUCCESS:
            return

        return await self.__recv_all(length)

    async def read_struct(self, pid: int, address: int, structure: str | struct.Struct) -> tuple | None:
        """
        Reads a struct from memory.
        @param pid: Process id.
        @param address: Starting address.
        @param structure: The Struct instance or a struct format string.
        @return: Your desired struct or None if the command failed.
            The return value will always be packed in a tuple regardless of length.
        """
        if isinstance(structure, str):
            structure = struct.Struct(structure)

        data = await self.read_memory(pid, address, structure.size)
        return structure.unpack(data) if data else None

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
        length = kwargs.get('length')
        if length:
            data = await self.read_memory(pid, address, length)
            return data.decode(encoding)

        chunk_size = kwargs.get('chunk_size', 64)
        chunk = await self.read_memory(pid, address, chunk_size)
        data = chunk

        while b'\x00' not in chunk:
            chunk = await self.read_memory(pid, address + len(data), chunk_size)
            data += chunk

        data = data[:data.index(b'\0')]
        return data.decode(encoding)

    async def write_memory(self, pid: int, address: int, value: bytearray | bytes) -> ResponseCode:
        """
        Writes the raw memory in bytes to an address.
        @param pid: Process id.
        @param address: Starting address.
        @param value: Bytes to write.
        @return: Response code.
        """
        payload = self.__memory_header_struct.pack(pid, address, len(value))
        status = await self.send_command(commands.PROC_WRITE, payload)

        if status != ResponseCode.SUCCESS:
            return status

        self.writer.write(value)
        await self.writer.drain()
        return await self.get_status()

    async def write_struct(self, pid: int, address: int, structure: str | struct.Struct, *value) -> ResponseCode:
        """
        Writes a struct to an address.
        @param pid: Process id.
        @param address: Starting address.
        @param structure: The Struct instance or a struct format string.
        @param value: Struct data to write
        @return: Response code.
        """
        if isinstance(structure, str):
            structure = struct.Struct(structure)

        data = structure.pack(*value)
        return await self.write_memory(pid, address, data)

    async def write_text(self, pid: int, address: int, value: str, encoding: str = 'ascii') -> ResponseCode:
        """
        Writes a text to an address.
        @param pid: Process id.
        @param address: Starting address.
        @param value: String to write.
        @param encoding: Encoding to use.
        @return: Response code.
        """
        if value is None:
            return ResponseCode.DATA_NULL

        value += '' if value.endswith('\0') else '\0'
        value = value.encode(encoding)

        return await self.write_memory(pid, address, value)

    # Wrappers
    read_bool = functools.partialmethod(__read_type, structure='<?')
    read_char = functools.partialmethod(__read_type, structure='<c')
    read_byte = functools.partialmethod(__read_type, structure='<b')
    read_ubyte = functools.partialmethod(__read_type, structure='<B')
    read_int16 = functools.partialmethod(__read_type, structure='<h')
    read_uint16 = functools.partialmethod(__read_type, structure='<H')
    read_int32 = functools.partialmethod(__read_type, structure='<i')
    read_uint32 = functools.partialmethod(__read_type, structure='<I')
    read_int64 = functools.partialmethod(__read_type, structure='<q')
    read_uint64 = functools.partialmethod(__read_type, structure='<Q')
    read_float = functools.partialmethod(__read_type, structure='<f')
    read_double = functools.partialmethod(__read_type, structure='<d')

    write_bool = functools.partialmethod(__write_type, structure='<?')
    write_char = functools.partialmethod(__write_type, structure='<c')
    write_byte = functools.partialmethod(__write_type, structure='<b')
    write_ubyte = functools.partialmethod(__write_type, structure='<B')
    write_int16 = functools.partialmethod(__write_type, structure='<h')
    write_uint16 = functools.partialmethod(__write_type, structure='<H')
    write_int32 = functools.partialmethod(__write_type, structure='<i')
    write_uint32 = functools.partialmethod(__write_type, structure='<I')
    write_int64 = functools.partialmethod(__write_type, structure='<q')
    write_uint64 = functools.partialmethod(__write_type, structure='<Q')
    write_float = functools.partialmethod(__write_type, structure='<f')
    write_double = functools.partialmethod(__write_type, structure='<d')

    def scan_int32(self, pid: int, compare_type: core.ScanCompareType, *values) -> list[int]:
        bytes_value1 = struct.pack('<i', values[0]) if len(values) > 0 else b''
        bytes_value2 = struct.pack('<i', values[1]) if len(values) > 1 else b''
        length_value1 = len(bytes_value1)
        length_value2 = len(bytes_value2)

        old_timeout = self.sock.gettimeout()
        self.sock.settimeout(None)

        payload = struct.pack('<ibbI', pid, 0, compare_type.value, length_value1 + length_value2)
        status = self.send_command(commands.PROC_SCAN, payload)

        if status != ResponseCode.SUCCESS:
            return []

        self.sock.sendall(bytes_value1 + bytes_value2)
        status = self.get_status()

        if status != ResponseCode.SUCCESS:
            return []

        addresses = []
        address = self.__recv_int64()
        while address != 0xFFFFFFFFFFFFFFFF:
            addresses.append(address)
            address = self.__recv_int64()

        self.sock.settimeout(old_timeout)
        return addresses

    def scan(self, pid: int, compare_type: core.ScanCompareType, value_type: core.ScanValueType, *values) -> list[int]:
        """
        Scans the memory remotely for certain addresses
        @param pid: Process id
        @param compare_type: Way to compare the values
        @param value_type: Type of the values to compare
        @param values: Values depend on the compare type
        @return: List of addresses that fulfill the compare condition
        """
        pass

    # Unfinished

    async def attach_debugger(self, pid: int, resume: bool = False) -> ResponseCode:
        """
        Attaches the debugger to the process on the remote system and
        causes it to connect to the debugger port of this machine.
        Note that this will pause the processes on the system.
        @param pid: Process id.
        @param resume: If true, will automatically resume the processes.
        @return: Response code
        """
        # if self.is_debugged:
        #     return ResponseCode.ALREADY_DEBUG
        # self.is_debugged = True

        pid_bytes = pid.to_bytes(4, 'little')
        status = await self.send_command(commands.DEBUG_ATTACH, pid_bytes)

        if not resume or status != ResponseCode.SUCCESS:
            return status

        return await self.resume_process()

    async def detach_debugger(self) -> ResponseCode:
        """
        Detaches the debugger from the remote system.
        @return: Response code.
        """
        # if not self.is_debugged:
        #     return ResponseCode.DATA_NULL
        # self.is_debugged = False
        return await self.send_command(commands.DEBUG_DETACH)

    async def resume_process(self) -> ResponseCode:
        """
        Resumes all processes on the remote system.
        @return: Response code
        """
        return await self.send_command(commands.DEBUG_STOPGO, b'\x00\x00\x00\x00')

    async def stop_process(self) -> ResponseCode:
        """
        Stops all processes on the remote system.
        @return: Response code
        """
        return await self.send_command(commands.DEBUG_STOPGO, b'\x01\x00\x00\x00')

    def get_threads(self) -> list[int]:
        """

        @return:
        """

    def get_thread_info(self, lwpid: int) -> object:
        """

        @param lwpid:
        @return:
        """
        raise NotImplementedError()

    def breakpoint(self, index: int, enabled: bool, address: int) -> ResponseCode:
        """

        @param index:
        @param enabled:
        @param address:
        @return:
        """
        raise NotImplementedError()

    def watchpoint(self, index: int, enabled: bool, address: int, length: object, type_: object) -> ResponseCode:
        """

        @param index:
        @param enabled:
        @param address:
        @param length:
        @param type_:
        @return:
        """
        # length and type_ have to be new enums
        raise NotImplementedError()

    def get_debug_registers(self, lwpid: int) -> object:
        """

        @param lwpid:
        @return:
        """
        # Registers have to be implemented as a class
        raise NotImplementedError()

    def set_debug_registers(self, lwpid: int, registers: object) -> ResponseCode:
        """

        @param lwpid:
        @param registers:
        @return:
        """
        raise NotImplementedError()

    def get_float_registers(self, lwpid: int) -> object:
        """

        @param lwpid:
        @return:
        """
        raise NotImplementedError()

    def set_float_registers(self, lwpid: int, registers: object) -> ResponseCode:
        """

        @param lwpid:
        @param registers:
        @return:
        """
        raise NotImplementedError()

    def get_registers(self, lwpid: int) -> object:
        """

        @param lwpid:
        @return:
        """
        raise NotImplementedError()

    def set_registers(self, lwpid: int, registers: object) -> ResponseCode:
        """

        @param lwpid:
        @param registers:
        @return:
        """
        raise NotImplementedError()

    def get_kernel_base(self) -> int:
        """

        @return:
        """
        raise NotImplementedError()

    def read_kernel_memory(self, address: int, length: int) -> bytearray:
        """

        @param address:
        @param length:
        @return:
        """
        raise NotImplementedError()

    def write_kernel_memory(self, address: int, data: bytearray | bytes) -> ResponseCode:
        """

        @param address:
        @param data:
        @return:
        """
        raise NotImplementedError()

    def kill_process(self) -> ResponseCode:
        """

        @return:
        """
        raise NotImplementedError()

    def resume_thread(self, lwpid: int) -> ResponseCode:
        """

        @param lwpid:
        @return:
        """
        raise NotImplementedError()

    def stop_thread(self, lwpid: int) -> ResponseCode:
        """

        @param lwpid:
        @return:
        """
        raise NotImplementedError()

    def single_step(self) -> ResponseCode:
        """

        @return:
        """
        raise NotImplementedError()
