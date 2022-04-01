from typing import Optional, List, NamedTuple, Union
import socket
import struct
import enum
import functools

# PS4Debug commands
CMD_VERSION = 0xBD000001
CMD_PROC_LIST = 0xBDAA0001
CMD_PROC_READ = 0xBDAA0002
CMD_PROC_WRITE = 0xBDAA0003
CMD_PROC_MAPS = 0xBDAA0004
CMD_PROC_INSTALL = 0xBDAA0005
CMD_PROC_CALL = 0xBDAA0006
CMD_PROC_ELF = 0xBDAA0007
CMD_PROC_PROTECT = 0xBDAA0008
CMD_PROC_SCAN = 0xBDAA0009
CMD_PROC_INFO = 0xBDAA000A
CMD_PROC_ALLOC = 0xBDAA000B
CMD_PROC_FREE = 0xBDAA000C
CMD_DEBUG_ATTACH = 0xBDBB0001
CMD_DEBUG_DETACH = 0xBDBB0002
CMD_DEBUG_BREAKPT = 0xBDBB0003
CMD_DEBUG_WATCHPT = 0xBDBB0004
CMD_DEBUG_THREADS = 0xBDBB0005
CMD_DEBUG_STOPTHR = 0xBDBB0006
CMD_DEBUG_RESUMETHR = 0xBDBB0007
CMD_DEBUG_GETREGS = 0xBDBB0008
CMD_DEBUG_SETREGS = 0xBDBB0009
CMD_DEBUG_GETFPREGS = 0xBDBB000A
CMD_DEBUG_SETFPREGS = 0xBDBB000B
CMD_DEBUG_GETDBGREGS = 0xBDBB000C
CMD_DEBUG_SETDBGREGS = 0xBDBB000D
CMD_DEBUG_STOPGO = 0xBDBB0010
CMD_DEBUG_THRINFO = 0xBDBB0011
CMD_DEBUG_SINGLESTEP = 0xBDBB0012
CMD_KERN_BASE = 0xBDCC0001
CMD_KERN_READ = 0xBDCC0002
CMD_KERN_WRITE = 0xBDCC0003
CMD_CONSOLE_REBOOT = 0xBDDD0001
CMD_CONSOLE_END = 0xBDDD0002
CMD_CONSOLE_PRINT = 0xBDDD0003
CMD_CONSOLE_NOTIFY = 0xBDDD0004
CMD_CONSOLE_INFO = 0xBDDD0005


class ResponseCode(enum.Enum):
    """Raw response codes from the ps4debug payload."""

    SUCCESS = 0x80000000
    ERROR = 0xF0000001
    TOO_MUCH_DATA = 0xF0000002
    DATA_NULL = 0xF0000003
    ALREADY_DEBUG = 0xF0000004
    INVALID_INDEX = 0xF0000005

    @classmethod
    def from_bytes(cls, value):
        """
        Create a response object from received bytes.
        @param value: Byte string or a bytearray object.
        @return: Response code object or None if bytes were invalid.
        """
        decoded = int.from_bytes(value, 'little')
        return next((p for p in cls if p.value == decoded), None)


class VMProtection(enum.Enum):
    """Contains possible settings for memory protection."""

    VM_PROT_NONE = 0x00
    VM_PROT_READ = 0x01
    VM_PROT_WRITE = 0x02
    VM_PROT_EXECUTE = 0x04
    VM_PROT_DEFAULT = 0x03
    VM_PROT_ALL = 0x07
    VM_PROT_NO_CHANGE = 0x08
    VM_PROT_COPY = 0x10


class ScanCompareType(enum.Enum):
    ExactValue = 0
    FuzzyValue = 1
    BiggerThan = 2
    SmallerThan = 3
    ValueBetween = 4
    IncreasedValue = 5
    IncreasedValueBy = 6
    DecreasedValue = 7
    DecreasedValueBy = 8
    ChangedValue = 9
    UnchangedValue = 10
    UnknownInitialValue = 11

    @classmethod
    def to_byte(cls, compare_type):
        compare_type.value.to_bytes(1, 'little')


class ScanValueType(enum.Enum):
    UInt8 = 0
    Int8 = 1
    UInt16 = 2
    Int16 = 3
    UInt32 = 4
    Int32 = 5
    UInt64 = 6
    Int64 = 7
    Float = 8
    Double = 9
    ByteArray = 10
    String = 11


class Process(NamedTuple):
    name: str
    pid: int


class ProcessMap(NamedTuple):
    name: str
    start: int
    end: int
    offset: int
    prot: int


class ProcessInfo(NamedTuple):
    pid: int
    name: str
    path: str
    title_id: str
    content_id: str


class AllocatedMemoryContext(object):
    """Context for handling memory allocation and freeing."""

    def __init__(self, debugger, pid, length):
        """
        Create a new allocated memory context.
        @param debugger: PS4Debug instance.
        @param pid: process id.
        @param length: length in bytes.
        """
        super(AllocatedMemoryContext, self).__init__()
        self.debugger = debugger
        self.pid = pid
        self.length = length

    def __enter__(self):
        self.memory_address = self.debugger.allocate_memory(self.pid, self.length)
        return self.memory_address

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.debugger.free_memory(self.pid, self.memory_address, self.length)


class DebuggingContext(object):
    def __init__(self, debugger, pid):
        super(DebuggingContext, self).__init__()
        self.debugger = debugger
        self.pid = pid

    def __enter__(self):
        self.debugger.attach_debugger(self.pid)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.debugger.detach_debugger()


class PS4DebugException(Exception):
    def __init__(self, message):
        super(PS4DebugException, self).__init__(message)


class PS4Debug(object):
    """Offers standard ps4debug methods."""
    magic = 0xFFAABBCC
    max_breakpoints = 10
    max_watchpoints = 4

    def __init__(self, host: str = None, port: int = 744, debug_port: int = 755):
        """
        Create a new PS4Debug instance.
        @param host: IP address or hostname of the PS4. If this is unset the network will be searched for a PS4.
        @param port: Port. defaults to 744 for ps4debug, set this if port forwarding is in use.
        """
        host = host or self.find_ps4()
        if not host:
            raise PS4DebugException('No host given and no PS4 found in network')

        self.endpoint = (host, port)
        self.endpoint_debug = (host, debug_port)
        self.connected = False
        self.is_debugged = False
        self.sock = None

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

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, type_, value, traceback):
        self.disconnect()

    def __recv_int32(self):
        data = self.__recv_all(4)
        data = int.from_bytes(data, 'little')
        return data

    def __recv_int64(self):
        data = self.__recv_all(8)
        data = int.from_bytes(data, 'little')
        return data

    def __recv_all(self, length):
        received = 0
        data = bytearray()

        while received < length:
            packet = self.sock.recv(length - received)
            if not packet:
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

    def __read_type(self, pid, address, structure):
        return self.read_struct(pid, address, structure)[0]

    def __write_type(self, pid, address, value, structure):
        return self.write_struct(pid, address, structure, value)

    @classmethod
    def find_ps4(cls) -> Optional[str]:
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
    def send_ps4debug(cls, host: str, port: int = 9020):
        with open(r'ps4debug.bin', 'rb') as f:
            content = f.read()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30.0)
            sock.connect((host, port))
            sock.sendall(content)
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

    def get_status(self) -> ResponseCode:
        status_bytes = self.__recv_all(4)
        return ResponseCode.from_bytes(status_bytes)

    def send_command(self, code, payload=None, status=True) -> Optional[ResponseCode]:
        payload_length = len(payload) if payload else 0
        header = self.__create_header(code, payload_length)

        self.sock.sendall(header)
        if payload and len(payload):
            self.sock.sendall(payload)

        return self.get_status() if status else None

    def connect(self):
        """
        Connects to the PS4
        @return: None
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(30.0)
        self.sock.connect(self.endpoint)
        self.connected = True

    def disconnect(self):
        """
        Disconnects from the PS4
        @return: None
        """
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        self.connected = False

    def memory(self, pid, length) -> AllocatedMemoryContext:
        """
        Context manager to manage allocated memory
        @param pid: Process id
        @param length: Length in bytes to allocate
        @return: A context to manage the allocated memory
        """
        return AllocatedMemoryContext(self, pid, length)

    def reboot(self):
        """
        Reboots the system.
        @return: None
        """
        self.send_command(CMD_CONSOLE_REBOOT)
        self.connected = False

    def get_version(self) -> str:
        """
        Gets the remote ps4debug version running on the PS4.
        @return: Version string
        """
        self.send_command(CMD_VERSION, status=False)

        length = self.__recv_int32()
        version = self.__recv_all(length)
        return version.decode('ascii')

    def get_console_info(self) -> ResponseCode:
        """
        Retrieves the console information
        @return: Response code
        """
        return self.send_command(CMD_CONSOLE_INFO)

    def print(self, text: str, encoding: str = 'utf8') -> ResponseCode:
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

        self.send_command(CMD_CONSOLE_PRINT, text_length, status=False)
        self.sock.sendall(text)

        return self.get_status()

    def notify(self, text: str, notification_type: int = 222, encoding: str = 'utf8') -> ResponseCode:
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

        self.send_command(CMD_CONSOLE_NOTIFY, payload, status=False)
        self.sock.sendall(text)

        return self.get_status()

    def get_processes(self) -> List[Process]:
        """
        Retrieves a list of processes running on the system.
        @return: List of Process instances. The list will be empty if the command failed.
        """

        def parse_entry(entry_bytes) -> Process:
            name, pid = self.__process_struct.unpack(entry_bytes)
            name = name.rstrip(b'\x00').decode('ascii')
            return Process(name=name, pid=pid)

        entry_size = 36
        status = self.send_command(CMD_PROC_LIST)

        if status != ResponseCode.SUCCESS:
            return []

        count = self.__recv_int32()
        data = self.__recv_all(count * entry_size)

        return [parse_entry(data[i:i + entry_size]) for i in range(0, count * entry_size, entry_size)]

    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """
        Retrieves information about a running process.
        @param pid: Process id
        @return: ProcessInfo instance or None if unsuccessful
        """

        entry_size = 188
        pid_bytes = pid.to_bytes(4, 'little')
        status = self.send_command(CMD_PROC_INFO, pid_bytes)

        if status != ResponseCode.SUCCESS:
            return

        data = self.__recv_all(entry_size)

        pid, name, path, title_id, content_id = self.__process_info_struct.unpack(data)
        name = name[:name.index(0)].decode('ascii')
        path = path[:path.index(0)].decode('ascii')
        title_id = title_id[:title_id.index(0)].decode('ascii')
        content_id = content_id[:content_id.index(0)].decode('ascii')

        return ProcessInfo(pid=pid, name=name, path=path, title_id=title_id, content_id=content_id)

    def get_process_maps(self, pid: int) -> List[ProcessMap]:
        """
        Retrieves all memory maps in the running process.
        @param pid: Process id
        @return: List of ProcessMap instances. The list will be empty if the command failed.
        """

        def parse_entry(entry_bytes) -> ProcessMap:
            name, start, end, offset, prot = self.__process_map_struct.unpack(entry_bytes)
            name_end = name.index(0)
            name = entry_bytes[:name_end].decode('ascii')
            return ProcessMap(name=name, start=start, end=end, offset=offset, prot=prot)

        entry_size = 58
        payload = pid.to_bytes(4, 'little')
        status = self.send_command(CMD_PROC_MAPS, payload)

        if status != ResponseCode.SUCCESS:
            return []

        count = self.__recv_int32()
        data = self.__recv_all(count * entry_size)

        return [parse_entry(data[i:i + entry_size]) for i in range(0, count * entry_size, entry_size)]

    def allocate_memory(self, pid: int, length: int) -> Optional[int]:
        """
        Allocates memory in the remote process.
        @param pid: Process id
        @param length: Length in bytes
        @return: The starting address of your memory section or None if the command failed.
        """
        payload = self.__allocate_struct.pack(pid, length)
        status = self.send_command(CMD_PROC_ALLOC, payload)

        if status != ResponseCode.SUCCESS:
            return

        address = self.__recv_int64()
        return address

    def free_memory(self, pid: int, address: int, length: int) -> ResponseCode:
        """
        Frees a previously allocated memory section in the remote process.
        @param pid: Process id
        @param address: Starting address of the memory section
        @param length: Length in bytes
        @return: Response code
        """
        payload = self.__free_struct.pack(pid, address, length)
        return self.send_command(CMD_PROC_FREE, payload)

    def change_protection(self, pid: int, address: int, length: int, prot: VMProtection) -> ResponseCode:
        """
        Changes the protection flags of a memory section.
        @param pid: Process id
        @param address: Starting address of the memory section
        @param length: Length in bytes
        @param prot: New protection flags
        @return: Response code
        """
        payload = self.__change_prot_struct.pack(pid, address, length, prot.value)
        return self.send_command(CMD_PROC_PROTECT, payload)

    def install_rpc(self, pid: int) -> Optional[int]:
        """
        Writes a small program to the process' memory to allow execution of remote procedures
        @param pid: Process id
        @return: The starting address of the RPC stub or None if the command failed.
        """
        pid_bytes = pid.to_bytes(4, 'little')
        status = self.send_command(CMD_PROC_INSTALL, pid_bytes)

        if status != ResponseCode.SUCCESS:
            return

        return self.__recv_int64()

    def call(self, pid: int, address: int, *args, **kwargs) -> Optional[tuple]:
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

        status = self.send_command(CMD_PROC_CALL, payload_buffer)

        if status != ResponseCode.SUCCESS:
            return

        missing_bytes = 8 - struct.calcsize(output_format)
        rax = self.__recv_all(result_size)
        rax = struct.unpack(output_format + 'x' * missing_bytes, rax[4:])
        return rax

    def load_elf(self, pid: int, elf_path: str) -> ResponseCode:
        """
        Loads an ELF file and sends it to the PS4 to load.
        @param pid: Process id
        @param elf_path: Path to the ELF file
        @return: Response code
        """
        with open(elf_path, 'rb') as file:
            elf_bytes = file.read()

        payload = self.__elf_struct.pack(pid, len(elf_bytes))
        self.send_command(CMD_PROC_ELF, payload)
        status = self.get_status()

        if status == ResponseCode.SUCCESS:
            self.sock.sendall(elf_bytes)
            status = self.get_status()

        return status

    def read_memory(self, pid: int, address: int, length: int) -> Optional[bytearray]:
        """
        Reads the raw memory in bytes.
        @param pid: Process id.
        @param address: Starting address.
        @param length: Length in bytes.
        @return: The bytes read or None if the command failed.
        """
        payload = self.__memory_header_struct.pack(pid, address, length)
        status = self.send_command(CMD_PROC_READ, payload)

        if status != ResponseCode.SUCCESS:
            return

        return self.__recv_all(length)

    def read_struct(self, pid: int, address: int, structure: Union[str, struct.Struct]) -> Optional[tuple]:
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

        data = self.read_memory(pid, address, structure.size)
        return structure.unpack(data) if data else None

    def read_text(self, pid: int, address: int, encoding: str = 'ascii', **kwargs) -> Optional[str]:
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
            data = self.read_memory(pid, address, length)
            return data.decode(encoding)

        chunk_size = kwargs.get('chunk_size', 64)
        chunk = self.read_memory(pid, address, chunk_size)
        data = chunk

        while b'\x00' not in chunk:
            chunk = self.read_memory(pid, address + len(data), chunk_size)
            data += chunk

        data = data[:data.index(b'\0')]
        return data.decode(encoding)

    def write_memory(self, pid: int, address: int, value: Union[bytearray, bytes]) -> ResponseCode:
        """
        Writes the raw memory in bytes to an address.
        @param pid: Process id.
        @param address: Starting address.
        @param value: Bytes to write.
        @return: Response code.
        """
        payload = self.__memory_header_struct.pack(pid, address, len(value))
        self.send_command(CMD_PROC_WRITE, payload)
        self.sock.sendall(value)
        return self.get_status()

    def write_struct(self, pid: int, address: int, structure: Union[str, struct.Struct], *value) -> ResponseCode:
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
        return self.write_memory(pid, address, data)

    def write_text(self, pid: int, address: int, value: str, encoding: str = 'ascii') -> ResponseCode:
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

        return self.write_memory(pid, address, value)

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

    def scan_int32(self, pid: int, compare_type: ScanCompareType, *values) -> List[int]:
        bytes_value1 = struct.pack('<i', values[0]) if len(values) > 0 else b''
        bytes_value2 = struct.pack('<i', values[1]) if len(values) > 1 else b''
        length_value1 = len(bytes_value1)
        length_value2 = len(bytes_value2)

        old_timeout = self.sock.gettimeout()
        self.sock.settimeout(None)

        payload = struct.pack('<ibbI', pid, 0, compare_type.value, length_value1 + length_value2)
        status = self.send_command(CMD_PROC_SCAN, payload)

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

    def scan(self, pid: int, compare_type: ScanCompareType, value_type: ScanValueType, *values) -> List[int]:
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
    def debugger(self, pid: int) -> DebuggingContext:
        """
        Returns a debugging context to use for debugging a process
        @param pid: Process id
        @return: Debugging context
        """
        return DebuggingContext(self, pid)

    def get_threads(self) -> List[int]:
        """

        @return:
        """

    def get_thread_info(self, lwpid: int) -> object:
        """

        @param lwpid:
        @return:
        """
        raise NotImplementedError()

    def attach_debugger(self, pid: int) -> ResponseCode:
        """

        @param pid:
        @return:
        """
        if self.is_debugged:
            return ResponseCode.ALREADY_DEBUG
        pid_bytes = pid.to_bytes(4, 'little')
        self.send_command(CMD_DEBUG_ATTACH, pid_bytes)
        self.is_debugged = True
        return self.get_status()

    def detach_debugger(self) -> ResponseCode:
        """

        @return:
        """
        if not self.is_debugged:
            return ResponseCode.DATA_NULL
        self.send_command(CMD_DEBUG_DETACH)
        self.is_debugged = False
        return self.get_status()

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

    def write_kernel_memory(self, address: int, data: Union[bytearray, bytes]) -> ResponseCode:
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

    def resume_process(self) -> ResponseCode:
        """

        @return:
        """
        return self.send_command(CMD_DEBUG_STOPGO, b'\x00\x00\x00\x00')

    def stop_process(self) -> ResponseCode:
        """

        @return:
        """
        return self.send_command(CMD_DEBUG_STOPGO, b'\x01\x00\x00\x00')

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
