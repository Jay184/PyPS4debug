from abc import ABCMeta
from construct import Struct, Int8ul, Int16ul, Int32ul, Int64ul, PaddedString
import construct
import enum


# "ps4debug"'s protocol for this is not good, so we have to post-process the string fields
# They are using a mix of pascal strings and c-strings
class PS4DebugStringAdapter(construct.Adapter, metaclass=ABCMeta):
    def _decode(self, obj, context, path):
        try:
            obj = obj[:obj.index(u'\x00')]
        except ValueError:
            pass
        finally:
            return obj

    def _encode(self, obj, context, path):
        return obj


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


class VMProtection(enum.IntEnum):
    """Contains possible settings for memory protection."""
    VM_PROT_NONE = 0x00
    VM_PROT_READ = 0x01
    VM_PROT_WRITE = 0x02
    VM_PROT_EXECUTE = 0x04
    VM_PROT_DEFAULT = 0x03
    VM_PROT_ALL = 0x07
    VM_PROT_NO_CHANGE = 0x08
    VM_PROT_COPY = 0x10


class ScanCompareType(enum.IntEnum):
    """PS4Debug scanning modes."""
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


class ScanValueType(enum.IntEnum):
    """PS4Debug scanning types"""
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


class WatchPointLengthType(enum.IntEnum):
    DBREG_DR7_LEN_1 = 0
    DBREG_DR7_LEN_2 = 1
    DBREG_DR7_LEN_4 = 3
    DBREG_DR7_LEN_8 = 2


class WatchPointBreakType(enum.IntEnum):
    DBREG_DR7_EXEC = 0
    DBREG_DR7_WRONLY = 1
    DBREG_DR7_RDWR = 3


Process = Struct(
    name=PaddedString(32, 'ascii'),
    pid=Int32ul,
)

ProcessInfo = Struct(
    pid=Int32ul,
    name=PS4DebugStringAdapter(PaddedString(40, 'ascii')),
    path=PS4DebugStringAdapter(PaddedString(64, 'ascii')),
    title_id=PS4DebugStringAdapter(PaddedString(16, 'ascii')),
    content_id=PS4DebugStringAdapter(PaddedString(64, 'ascii')),
)

ProcessMap = Struct(
    name=PS4DebugStringAdapter(PaddedString(32, 'ascii')),
    start=construct.Hex(Int64ul),
    end=construct.Hex(Int64ul),
    offset=construct.Hex(Int64ul),
    prot=Int16ul,
)

PS4DebugCommandHeader = Struct(
    magic=construct.Hex(construct.Const(b'\xCC\xBB\xAA\xFF')),
    code=Int32ul,
    length=Int32ul,
)

NotifyPayload = Struct(
    type=Int32ul,
    length=Int32ul,
)

AllocateMemoryPayload = Struct(
    pid=Int32ul,
    length=Int32ul,
)

FreeMemoryPayload = Struct(
    pid=Int32ul,
    address=construct.Hex(Int64ul),
    length=Int32ul,
)

ChangeMemoryProtectionPayload = Struct(
    pid=Int32ul,
    address=Int64ul,
    length=Int32ul,
    prot=Int32ul,
)

CallPayload = Struct(
    pid=Int32ul,
    rpc_stub=Int64ul,
    address=Int64ul,
    parameters=construct.Bytes(48),
)

CallResult = Struct(
    pid=Int32ul,
    rax=construct.Bytes(8),
)

LoadELFPayload = Struct(
    pid=Int32ul,
    length=Int32ul,
)

MemoryPayload = Struct(
    pid=Int32ul,
    address=Int64ul,
    length=Int32ul,
)

KernelMemoryPayload = Struct(
    address=Int64ul,
    length=Int32ul,
)

SetWatchpointPayload = Struct(
    index=Int32ul,
    enabled=Int32ul,
    length=Int32ul,
    type=Int32ul,
    address=construct.Hex(Int64ul),
)

SetBreakpointPayload = Struct(
    index=Int32ul,
    enabled=Int32ul,
    address=construct.Hex(Int64ul),
)

SetRegisterPayload = Struct(
    thread_id=Int32ul,
    size=Int32ul,
)

# TODO What encoding to use?
ThreadInfo = Struct(
    pid=Int32ul,
    priority=Int32ul,
    name=PaddedString(32, 'utf_16_le'),
)

Registers64 = Struct(
    r15=Int64ul,
    r14=Int64ul,
    r13=Int64ul,
    r12=Int64ul,
    r11=Int64ul,
    r10=Int64ul,
    r9=Int64ul,
    r8=Int64ul,
    rdi=Int64ul,
    rsi=Int64ul,
    rbp=Int64ul,
    rbx=Int64ul,
    rdx=Int64ul,
    rcx=Int64ul,
    rax=Int64ul,
    trapno=Int32ul,
    fs=Int16ul,
    gs=Int16ul,
    err=Int32ul,
    es=Int16ul,
    ds=Int16ul,
    rip=Int64ul,
    cs=Int64ul,
    rflags=Int64ul,
    rsp=Int64ul,
    ss=Int64ul,
)

FPRegisters = Struct(
    env=Struct(
        cw=Int16ul,
        sw=Int16ul,
        tw=Int8ul,
        zero=Int8ul,
        opcode=Int16ul,
        rip=Int64ul,
        rdp=Int64ul,
        mxcsr=Int32ul,
        mxcsr_mask=Int32ul,
    ),
    acc=construct.LazyStruct(
        bytes=Int8ul[10],
        _=construct.Padding(6),
    )[8],
    xmmacc=construct.LazyStruct(
        bytes=Int8ul[16],
    )[16],
    _=construct.Padding(96),
    xstate=construct.LazyStruct(
        bv=Int64ul,
        rsrv0=Int8ul[16],
        rsrv=Int8ul[40],
        ymm=Struct(
            bytes=Int8ul[16],
        )[16],
    ),
)

DebugRegisters = Struct(
    dr0=Int64ul,
    dr1=Int64ul,
    dr2=Int64ul,
    dr3=Int64ul,
    dr4=Int64ul,
    dr5=Int64ul,
    dr6=Int64ul,
    dr7=Int64ul,
    dr8=Int64ul,
    dr9=Int64ul,
    dr10=Int64ul,
    dr11=Int64ul,
    dr12=Int64ul,
    dr13=Int64ul,
    dr14=Int64ul,
    dr15=Int64ul,
)

DebuggerInterrupt = Struct(
    lwpid=construct.Hex(Int32ul),
    status=Int32ul,
    name=PaddedString(40, 'ascii'),
    regs=Registers64,
    fp_regs=FPRegisters,
    db_regs=DebugRegisters,
)


class BreakpointEvent(object):
    def __init__(self, debugger, index: int, interrupt: DebuggerInterrupt):
        super(BreakpointEvent, self).__init__()
        self.debugger = debugger
        self.index = index
        self.interrupt = interrupt
        self.resume = True
