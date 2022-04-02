from typing import NamedTuple
import enum


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


class ScanValueType(enum.Enum):
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


class Process(NamedTuple):
    """Represents a remote process."""
    name: str
    pid: int


class ProcessMap(NamedTuple):
    """Represents a memory section in a process."""
    name: str
    start: int
    end: int
    offset: int
    prot: int


class ProcessInfo(NamedTuple):
    """Contains process information."""
    pid: int
    name: str
    path: str
    title_id: str
    content_id: str
