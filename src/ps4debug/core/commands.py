from typing import Annotated, Literal

from construct import Int32ul, Int64ul, Int8ul, Bytes
from pydantic import BaseModel, Field, NonNegativeInt, PositiveInt, computed_field
from pydantic_construct import ConstructModel, binary_after

from .enums import VMProtection, ScanValueType, ScanCompareType, ProcessState, NotificationType, WatchPointLengthType, WatchPointBreakType


MAX_BREAKPOINTS = 30
MAX_WATCHPOINTS = 4


class BaseCommand(ConstructModel):
    """Base class for all protocol commands."""
    magic: Annotated[Literal[0xFFAABBCC], Int32ul] = 0xFFAABBCC
    code: Annotated[int, Int32ul]

    @computed_field
    @property
    @binary_after("code")
    def header_length(self) -> Annotated[int, Int32ul]:
        return self.struct.sizeof() - BaseCommand.struct.sizeof()


class ProcessMixin(BaseModel):
    pid: Annotated[int, Int32ul]


class ThreadMixin(BaseModel):
    thread_id: Annotated[int, Int32ul]


class ThreadRegistersMixin(ThreadMixin):
    size: Annotated[NonNegativeInt, Int32ul]


class MemoryMixin(BaseModel):
    address: Annotated[PositiveInt, Int64ul]
    length: Annotated[PositiveInt, Int32ul]

# General commands:

class VersionCommand(BaseCommand):
    code: Annotated[Literal[0xBD000001], Int32ul] = 0xBD000001

# Process commands:

class ListProcessesCommand(BaseCommand):
    code: Annotated[Literal[0xBDAA0001], Int32ul] = 0xBDAA0001


class ReadMemoryCommand(MemoryMixin, ProcessMixin, BaseCommand):
    code: Annotated[Literal[0xBDAA0002], Int32ul] = 0xBDAA0002


class WriteMemoryCommand(MemoryMixin, ProcessMixin, BaseCommand):
    code: Annotated[Literal[0xBDAA0003], Int32ul] = 0xBDAA0003


class ProcessMapsCommand(ProcessMixin, BaseCommand):
    code: Annotated[Literal[0xBDAA0004], Int32ul] = 0xBDAA0004


class InstallRPCCommand(ProcessMixin, BaseCommand):
    code: Annotated[Literal[0xBDAA0005], Int32ul] = 0xBDAA0005


class CallCommand(ProcessMixin, BaseCommand):
    code: Annotated[Literal[0xBDAA0006], Int32ul] = 0xBDAA0006

    rpc_address: Annotated[int, Int64ul]
    address: Annotated[int, Int64ul]
    """RIP register"""
    registers: Annotated[bytes, Bytes(48)]
    """RDI, RSI, RDX, RCX, R8, R9"""


class LoadELFCommand(ProcessMixin, BaseCommand):
    code: Annotated[Literal[0xBDAA0007], Int32ul] = 0xBDAA0007

    size: Annotated[NonNegativeInt, Int32ul]


class ChangeMemoryProtectionCommand(MemoryMixin, ProcessMixin, BaseCommand):
    code: Annotated[Literal[0xBDAA0008], Int32ul] = 0xBDAA0008

    protection: Annotated[VMProtection, Int32ul] = VMProtection.NO_CHANGE


class ScanMemoryCommand(ProcessMixin, BaseCommand):
    code: Annotated[Literal[0xBDAA0009], Int32ul] = 0xBDAA0009

    value_type: Annotated[ScanValueType, Int8ul]
    compare_type: Annotated[ScanCompareType, Int8ul]
    data_length: Annotated[NonNegativeInt, Int32ul]


class ProcessInfoCommand(ProcessMixin, BaseCommand):
    code: Annotated[Literal[0xBDAA000A], Int32ul] = 0xBDAA000A


class AllocateMemoryCommand(ProcessMixin, BaseCommand):
    code: Annotated[Literal[0xBDAA000B], Int32ul] = 0xBDAA000B

    length: Annotated[NonNegativeInt, Int32ul]


class FreeMemoryCommand(MemoryMixin, ProcessMixin, BaseCommand):
    code: Annotated[Literal[0xBDAA000C], Int32ul] = 0xBDAA000C

# Debug commands:

class AttachDebuggerCommand(ProcessMixin, BaseCommand):
    code: Annotated[Literal[0xBDBB0001], Int32ul] = 0xBDBB0001


class DetachDebuggerCommand(BaseCommand):
    code: Annotated[Literal[0xBDBB0002], Int32ul] = 0xBDBB0002


class SetBreakpointCommand(BaseCommand):
    code: Annotated[Literal[0xBDBB0003], Int32ul] = 0xBDBB0003

    index: Annotated[int, Int32ul, Field(ge=0, lt=MAX_BREAKPOINTS)]
    enabled: Annotated[bool, Int32ul]
    address: Annotated[PositiveInt, Int64ul]


class SetWatchpointCommand(BaseCommand):
    code: Annotated[Literal[0xBDBB0004], Int32ul] = 0xBDBB0004

    index: Annotated[int, Int32ul, Field(ge=0, lt=MAX_WATCHPOINTS)]
    enabled: Annotated[bool, Int32ul]
    length: Annotated[WatchPointLengthType, Int32ul]
    type: Annotated[WatchPointBreakType, Int32ul]
    address: Annotated[PositiveInt, Int64ul]


class ListThreadsCommand(BaseCommand):
    code: Annotated[Literal[0xBDBB0005], Int32ul] = 0xBDBB0005


class StopThreadCommand(ThreadMixin, BaseCommand):
    code: Annotated[Literal[0xBDBB0006], Int32ul] = 0xBDBB0006


class ResumeThreadCommand(ThreadMixin, BaseCommand):
    code: Annotated[Literal[0xBDBB0007], Int32ul] = 0xBDBB0007


class GetRegistersCommand(ThreadMixin, BaseCommand):
    code: Annotated[Literal[0xBDBB0008], Int32ul] = 0xBDBB0008


class SetRegistersCommand(ThreadRegistersMixin, BaseCommand):
    code: Annotated[Literal[0xBDBB0009], Int32ul] = 0xBDBB0009


class GetFloatRegistersCommand(ThreadMixin, BaseCommand):
    code: Annotated[Literal[0xBDBB000A], Int32ul] = 0xBDBB000A


class SetFloatRegistersCommand(ThreadRegistersMixin, BaseCommand):
    code: Annotated[Literal[0xBDBB000B], Int32ul] = 0xBDBB000B


class GetDebugRegistersCommand(ThreadMixin, BaseCommand):
    code: Annotated[Literal[0xBDBB000C], Int32ul] = 0xBDBB000C


class SetDebugRegistersCommand(ThreadRegistersMixin, BaseCommand):
    code: Annotated[Literal[0xBDBB000D], Int32ul] = 0xBDBB000D


class ChangeProcessStateCommand(BaseCommand):
    code: Annotated[Literal[0xBDBB0010], Int32ul] = 0xBDBB0010
    stop: Annotated[ProcessState, Int32ul]


class ResumeProcessCommand(ChangeProcessStateCommand):
    code: Annotated[Literal[0xBDBB0010], Int32ul] = 0xBDBB0010
    stop: Annotated[Literal[ProcessState.RESUME], Int32ul] = ProcessState.RESUME


class StopProcessCommand(ChangeProcessStateCommand):
    code: Annotated[Literal[0xBDBB0010], Int32ul] = 0xBDBB0010
    stop: Annotated[Literal[ProcessState.STOP], Int32ul] = ProcessState.STOP


class KillProcessCommand(ChangeProcessStateCommand):
    code: Annotated[Literal[0xBDBB0010], Int32ul] = 0xBDBB0010
    stop: Annotated[Literal[ProcessState.KILL], Int32ul] = ProcessState.KILL


class ThreadInfoCommand(ThreadMixin, BaseCommand):
    code: Annotated[Literal[0xBDBB0011], Int32ul] = 0xBDBB0011


class SingleStepCommand(BaseCommand):
    code: Annotated[Literal[0xBDBB0012], Int32ul] = 0xBDBB0012

# Kernel commands:

class GetKernelBaseCommand(BaseCommand):
    code: Annotated[Literal[0xBDCC0001], Int32ul] = 0xBDCC0001


class ReadKernelMemoryCommand(MemoryMixin, BaseCommand):
    code: Annotated[Literal[0xBDCC0002], Int32ul] = 0xBDCC0002


class WriteKernelMemoryCommand(MemoryMixin, BaseCommand):
    code: Annotated[Literal[0xBDCC0003], Int32ul] = 0xBDCC0003

# Console commands:

class RebootCommand(BaseCommand):
    code: Annotated[Literal[0xBDDD0001], Int32ul] = 0xBDDD0001


class EndCommand(BaseCommand):
    code: Annotated[Literal[0xBDDD0002], Int32ul] = 0xBDDD0002


class PrintCommand(BaseCommand):
    code: Annotated[Literal[0xBDDD0003], Int32ul] = 0xBDDD0003
    length: Annotated[NonNegativeInt, Int32ul]


class NotificationCommand(BaseCommand):
    code: Annotated[Literal[0xBDDD0004], Int32ul] = 0xBDDD0004
    message_type: Annotated[NotificationType | int, Int32ul] = NotificationType.CUSTOM
    length: Annotated[NonNegativeInt, Int32ul]


class ConsoleInfoCommand(BaseCommand):
    code: Annotated[Literal[0xBDDD0005], Int32ul] = 0xBDDD0005
