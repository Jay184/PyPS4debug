from typing import Annotated

from construct import Padding, Bytes, Int8ul, Int16ul, Int32ul, Int64ul, PaddedString
from pydantic import PositiveInt, NonNegativeInt
from pydantic_construct import ConstructModel, OmitInMode

from .base import ascii_string
from .enums import VMProtection


class Process(ConstructModel):
    name: Annotated[str, ascii_string(length=32)]
    pid: Annotated[int, Int32ul]


class ProcessInfo(ConstructModel):
    pid: Annotated[int, Int32ul]
    name: Annotated[str, ascii_string(length=40, strip=True)]
    path: Annotated[str, ascii_string(length=64, strip=True)]
    title_id: Annotated[str, ascii_string(length=16, strip=True)]
    content_id: Annotated[str, ascii_string(length=64, strip=True)]


class ProcessMap(ConstructModel):
    name: Annotated[str, ascii_string(length=32, strip=True)]
    start: Annotated[NonNegativeInt, Int64ul]
    end: Annotated[PositiveInt, Int64ul]
    offset: Annotated[NonNegativeInt, Int64ul]
    prot: Annotated[VMProtection, Int16ul]



class CallRegisters(ConstructModel):
    rdi: Annotated[int, Int64ul] = 0
    rsi: Annotated[int, Int64ul] = 0
    rdx: Annotated[int, Int64ul] = 0
    rcx: Annotated[int, Int64ul] = 0
    r8: Annotated[int, Int64ul] = 0
    r9: Annotated[int, Int64ul] = 0


class CallResult(ConstructModel):
    pid: Annotated[int, Int32ul]
    rax: Annotated[bytes, Bytes(8)]


class ThreadInfo(ConstructModel):
    pid: Annotated[int, Int32ul]
    priority: Annotated[int, Int32ul]
    name: Annotated[str, PaddedString(32, "utf_16_le")] # NOTE Is UTF_16 LE the correct encoding?


class Registers64(ConstructModel):
    r15: Annotated[int, Int64ul]
    r14: Annotated[int, Int64ul]
    r13: Annotated[int, Int64ul]
    r12: Annotated[int, Int64ul]
    r11: Annotated[int, Int64ul]
    r10: Annotated[int, Int64ul]
    r9: Annotated[int, Int64ul]
    r8: Annotated[int, Int64ul]
    rdi: Annotated[int, Int64ul]
    rsi: Annotated[int, Int64ul]
    rbp: Annotated[int, Int64ul]
    rbx: Annotated[int, Int64ul]
    rdx: Annotated[int, Int64ul]
    rcx: Annotated[int, Int64ul]
    rax: Annotated[int, Int64ul]
    trapno: Annotated[int, Int32ul]
    fs: Annotated[int, Int64ul]
    gs: Annotated[int, Int64ul]
    err: Annotated[int, Int32ul]
    es: Annotated[int, Int64ul]
    ds: Annotated[int, Int64ul]
    rip: Annotated[int, Int64ul]
    cs: Annotated[int, Int64ul]
    rflags: Annotated[int, Int64ul]
    rsp: Annotated[int, Int64ul]
    ss: Annotated[int, Int64ul]


class FPEnv(ConstructModel):
    cw: Annotated[int, Int16ul]
    sw: Annotated[int, Int16ul]
    tw: Annotated[int, Int8ul]
    zero: Annotated[int, Int8ul]
    opcode: Annotated[int, Int16ul]
    rip: Annotated[int, Int64ul]
    rdp: Annotated[int, Int64ul]
    mxcsr: Annotated[int, Int32ul]
    mxcsr_mask: Annotated[int, Int32ul]


class FPAcc(ConstructModel):
    data: Annotated[list[int], Int8ul[10]]
    padding: Annotated[bytes | None, Padding(6), OmitInMode("json")] = None


class FPRegister(ConstructModel):
    data: Annotated[list[int], Int8ul[16]]


class FPXState(ConstructModel):
    bv: Annotated[int, Int64ul]
    rsrv0: Annotated[list[int], Int8ul[16]]
    rsrv: Annotated[list[int], Int8ul[40]]
    ymm: Annotated[list[FPRegister], FPRegister.struct[16]]


class FPRegisters(ConstructModel):
    env: FPEnv
    acc: Annotated[list[FPAcc], FPAcc.struct[8]]
    xmm: Annotated[list[FPRegister], FPRegister.struct[16]]
    pad: Annotated[bytes | None, Padding(96), OmitInMode("json")] = None
    xstate: FPXState


class DebugRegisters(ConstructModel):
    dr0: Annotated[int, Int64ul]
    dr1: Annotated[int, Int64ul]
    dr2: Annotated[int, Int64ul]
    dr3: Annotated[int, Int64ul]
    dr4: Annotated[int, Int64ul]
    dr5: Annotated[int, Int64ul]
    dr6: Annotated[int, Int64ul]
    dr7: Annotated[int, Int64ul]
    dr8: Annotated[int, Int64ul]
    dr9: Annotated[int, Int64ul]
    dr10: Annotated[int, Int64ul]
    dr11: Annotated[int, Int64ul]
    dr12: Annotated[int, Int64ul]
    dr13: Annotated[int, Int64ul]
    dr14: Annotated[int, Int64ul]
    dr15: Annotated[int, Int64ul]


class DebuggerInterrupt(ConstructModel):
    lwpid: Annotated[int, Int32ul]
    status: Annotated[int, Int32ul]
    name: Annotated[str, ascii_string(length=40)]
    regs: Registers64
    fp_regs: FPRegisters
    db_regs: DebugRegisters
