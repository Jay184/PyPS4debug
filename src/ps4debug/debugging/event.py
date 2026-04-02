from typing import TYPE_CHECKING
from dataclasses import dataclass

from ps4debug.core import DebuggerInterrupt

if TYPE_CHECKING:
    from .context import DebuggingContext


@dataclass(slots=True)
class BreakpointEventArgs:
    debugger: "DebuggingContext"
    index: int
    interrupt: DebuggerInterrupt
    resume: bool = True
