from typing import Any
from construct import Adapter, PaddedString, StringEncoded

class NullTerminatedPaddedString(Adapter):
    def _decode(self, obj: str, context: Any, path: Any) -> str:
        return obj.split("\x00", 1)[0]

    def _encode(self, obj: str, context: Any, path: Any) -> str:
        return obj


def ascii_string(length: int, *, strip: bool = False) -> NullTerminatedPaddedString | StringEncoded:
    padded = PaddedString(length, encoding="ascii")
    return NullTerminatedPaddedString(padded) if strip else padded
