from typing import Literal, Protocol, Any
from dataclasses import dataclass


ByteOrder = Literal["little", "big"]


class Constructable(Protocol):
    def build(self, v: Any) -> bytes:
        ...

    def parse(self, b: bytes) -> Any:
        ...

    def sizeof(self) -> int:
        ...


@dataclass(slots=True)
class TypeSpec:
    little: Constructable | None
    big: Constructable | None
