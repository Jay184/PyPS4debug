import struct
from typing import TYPE_CHECKING, TypeVar, Self

from pydantic_construct import ConstructModel
from construct import (
    Int8sl, Int8ul,
    Int16sl, Int16ul,
    Int32sl, Int32ul,
    Int64sl, Int64ul,
    Float32l, Float64l,
)

from .accessors import MemoryAccessor, NumericMemoryAccessor, StringMemoryAccessor

if TYPE_CHECKING:
    from ps4debug.ps4debug import PS4Debug


T = TypeVar("T", bound="ConstructModel")


class MemoryView:
    """Immutable view into a process memory region.

    This class provides a structured, type-safe interface for reading and writing
    memory relative to a base address. It acts as a factory for
    :class:`MemoryAccessor` instances.

    The view itself is immutable; operations such as :meth:`offset` return new
    instances rather than modifying the current one.

    Attributes:
        client: PS4Debug client instance.
        pid: Target process ID.
        base: Base address for this view.
    """

    def __init__(self, client: "PS4Debug", pid: int, base: int):
        self.client = client
        self.pid = pid
        self.base = base

    def offset(self, by: int) -> Self:
        """Create a new view shifted by a given offset.

        Args:
            by: Offset in bytes.

        Returns:
            New MemoryView with adjusted base address.
        """
        return MemoryView(self.client, self.pid, self.base + by)

    def int8(self, offset: int = 0) -> MemoryAccessor[int]:
        """Create an 8-bit signed integer accessor.

        Args:
            offset: Offset from the base address.

        Returns:
            MemoryAccessor for a signed 8-bit integer.
        """
        return NumericMemoryAccessor(self, offset, Int8sl)

    def uint8(self, offset: int = 0) -> MemoryAccessor[int]:
        """Create an 8-bit unsigned integer accessor.

        Args:
            offset: Offset from the base address.

        Returns:
            MemoryAccessor for an unsigned 8-bit integer.
        """
        return NumericMemoryAccessor(self, offset, Int8ul)

    def int16(self, offset: int = 0) -> MemoryAccessor[int]:
        """Create a 16-bit signed integer accessor.

        Args:
            offset: Offset from the base address.

        Returns:
            MemoryAccessor for a signed 16-bit integer.
        """
        return NumericMemoryAccessor(self, offset, Int16sl)

    def uint16(self, offset: int = 0) -> MemoryAccessor[int]:
        """Create a 16-bit unsigned integer accessor.

        Args:
            offset: Offset from the base address.

        Returns:
            MemoryAccessor for an unsigned 16-bit integer.
        """
        return NumericMemoryAccessor(self, offset, Int16ul)

    def int32(self, offset: int = 0) -> MemoryAccessor[int]:
        """Create a 32-bit signed integer accessor.

        Args:
            offset: Offset from the base address.

        Returns:
            MemoryAccessor for a signed 32-bit integer.
        """
        return NumericMemoryAccessor(self, offset, Int32sl)

    def uint32(self, offset: int = 0) -> MemoryAccessor[int]:
        """Create a 32-bit unsigned integer accessor.

        Args:
            offset: Offset from the base address.

        Returns:
            MemoryAccessor for an unsigned 32-bit integer.
        """
        return NumericMemoryAccessor(self, offset, Int32ul)

    def int64(self, offset: int = 0) -> MemoryAccessor[int]:
        """Create a 64-bit signed integer accessor.

        Args:
            offset: Offset from the base address.

        Returns:
            MemoryAccessor for a signed 64-bit integer.
        """
        return NumericMemoryAccessor(self, offset, Int64sl)

    def uint64(self, offset: int = 0) -> MemoryAccessor[int]:
        """Create a 64-bit unsigned integer accessor.

        Args:
            offset: Offset from the base address.

        Returns:
            MemoryAccessor for an unsigned 64-bit integer.
        """
        return NumericMemoryAccessor(self, offset, Int64ul)

    def floating(self, offset: int = 0) -> MemoryAccessor[float]:
        """Create a 32-bit floating-point accessor.

        Args:
            offset: Offset from the base address.

        Returns:
            MemoryAccessor for a 32-bit floating-point.
        """
        return MemoryAccessor(
            self,
            offset,
            4,
            lambda b: Float32l.parse(b),
            lambda v: Float32l.build(v),
        )

    def double(self, offset: int = 0) -> MemoryAccessor[float]:
        """Create a 64-bit floating-point accessor.

        Args:
            offset: Offset from the base address.

        Returns:
            MemoryAccessor for a 64-bit floating-point.
        """
        return MemoryAccessor(
            self,
            offset,
            8,
            lambda b: Float64l.parse(b),
            lambda v: Float64l.build(v),
        )

    def boolean(self, offset: int = 0) -> MemoryAccessor[bool]:
        """Create a boolean accessor.

        Args:
            offset: Offset from the base address.

        Returns:
            MemoryAccessor for a boolean.
        """
        return MemoryAccessor(
            self,
            offset,
            1,
            lambda b: struct.unpack("<?", b)[0],
            lambda v: struct.pack("<?", v),
        )

    def bytes(self, size: int, offset: int = 0) -> MemoryAccessor[bytes]:
        """Create a raw byte accessor.

        Args:
            size: Number of bytes.
            offset: Offset from the base address.

        Returns:
            MemoryAccessor for raw bytes.
        """
        return MemoryAccessor(
            self,
            offset,
            size,
            lambda b: b,
            lambda v: v,
        )

    def model(self, model: type[T], offset: int = 0) -> MemoryAccessor[T]:
        """Create an accessor for a ConstructModel.

        Args:
            model: Model type derived from ConstructModel.
            offset: Offset from the base address.

        Returns:
            MemoryAccessor that reads/writes the given model.
        """
        size = model.struct.sizeof()

        return MemoryAccessor(
            self,
            offset,
            size,
            lambda b: model.model_validate_bytes(b),
            lambda v: v.model_dump_bytes(),
        )

    def string(
        self,
        length: int,
        offset: int = 0,
        encoding: str = "ascii",
    ) -> MemoryAccessor[str]:
        """Create an accessor for a string.

        Supports both fixed-length and null-terminated strings.

        Args:
            offset: Offset from the base address.
            length: Optional fixed length. If omitted, reads until a null byte.
            encoding: Text encoding.

        Returns:
            MemoryAccessor for a string.
        """
        return StringMemoryAccessor(
            self,
            offset,
            length,
            encoding,
        )

    async def read_variable_text(
        self,
        offset: int = 0,
        encoding: str = "ascii",
        *,
        chunk_size: int = 64,
    ) -> str:
        """Read a null-terminated string from memory.

        Args:
            offset: Offset from the base address.
            encoding: Text encoding.
            chunk_size: Bytes to read at a time.

        Returns:
            Decoded string.

        Raises:
            PS4DebugException: If memory reads fail.
        """
        base = self.base + offset
        data = bytearray()

        while True:
            chunk = await self.client.read_memory(
                self.pid,
                base + len(data),
                chunk_size,
            )
            data += chunk

            if b"\0" in chunk:
                break

        return data[:data.index(b"\0")].decode(encoding)
