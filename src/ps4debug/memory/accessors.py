from typing import TYPE_CHECKING, Callable, TypeVar, Protocol, Any, Generic, Awaitable, Generator

from construct import CString

if TYPE_CHECKING:
    from .view import MemoryView


T = TypeVar("T")
Reader = Callable[[bytes], T]
Writer = Callable[[T], bytes]


class Constructable(Protocol):
    def build(self, v: Any) -> bytes:
        ...

    def parse(self, b: bytes) -> Any:
        ...

    def sizeof(self) -> int:
        ...


class MemoryAccessor(Generic[T]):
    """Typed asynchronous accessor for a fixed memory location.

    This class encapsulates reading and writing a specific region of memory
    relative to a :class:`MemoryView`. It is designed to be lightweight and
    reusable, allowing callers to cache accessors for repeated operations.

    The accessor is awaitable, resolving to the result of :meth:`get`.

    Example:
        value = await view.int32(0x10)
        await view.int32(0x10).set(42)

    Attributes:
        mem: Parent memory view.
        offset: Offset from the base address.
        size: Number of bytes read/written.
        reader: Function converting raw bytes into a Python value.
        writer: Function converting a Python value into raw bytes.
    """

    def __init__(
        self,
        mem: "MemoryView",
        offset: int,
        size: int,
        reader: Reader,
        writer: Writer,
    ):
        self.mem = mem
        self.offset = offset
        self.size = size
        self.reader = reader
        self.writer = writer

    async def get(self) -> T:
        """Read and decode the value from memory.

        Returns:
            Decoded value of type ``T``.

        Raises:
            PS4DebugException: If the underlying memory read fails.
        """
        data = await self.mem.client.read_memory(
            self.mem.pid,
            self.mem.base + self.offset,
            self.size,
        )
        return self.reader(data)

    async def set(self, value: T) -> None:
        """Encode and write a value to memory.

        Args:
            value: Value to write.

        Raises:
            ValueError: If the encoded value size does not match the expected size.
            PS4DebugException: If the underlying memory write fails.
        """
        data = self.writer(value)

        if len(data) != self.size:
            raise ValueError(
                f"Writer produced {len(data)} bytes, expected {self.size}"
            )

        await self.mem.client.write_memory(
            self.mem.pid,
            self.mem.base + self.offset,
            data,
        )

    def __call__(self, value: T) -> Awaitable[None]:
        """Alias for :meth:`set`."""
        return self.set(value)

    def __await__(self) -> Generator[Any, Any, T]:
        """Allow ``await accessor`` as shorthand for ``await accessor.get()``."""
        return self.get().__await__()


class NumericMemoryAccessor(MemoryAccessor[int]):
    """Specialized memory accessor for integer values using Construct types.

    This accessor uses a ``Construct`` instance to parse and build binary data,
    ensuring consistency with the rest of the protocol models.

    Attributes:
        construct_type: Construct type used for parsing and building.
    """

    def __init__(
        self,
        mem: "MemoryView",
        offset: int,
        construct_type: Constructable,
    ):
        self.construct_type = construct_type

        size = construct_type.sizeof()
        super().__init__(mem, offset, size, self.parse, self.build)

    def parse(self, b: bytes) -> int:
        """Parse raw bytes into an integer."""
        return self.construct_type.parse(b)

    def build(self, v: int) -> bytes:
        """Serialize an integer into bytes."""
        return self.construct_type.build(v)


class StringMemoryAccessor(MemoryAccessor[str]):
    def __init__(
        self,
        mem: "MemoryView",
        offset: int,
        size: int,
        encoding: str = "ascii",
    ):
        super().__init__(mem, offset, size, self.read, self.write)
        self.encoding = encoding

    def read(self, b: bytes) -> str:
        """Parse raw bytes into a string."""
        return CString(self.encoding).parse(b)

    def write(self, v: str) -> bytes:
        """Serialize a string into bytes."""
        return CString(self.encoding).build(v)
