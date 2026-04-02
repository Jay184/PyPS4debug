from typing import TYPE_CHECKING, Any, Self, TypeVar, TypeAlias

from pydantic_construct import ConstructModel

from ps4debug.core import ResponseCode, VMProtection

from .view import MemoryView

if TYPE_CHECKING:
    from ps4debug.ps4debug import PS4Debug


T = TypeVar("T", bound="ConstructModel")
RPCResult: TypeAlias = tuple[Any, ...] | None


class MemoryContext:
    """Async context manager for remote memory allocation and operations."""

    __slots__ = ("_ps4debug", "pid", "address", "length")

    def __init__(self, ps4debug: "PS4Debug", pid: int, length: int = 4096) -> None:
        self._ps4debug = ps4debug
        self.pid = pid
        self.length = length
        self.address: int | None = None

    def view(self) -> MemoryView:
        """Create a memory view for the allocated region.

        This method returns a :class:`MemoryView` rooted at the base address
        of the currently allocated memory block. The view can be used to
        perform typed reads and writes relative to this allocation.

        Returns:
            MemoryView bound to the allocated memory region.

        Raises:
            RuntimeError: If memory has not been allocated yet. Use
                ``async with MemoryContext(...)`` before calling this method.

        Example:
            async with MemoryContext(client, pid) as mem:
                value = await mem.view().int32()
        """
        self._require_address()
        return MemoryView(self._ps4debug, self.pid, self.address)

    def _require_address(self) -> int:
        if self.address is None:
            raise RuntimeError("Memory is not allocated. Use 'async with'.")
        return self.address

    def _resolve(self, offset: int, size: int | None = None) -> int:
        base = self._require_address()

        if offset < 0:
            raise ValueError("Offset cannot be negative.")

        if size is not None and offset + size > self.length:
            raise ValueError("Memory access out of bounds.")

        return base + offset

    async def __aenter__(self) -> Self:
        if self.address is None:
            self.address = await self._ps4debug.allocate_memory(self.pid, self.length)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self.address is not None:
            await self._ps4debug.free_memory(self.pid, self.address, self.length)
            self.address = None

    @property
    def end_address(self) -> int | None:
        """Return the end address of the allocated memory region.

        The end address is calculated as `address + length`.

        Returns:
            The end address if the memory has been allocated, otherwise None.
        """
        if self.address:
            return self.address + self.length
        return None

    async def change_protection(self, prot: VMProtection) -> ResponseCode:
        """Change memory protection flags.

        Args:
            prot: New protection flags.

        Returns:
            ResponseCode from the debugger.
        """
        addr = self._require_address()
        return await self._ps4debug.change_protection(self.pid, addr, self.length, prot)

    async def call(
        self,
        params: ConstructModel | None = None,
        result_model: type[T] | None = None,
        **kwargs: Any,
    ) -> T | bytes | None:
        """Execute code using structured parameters.

        Args:
            params: ConstructModel instance describing input parameters.
            result_model: Optional ConstructModel type for parsing the result.

        Returns:
            Parsed result model, raw bytes if no model is provided,
            or None if the call failed.
        """
        return await self._ps4debug.call(
            self.pid,
            self._require_address(),
            params,
            result_model,
            **kwargs,
        )

    async def read(self, length: int, offset: int = 0) -> bytes | None:
        """Read memory from the allocated region.

        Args:
            length: Number of bytes to read.
            offset: Offset from the base address.

        Returns:
            Bytes read, or None on failure.
        """
        address = self._resolve(offset, length)
        return await self._ps4debug.read_memory(self.pid, address, length)

    async def read_model(self, model_type: type[T], offset: int = 0) -> T | None:
        """Read and deserialize a structured object from memory.

        Args:
            model_type: ConstructModel type used to parse the memory contents.
            offset: Offset from the base address of the allocated region.

        Returns:
            An instance of `model_type` populated with data from memory,
            or None if the read operation failed.

        Raises:
            ValueError: If the read exceeds the allocated memory bounds.
        """
        size = model_type.struct.sizeof()
        data = await self.read(size, offset)

        if data is None:
            return None

        return model_type.model_validate_bytes(data)

    async def write(self, value: bytes, offset: int = 0) -> ResponseCode:
        """Write bytes into the allocated region.

        Args:
            value: Data to write.
            offset: Offset from the base address.

        Returns:
            ResponseCode from the debugger.
        """
        address = self._resolve(offset, len(value))
        return await self._ps4debug.write_memory(self.pid, address, value)

    async def write_model(self, model: ConstructModel, offset: int = 0) -> ResponseCode:
        """Serialize and write a structured object into memory.

        Args:
            model: ConstructModel instance to serialize and write.
            offset: Offset from the base address of the allocated region.

        Returns:
            ResponseCode indicating the result of the write operation.

        Raises:
            ValueError: If bytes exceed the allocated memory bounds.
        """
        data = model.model_dump_bytes()
        return await self.write(data, offset)
