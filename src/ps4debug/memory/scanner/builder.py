from typing import TYPE_CHECKING, Optional, Self, Any, AsyncGenerator
from dataclasses import dataclass
import re

from construct import (
    GreedyBytes, CString,
    Int8ul, Int8sl,
    Int16ul, Int16sl,
    Int32ul, Int32sl,
    Int64ul, Int64sl,
    Float32l, Float64l,
    Int8ub, Int8sb,
    Int16ub, Int16sb,
    Int32ub, Int32sb,
    Int64ub, Int64sb,
    Float32b, Float64b,
)

from ps4debug.core import ScanValueType, ScanCompareType

from .base import ByteOrder, TypeSpec

if TYPE_CHECKING:
    from .session import ScanSession


@dataclass(slots=True)
class ScanBuilderState:
    pid: int | None = None
    value_type: ScanValueType | None = None
    type_spec: TypeSpec | None = None
    compare_type: ScanCompareType | None = None
    value: Any = None
    extra: Any = None
    bounds: tuple[int, int] | None = None
    module_pattern: re.Pattern[str] | None = None
    pause_process: bool = False
    aligned: bool = True
    byteorder: ByteOrder = "little"

    @property
    def core_type(self) -> Any | None:
        if self.type_spec is None:
            return None
        return self.type_spec.little if self.byteorder == "little" else self.type_spec.big


class ScanBuilder:
    __slots__ = ("_session", "_state")

    def __init__(self, session: Optional["ScanSession"] = None):
        self._session = session
        self._state = ScanBuilderState()

    async def execute(self) -> dict[int, Any]:
        """Executes the scan using the current builder state.

        This method delegates execution to the associated session. The builder
        must be bound to a session before calling this method.

        Raises:
            RuntimeError: If the builder is not associated with a session.
        """
        if self._session is None:
            raise RuntimeError("This builder is unbounded and cannot execute itself.")

        return await self._session.execute(self._state)

    async def execute_iter(self) -> AsyncGenerator[tuple[int, Any], None]:
        """Executes the scan using the current builder state.

        This method delegates execution to the associated session. The builder
        must be bound to a session before calling this method.

        Raises:
            RuntimeError: If the builder is not associated with a session.
        """
        if self._session is None:
            raise RuntimeError("This builder is unbounded and cannot execute itself.")

        it = self._session.execute_iter(self._state)

        # We can simply return the iterator, but we would have to mark the function sync.
        async for addr, value in it:
            yield addr, value

    def reset(self) -> Self:
        """Resets the builder state to its default configuration.

        This clears all previously configured options, allowing the builder
        to be reused for a new query.
        """
        self._state = ScanBuilderState()
        return self

    def byteorder(self, order: ByteOrder) -> Self:
        """Sets the byte order used during the scan.

        Args:
            order (ByteOrder): The byte order to use when interpreting values.
        """
        self._state.byteorder = order
        return self

    def bounds(self, start: int, end: int) -> Self:
        """Restricts the scan to a specific memory address range.

        The resulting scan will only include regions that intersect with the
        given address interval.

        Args:
            start (int): The start address (inclusive).
            end (int): The end address (exclusive).

        Raises:
            ValueError: If start is greater than or equal to end, or if values negative.
        """
        if start >= end:
            raise ValueError(f"Invalid bounds: start ({start}) must be < end ({end})")

        if start < 0 or end < 0:
            raise ValueError("Bounds must be non-negative")

        self._state.bounds = (start, end)
        return self

    def only_module(self, pattern: str | re.Pattern[str]) -> Self:
        """Restricts the scan to memory maps whose names match a pattern.

        The pattern is applied to each memory map's name. Only maps that match
        the pattern are included in the scan. This constraint composes with
        other filters such as ``bounds``.

        Args:
            pattern (str | re.Pattern[str]): A regular expression pattern used
                to match module names. Strings are compiled automatically.
        """
        if isinstance(pattern, str):
            pattern = re.compile(pattern)

        self._state.module_pattern = pattern
        return self

    def pause(self, pause: bool = True) -> Self:
        """Controls whether the target process should be paused during the scan.

        Args:
            pause (bool): If True, the process will be paused while scanning.
                Defaults to True.
        """
        self._state.pause_process = pause
        return self

    def aligned(self, aligned: bool = True) -> Self:
        """Controls whether the memory scan is using aligned memory.

        Args:
            aligned (bool): If True, the scanning is aligning to the value type.
        """
        self._state.aligned = aligned
        return self

    def int8(self) -> Self:
        """Set the scan type to signed 8-bit integer."""
        self._state.value_type = ScanValueType.INT8
        self._state.type_spec = TypeSpec(Int8sl, Int8sb)
        return self

    def uint8(self) -> Self:
        """Set the scan type to unsigned 8-bit integer."""
        self._state.value_type = ScanValueType.UINT8
        self._state.type_spec = TypeSpec(Int8ul, Int8ub)
        return self

    def int16(self) -> Self:
        """Set the scan type to signed 16-bit integer."""
        self._state.value_type = ScanValueType.INT16
        self._state.type_spec = TypeSpec(Int16sl, Int16sb)
        return self

    def uint16(self) -> Self:
        """Set the scan type to unsigned 16-bit integer."""
        self._state.value_type = ScanValueType.UINT16
        self._state.type_spec = TypeSpec(Int16ul, Int16ub)
        return self

    def int32(self) -> Self:
        """Set the scan type to signed 32-bit integer."""
        self._state.value_type = ScanValueType.INT32
        self._state.type_spec = TypeSpec(Int32sl, Int32sb)
        return self

    def uint32(self) -> Self:
        """Set the scan type to unsigned 32-bit integer."""
        self._state.value_type = ScanValueType.UINT32
        self._state.type_spec = TypeSpec(Int32ul, Int32ub)
        return self

    def int64(self) -> Self:
        """Set the scan type to signed 64-bit integer."""
        self._state.value_type = ScanValueType.INT64
        self._state.type_spec = TypeSpec(Int64sl, Int64sb)
        return self

    def uint64(self) -> Self:
        """Set the scan type to unsigned 64-bit integer."""
        self._state.value_type = ScanValueType.UINT64
        self._state.type_spec = TypeSpec(Int64ul, Int64ub)
        return self

    def float(self) -> Self:
        """Set the scan type to 32-bit floating point."""
        self._state.value_type = ScanValueType.FLOAT
        self._state.type_spec = TypeSpec(Float32l, Float32b)
        return self

    def double(self) -> Self:
        """Set the scan type to 64-bit floating point."""
        self._state.value_type = ScanValueType.DOUBLE
        self._state.type_spec = TypeSpec(Float64l, Float64b)
        return self

    def string(self, encoding: str = "utf-8") -> Self:
        """
        Set the scan type to a null-terminated string.

        Args:
            encoding: Encoding of the string. Defaults to 'utf-8'.
        """
        ctype = CString(encoding)

        self._state.value_type = ScanValueType.STRING
        self._state.type_spec = TypeSpec(ctype, ctype)
        return self

    def byte_array(self) -> Self:
        """Set the scan type to a variable-length byte array."""
        self._state.value_type = ScanValueType.BYTE_ARRAY
        self._state.type_spec = TypeSpec(GreedyBytes, GreedyBytes)
        return self

    def exact(self, value: Any) -> Self:
        """
        Configure an exact match scan.

        Args:
            value: Value to match exactly.
        """
        self._state.compare_type = ScanCompareType.EXACT
        self._state.value = value
        self._state.extra = None
        return self

    def fuzzy(self, value: Any) -> Self:
        """
        Configure a fuzzy comparison scan (only for float/double).

        Args:
            value: Reference value for fuzzy comparison.
        """
        self._state.compare_type = ScanCompareType.FUZZY
        self._state.value = value
        self._state.extra = None
        return self

    def bigger(self, value: Any) -> Self:
        """
        Configure a scan for values greater than the given value.

        Args:
            value: Value to compare against.
        """
        self._state.compare_type = ScanCompareType.BIGGER_THAN
        self._state.value = value
        self._state.extra = None
        return self

    def smaller(self, value: Any) -> Self:
        """
        Configure a scan for values smaller than the given value.

        Args:
            value: Value to compare against.
        """
        self._state.compare_type = ScanCompareType.SMALLER_THAN
        self._state.value = value
        self._state.extra = None
        return self

    def between(self, low: Any, high: Any) -> Self:
        """
        Configure a scan for values between two limits. (exclusive)

        Args:
            low: Lower bound of the scan.
            high: Upper bound of the scan.
        """
        self._state.compare_type = ScanCompareType.SMALLER_THAN
        self._state.value = low
        self._state.extra = high
        return self

    def increased(self, to: Any) -> Self:
        """Configure a scan for values that have increased to the given value."""
        self._state.compare_type = ScanCompareType.INCREASED
        self._state.value = None
        self._state.extra = to
        return self

    def increased_by(self, value: Any, by: Any) -> Self:
        """Configure a scan for values that have increased by a given amount.

        Args:
            value: Current value.
            by: Amount of increase.
        """
        self._state.compare_type = ScanCompareType.INCREASED_BY
        self._state.value = by
        self._state.extra = value
        return self

    def decreased(self, to: Any) -> Self:
        """Configure a scan for values that have decreased to the given value."""
        self._state.compare_type = ScanCompareType.DECREASED
        self._state.value = None
        self._state.extra = to
        return self

    def decreased_by(self, value: Any, by: Any) -> Self:
        """Configure a scan for values that have decreased by a given amount.

        Args:
            value: Current value.
            by: Amount of decrease.
        """
        self._state.compare_type = ScanCompareType.DECREASED_BY
        self._state.value = by
        self._state.extra = value
        return self

    def changed(self, value: Any) -> Self:
        """Configure a scan for values that have changed from the previous value."""
        self._state.compare_type = ScanCompareType.CHANGED
        self._state.value = None
        self._state.extra = value
        return self

    def unchanged(self, value: Any) -> Self:
        """Configure a scan for values that have remained unchanged from the previous value."""
        self._state.compare_type = ScanCompareType.UNCHANGED
        self._state.value = None
        self._state.extra = value
        return self

    def unknown_initial_value(self) -> Self:
        """Configure a scan for unknown initial values."""
        self._state.compare_type = ScanCompareType.UNKNOWN_INITIAL
        self._state.value = None
        self._state.extra = None
        return self
