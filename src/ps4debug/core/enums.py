from enum import IntEnum, IntFlag
from typing import Literal, Self


class ResponseCode(IntEnum):
    SUCCESS = 0x80000000
    ERROR = 0xF0000001
    TOO_MUCH_DATA = 0xF0000002
    DATA_NULL = 0xF0000003
    ALREADY_DEBUG = 0xF0000004
    INVALID_INDEX = 0xF0000005

    def is_success(self) -> bool:
        return self is ResponseCode.SUCCESS

    def is_error(self) -> bool:
        return self is ResponseCode.ERROR

    def should_raise(self) -> bool:
        if self in {
            self.ERROR,
            self.TOO_MUCH_DATA,
            self.DATA_NULL,
            self.ALREADY_DEBUG,
            self.INVALID_INDEX,
        }:
            return True

        return (int(self) >> 28) == 0xF

    @classmethod
    def decode(cls, value: bytes | bytearray, *, byteorder: Literal["little", "big"] = "little") -> Self:
        if len(value) != 4:
            raise ValueError(f"Expected 4 bytes, got {len(value)}")

        decoded = int.from_bytes(value, byteorder=byteorder)

        try:
            return cls(decoded)
        except ValueError as e:
            raise ValueError(f"Unknown response code: {decoded:#x}") from e

    def encode(self, *, byteorder: Literal["little", "big"] = "little") -> bytes:
        return int(self).to_bytes(4, byteorder=byteorder)


class VMProtection(IntFlag):
    """Memory protection flags."""
    NONE = 0x00
    READ = 0x01
    WRITE = 0x02
    EXECUTE = 0x04

    DEFAULT = READ | WRITE
    ALL = READ | WRITE | EXECUTE

    NO_CHANGE = 0x08
    COPY = 0x10


class ScanValueType(IntEnum):
    """Value types for scanning."""
    UINT8 = 0
    INT8 = 1
    UINT16 = 2
    INT16 = 3
    UINT32 = 4
    INT32 = 5
    UINT64 = 6
    INT64 = 7
    FLOAT = 8
    DOUBLE = 9
    BYTE_ARRAY = 10
    STRING = 11

    @classmethod
    def numeric_types(cls) -> set[Self]:
        return {
            cls.UINT8, cls.INT8,
            cls.UINT16, cls.INT16,
            cls.UINT32, cls.INT32,
            cls.UINT64, cls.INT64,
            cls.FLOAT, cls.DOUBLE,
        }

    @classmethod
    def variable_types(cls) -> set[Self]:
        return {
            cls.BYTE_ARRAY,
            cls.STRING,
        }

    def allowed_compare_types(self) -> set["ScanCompareType"]:
        return {
            cmp for cmp in ScanCompareType
            if self in cmp.allowed_value_types()
        }


class ScanCompareType(IntEnum):
    """Scanning modes."""
    EXACT = 0
    FUZZY = 1
    BIGGER_THAN = 2
    SMALLER_THAN = 3
    BETWEEN = 4
    INCREASED = 5
    INCREASED_BY = 6
    DECREASED = 7
    DECREASED_BY = 8
    CHANGED = 9
    UNCHANGED = 10
    UNKNOWN_INITIAL = 11

    def requires_scan_value(self) -> bool:
        return self in {
            ScanCompareType.EXACT,
            ScanCompareType.FUZZY,
            ScanCompareType.BIGGER_THAN,
            ScanCompareType.SMALLER_THAN,
            ScanCompareType.BETWEEN,
            ScanCompareType.INCREASED_BY,
            ScanCompareType.DECREASED_BY,
        }

    def requires_extra_value(self) -> bool:
        return self in {
            ScanCompareType.BETWEEN,
            ScanCompareType.INCREASED,
            ScanCompareType.INCREASED_BY,
            ScanCompareType.DECREASED,
            ScanCompareType.DECREASED_BY,
            ScanCompareType.CHANGED,
            ScanCompareType.UNCHANGED,
        }

    def allowed_value_types(self) -> set[ScanValueType]:
        numeric = ScanValueType.numeric_types()
        string_like = {ScanValueType.STRING, ScanValueType.BYTE_ARRAY}

        if self == self.FUZZY:
            return {ScanValueType.FLOAT, ScanValueType.DOUBLE}

        if self in {
            self.BIGGER_THAN,
            self.SMALLER_THAN,
            self.BETWEEN,
            self.INCREASED,
            self.INCREASED_BY,
            self.DECREASED,
            self.DECREASED_BY,
            self.CHANGED,
            self.UNCHANGED,
        }:
            return numeric

        if self in {self.EXACT, self.UNKNOWN_INITIAL}:
            return numeric | string_like

        return set()

    def validate(self, value_type: ScanValueType, *, has_scan: bool, has_extra: bool) -> None:
        if value_type not in self.allowed_value_types():
            raise ValueError(f"{self.name} not valid for {value_type.name}")

        if self.requires_scan_value() and not has_scan:
            raise ValueError(f"{self.name} requires scan_value")

        if self.requires_extra_value() and not has_extra:
            raise ValueError(f"{self.name} requires extra_value")


class ProcessState(IntEnum):
    RESUME = 0
    STOP = 1
    KILL = 2


class NotificationType(IntEnum):
    UNKNOWN_USB = 1
    TOO_MANY_USB = 2
    CONNECT_VIA_USB = 3
    BATTERY_LEVEL_LOW = 4
    DISCONNECTED = 5
    TOO_MANY_USB2 = 6
    CANNOT_CONNECT_BT = 7
    CANNOT_CONNECT_CONTROLLER = 9
    CANNOT_CONNECT_MOUSE_OR_KB = 10
    CANNOT_USE_FEATURE_OF_KB = 11
    DEVICE_NOT_SUPPORTED = 12
    CANNOT_USE_WIRELESS_DS3 = 13
    COMPANION_APP_CONNECTED_ = 14
    COMPANION_APP_DISCONNECTED = 15
    REMOTE_PLAY_CONNECTED = 16
    REMOTE_PLAY_DISCONNECTED = 17
    REMOTE_PLAY_SCREEN_BLOCKED = 18
    REMOTE_PLAY_SCREEN_UNBLOCKED = 19
    DISK_SPACE_FREE = 22
    LAN_CABLE_DISCONNECTED = 23
    WIFI_CONNECTION_LOST = 24
    CANNOT_CONNECT_NETWORK = 25
    LOGGED_IN = 26
    ACCOUNT_BANNED = 28
    ACCOUNT_SUSPENDED = 29
    UPDATE_SYSTEM = 30
    PSN_BUSY = 31
    PSN_MAINTENANCE = 32
    PSN_UNAVAILABLE = 33
    SIGN_INTO_PSN = 35
    PSN_SIGNED_OUT = 36
    UPDATE_APP_FOR_NETWORK = 37
    UPDATE_SYSTEM_FOR_NETWORK = 38
    PSN_AGE_RESTRICTION = 39
    APPLICATION_WILL_EXPIRE = 40
    APPLICATION_SUSPENDING = 41
    PARTY_CHAT_AUDIO_PRIORITIZED = 42
    GAME_CHAT_AUDIO_PRIORITIZED = 43
    CANNOT_USE_VOICE = 45
    KICKED_FROM_PARTY = 46
    REMOVED_FROM_PARTY_ERROR = 47
    CANNOT_TAKE_SCREENSHOT = 48
    BLOCKED_SCENE = 49
    CANNOT_DISPLAY_MENU = 50
    ONLY_MIC_BROADCASTED = 51
    BROADCAST_STOPPED = 53
    SONG_PLAYBACK_STOPPED = 54
    # TODO Add the rest...
    CUSTOM = 222


class WatchPointLengthType(IntEnum):
    LEN_1 = 0
    LEN_2 = 1
    LEN_4 = 3
    LEN_8 = 2


class WatchPointBreakType(IntEnum):
    EXEC = 0
    WRITE_ONLY = 1
    READ_WRITE = 3
