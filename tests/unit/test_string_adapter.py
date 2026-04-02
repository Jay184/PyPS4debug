import pytest

from hypothesis import given, strategies as st
import construct

from ps4debug.core.base import NullTerminatedPaddedString


def test_decode_truncates_at_null():
    adapter = NullTerminatedPaddedString(construct.GreedyString("utf-8"))
    assert adapter._decode("abc\x00def", None, None) == "abc"


def test_decode_no_null_returns_same():
    adapter = NullTerminatedPaddedString(construct.GreedyString("utf-8"))
    assert adapter._decode("abcdef", None, None) == "abcdef"


def test_decode_empty_string():
    adapter = NullTerminatedPaddedString(construct.GreedyString("utf-8"))
    assert adapter._decode("", None, None) == ""


def test_decode_only_null():
    adapter = NullTerminatedPaddedString(construct.GreedyString("utf-8"))
    assert adapter._decode("\x00", None, None) == ""


def test_encode_is_identity():
    adapter = NullTerminatedPaddedString(construct.GreedyString("utf-8"))
    assert adapter._encode("abc", None, None) == "abc"


def test_struct_parsing_trims_nulls():
    process_map = construct.Struct(
        name=NullTerminatedPaddedString(construct.PaddedString(8, "ascii")),
        start=construct.Int32ul,
    )

    data = b"abc\x00\x00\x00\x00\x00" + (123).to_bytes(4, "little")

    parsed = process_map.parse(data)

    assert parsed.name == "abc"
    assert parsed.start == 123


def test_roundtrip_with_padding():
    process_map = construct.Struct(
        name=NullTerminatedPaddedString(construct.PaddedString(8, "ascii")),
    )

    built = process_map.build(dict(name="abc"))
    parsed = process_map.parse(built)

    assert parsed.name == "abc"


@given(st.text())
def test_decode_never_contains_null_after_processing(s):
    adapter = NullTerminatedPaddedString(construct.GreedyString("utf-8"))
    result = adapter._decode(s, None, None)

    assert "\x00" not in result


@given(st.text())
def test_decode_matches_split_behavior(s):
    adapter = NullTerminatedPaddedString(construct.GreedyString("utf-8"))
    result = adapter._decode(s, None, None)

    assert result == s.split("\x00", 1)[0]


@given(st.binary(min_size=0, max_size=32))
def test_padded_string_integration(data):
    process_map = construct.Struct(
        name=NullTerminatedPaddedString(construct.PaddedString(32, "ascii")),
    )

    # constrain to valid ascii
    data = bytes(b & 0x7F for b in data)
    data = data.ljust(32, b"\x00")[:32]

    parsed = process_map.parse(data)

    decoded = data.decode("ascii")
    expected = decoded.split("\x00", 1)[0]

    assert parsed.name == expected


def test_decode_requires_string():
    adapter = NullTerminatedPaddedString(construct.GreedyString("utf-8"))

    with pytest.raises(TypeError):
        adapter._decode(b"abc\x00def", None, None)  # noqa
