import asyncio
import pytest

from ps4debug.find_device_protocol import FindDeviceProtocol


class DummyTransport:
    def __init__(self):
        self.sent = []
        self.closed = False

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_connection_sends_broadcast():
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    magic = 0xFFFFAAAA

    proto = FindDeviceProtocol(magic, fut)
    transport = DummyTransport()

    proto.connection_made(transport)
    data, (host, port) = transport.sent[0]

    assert host.endswith("255")
    assert port == 1010
    assert data == magic.to_bytes(4, "little")


@pytest.mark.asyncio
async def test_valid_response_sets_future():
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    magic = 0xFFFFAAAA

    proto = FindDeviceProtocol(magic, fut)

    proto.datagram_received(
        magic.to_bytes(4, "little"),
        ("192.168.1.100", 12345),
    )

    assert fut.done()
    assert fut.result() == "192.168.1.100"


@pytest.mark.asyncio
async def test_invalid_response_is_ignored():
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    magic = 0xFFFFAAAA

    proto = FindDeviceProtocol(magic, fut)

    proto.datagram_received(
        b"\x00\x00\x00\x00",
        ("192.168.1.100", 12345),
    )

    assert not fut.done()


@pytest.mark.asyncio
async def test_future_not_overwritten_if_already_done():
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    magic = 0xFFFFAAAA

    proto = FindDeviceProtocol(magic, fut)

    proto.datagram_received(
        magic.to_bytes(4, "little"),
        ("192.168.1.100", 12345),
    )

    # second valid response should be ignored
    proto.datagram_received(
        magic.to_bytes(4, "little"),
        ("192.168.1.200", 12345),
    )

    assert fut.result() == "192.168.1.100"


@pytest.mark.asyncio
async def test_error_sets_exception():
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    magic = 0xFFFFAAAA

    proto = FindDeviceProtocol(magic, fut)

    exc = RuntimeError("network error")
    proto.error_received(exc)

    assert fut.done()
    with pytest.raises(RuntimeError):
        fut.result()
