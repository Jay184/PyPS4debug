from asyncio import DatagramProtocol, Future, DatagramTransport
from typing import Any
import socket


def get_local_ips():
    return {
        info[4][0]
        for info in socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET)
    }


class FindDeviceProtocol(DatagramProtocol):
    """
    asyncio DatagramProtocol used to discover a device via UDP broadcast.

    On connection, this protocol sends a 4-byte "magic" value to the broadcast
    address (255.255.255.255:1010). It then listens for incoming datagrams and
    resolves the provided Future with the sender's IP address if a response
    matches the expected magic payload.

    Attributes:
        broadcast_data (bytes): The 4-byte magic value sent and expected in responses.
        on_response (Future): Future that is completed with the sender IP (str)
            when a valid response is received.
        transport (DatagramTransport | None): Transport used for sending/receiving.
    """

    def __init__(self, magic: int, on_response: Future) -> None:
        self.broadcast_data = magic.to_bytes(4, "little")
        self.local_ips = get_local_ips()
        self.on_response = on_response
        self.transport: DatagramTransport | None = None

    def connection_made(self, transport: DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport
        self.transport.sendto(self.broadcast_data, ("192.168.2.255", 1010))

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        host, port = addr

        if host in self.local_ips:
            return

        if not self.on_response.done() and data == self.broadcast_data:
            host, port = addr
            self.on_response.set_result(host)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc and not self.on_response.done():
            self.on_response.set_exception(exc)

    def error_received(self, exc: Exception) -> None:
        if not self.on_response.done():
            self.on_response.set_exception(exc)
