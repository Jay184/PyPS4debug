from contextlib import asynccontextmanager


class FakeReader:
    def __init__(self, data: bytes = b""):
        self._buffer = data

    async def readexactly(self, n: int) -> bytes:
        chunk = self._buffer[:n]
        self._buffer = self._buffer[n:]
        return chunk


class FakeWriter:
    def __init__(self):
        self.written = bytearray()
        self.closed = False

    def write(self, data: bytes):
        self.written += data

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class FakePool:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer

    @asynccontextmanager
    async def get_socket(self):
        yield self.reader, self.writer
