import asyncio
import contextlib
from contextlib import AbstractAsyncContextManager
from asyncio import StreamReader, StreamWriter


class SocketPool:
    """
    A bounded asynchronous pool of TCP connections.

    This pool maintains up to ``limit`` concurrent open connections to a given
    host and port. Connections are reused when possible and returned to the pool
    after use.

    Internally, idle connections are stored in a LIFO queue to favor reuse of
    recently used sockets.

    The pool supports both:
    - eager initialization via ``start()``
    - lazy connection creation on demand

    Notes:
        - The pool enforces a hard cap on total live connections.
        - Connections detected as closed are discarded and replaced lazily.
        - The class is safe for concurrent use across multiple coroutines.
    """

    def __init__(self, host: str, port: int, limit: int = 8):
        """
        Initialize the socket pool.

        Args:
            host: Target hostname or IP address.
            port: Target TCP port.
            limit: Maximum number of concurrent open connections.
        """
        self.host = host
        self.port = port

        self._limit = limit
        self._created = 0

        self._pool: asyncio.LifoQueue[tuple[StreamReader, StreamWriter]] = asyncio.LifoQueue(maxsize=limit)
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        """
        Pre-create all connections up to the configured limit.

        After calling this, the pool is fully populated and no connections
        will be created lazily until some are dropped.
        """
        for _ in range(self._limit):
            reader, writer = await asyncio.open_connection(self.host, self.port)
            await self._pool.put((reader, writer))
        self._created = self._limit

    async def close(self) -> None:
        """
        Close all idle connections currently held in the pool.

        This does not affect connections that are currently checked out.
        Those will be closed when returned if already marked as closing.
        """
        while not self._pool.empty():
            _, writer = await self._pool.get()
            writer.close()
            await writer.wait_closed()

    def get_socket(self) -> AbstractAsyncContextManager[tuple[StreamReader, StreamWriter]]:
        """
        Acquire a connection from the pool.

        This method returns an async context manager that yields a
        ``(StreamReader, StreamWriter)`` pair.

        Behavior:
            - Reuses an idle connection if available.
            - Creates a new connection if below the limit.
            - Otherwise waits until a connection is returned.

        Yields:
            A tuple of (StreamReader, StreamWriter).

        The connection is automatically returned to the pool when the
        context exits, unless it is closed or broken, in which case it
        is discarded.
        """
        @contextlib.asynccontextmanager
        async def _impl():
            reader, writer = None, None

            async with self._lock:
                if not self._pool.empty():
                    reader, writer = await self._pool.get()
                elif self._created < self._limit:
                    reader, writer = await asyncio.open_connection(self.host, self.port)
                    self._created += 1

            if reader is None or writer is None:
                reader, writer = await self._pool.get()

            try:
                yield reader, writer
            except Exception:
                if writer is not None:
                    writer.close()
                    await writer.wait_closed()

                async with self._lock:
                    self._created -= 1

                raise
            else:
                if writer.is_closing() or reader.at_eof():
                    async with self._lock:
                        self._created -= 1
                else:
                    await self._pool.put((reader, writer))

        # This fixes typing issues around the decorator.
        return _impl()
