from ps4debug.memory.scanner.session import ScanSession


class FakeSession(ScanSession):
    def __init__(self):
        super().__init__(ps4=None, pid=123)
        self.scan_called = False
        self.refresh_called = False

    async def _scan(self, query):
        self.scan_called = True
        for i in range(3):
            yield i, i * 10

    async def _refresh(self, query):
        self.refresh_called = True
        for i in range(2):
            yield i, i * 100
