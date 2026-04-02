from ps4debug import ResponseCode


class FakePS4:
    def __init__(self):
        self.allocations = []
        self.freed = []
        self.memory = {}

    async def allocate_memory(self, pid, length):
        addr = 0x1000
        self.allocations.append((pid, length))
        return addr

    async def free_memory(self, pid, address, length):
        self.freed.append((pid, address, length))

    async def read_memory(self, pid, address, length):
        return self.memory.get(address, b"\x00" * length)

    async def write_memory(self, pid, address, value):
        self.memory[address] = value
        return ResponseCode.SUCCESS

    async def change_protection(self, pid, addr, length, prot):
        return ResponseCode.SUCCESS

    async def call(self, pid, address, *args, **kwargs):
        return b"result"
