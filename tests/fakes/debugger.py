from ps4debug import ResponseCode


class FakeDebugger:
    def __init__(self):
        self.memory = {}
        self.next_address = 0x1000

    async def allocate_memory(self, pid: int, length: int) -> int:
        addr = self.next_address
        self.memory[addr] = bytearray(length)
        self.next_address += length
        return addr

    async def free_memory(self, pid: int, address: int, length: int) -> None:
        self.memory.pop(address, None)

    async def read_memory(self, pid: int, address: int, length: int):
        for base, buf in self.memory.items():
            if base <= address < base + len(buf):
                offset = address - base
                return bytes(buf[offset:offset + length])
        return None

    async def write_memory(self, pid: int, address: int, value: bytes):
        for base, buf in self.memory.items():
            if base <= address < base + len(buf):
                offset = address - base
                buf[offset:offset + len(value)] = value
                return ResponseCode.SUCCESS
        return ResponseCode.ERROR


    async def call(self, pid, address, params, result_model, **kwargs):
        # Just echo back first 8 bytes as "rax"
        data = params.model_dump_bytes()
        return (bytes(data[:8]),)

    async def change_protection(self, *args, **kwargs):
        return ResponseCode.SUCCESS
