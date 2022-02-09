import socket
import struct
from enum import Enum
from functools import partial, partialmethod


# TODO implement these
CMD_VERSION = 0xBD000001

CMD_PROC_MAPS = 0xBDAA0004
CMD_PROC_INTALL = 0xBDAA0005
CMD_PROC_CALL = 0xBDAA0006
CMD_PROC_ELF = 0xBDAA0007
CMD_PROC_PROTECT = 0xBDAA0008
CMD_PROC_SCAN = 0xBDAA0009
CMD_PROC_INFO = 0xBDAA000A
CMD_PROC_ALLOC = 0xBDAA000B
CMD_PROC_FREE = 0xBDAA000C

CMD_DEBUG_ATTACH = 0xBDBB0001
CMD_DEBUG_DETACH = 0xBDBB0002
CMD_DEBUG_BREAKPT = 0xBDBB0003
CMD_DEBUG_WATCHPT = 0xBDBB0004
CMD_DEBUG_THREADS = 0xBDBB0005
CMD_DEBUG_STOPTHR = 0xBDBB0006
CMD_DEBUG_RESUMETHR = 0xBDBB0007
CMD_DEBUG_GETREGS = 0xBDBB0008
CMD_DEBUG_SETREGS = 0xBDBB0009
CMD_DEBUG_GETFPREGS = 0xBDBB000A
CMD_DEBUG_SETFPREGS = 0xBDBB000B
CMD_DEBUG_GETDBGREGS = 0xBDBB000C
CMD_DEBUG_SETDBGREGS = 0xBDBB000D
CMD_DEBUG_STOPGO = 0xBDBB0010
CMD_DEBUG_THRINFO = 0xBDBB0011
CMD_DEBUG_SINGLESTEP = 0xBDBB0012

CMD_KERN_BASE = 0xBDCC0001
CMD_KERN_READ = 0xBDCC0002
CMD_KERN_WRITE = 0xBDCC0003

CMD_CONSOLE_REBOOT = 0xBDDD0001
CMD_CONSOLE_END = 0xBDDD0002
CMD_CONSOLE_PRINT = 0xBDDD0003
CMD_CONSOLE_NOTIFY = 0xBDDD0004
CMD_CONSOLE_INFO = 0xBDDD0005


class ResponseCodes(Enum):
   SUCCESS = 0x80000000
   ERROR = 0xF0000001
   TOO_MUCH_DATA = 0xF0000002
   DATA_NULL = 0xF0000003
   ALREADY_DEBUG = 0xF0000004
   INVALID_INDEX = 0xF0000005

   @classmethod
   def from_bytes(cls, value):
      decoded = int.from_bytes(value, 'little')
      return next((p for p in cls if p.value == decoded), None)


class PS4Debugger(object):
   """Offers standard ps4debug methods."""

   def __init__(self, host, port=744):
      super(PS4Debugger, self).__init__()
      self.endpoint = (host, port)

      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.sock.connect(self.endpoint)

      # TODO Define structs to avoid creating them each (un)pack()-call
      pass

   def __del__(self):
      self.sock.shutdown(socket.SHUT_RDWR)
      self.sock.close()
      del self.sock


   def get_status(self):
      byte_data = self.sock.recv(4)
      return ResponseCodes.from_bytes(byte_data)

   def send_command(self, code, payload=None):
      magic = 0xFFAABBCC
      header = struct.pack('<3I', magic, code, len(payload) if payload else 0)
      self.sock.send(header)

      if payload and len(payload):
         self.sock.send(payload)

      return self.get_status()


   def read_memory(self, pid, address, length):
      payload = struct.pack('<iQi', pid, address, length)
      self.send_command(0xBDAA0002, payload)
      return self.sock.recv(length)

   def read_struct(self, pid, address, format):
      size = struct.calcsize(format)
      data = self.read_memory(pid, address, size)
      data = struct.unpack(format, data)
      return data

   def __read_type(self, pid, address, format):
      # Only unpacks tuple for use in read_<type>
      return self.read_struct(pid, address, format)[0]

   read_bool = partialmethod(__read_type, format='<?')
   read_char = partialmethod(__read_type, format='<c')
   read_byte = partialmethod(__read_type, format='<b')
   read_ubyte = partialmethod(__read_type, format='<B')
   read_int16 = partialmethod(__read_type, format='<h')
   read_uint16 = partialmethod(__read_type, format='<H')
   read_int32 = partialmethod(__read_type, format='<i')
   read_uint32 = partialmethod(__read_type, format='<I')
   read_int64 = partialmethod(__read_type, format='<q')
   read_uint64 = partialmethod(__read_type, format='<Q')
   #read_ptr = partialmethod(__read_type, format='<p') # Doesn't exist in python
   #read_uptr = partialmethod(__read_type, format='<P') # Just use an integer instead
   read_float = partialmethod(__read_type, format='<f')
   read_double = partialmethod(__read_type, format='<d')

   def read_text(self, pid, address, encoding='ascii', length=None):
      if length:
         data = self.read_memory(pid, address, length)
         return data.decode(encoding)

      chunk_size = 32
      chunk = self.read_memory(pid, address, chunk_size)
      data = chunk

      while b'\0' not in chunk:
         chunk = self.read_memory(pid, address + len(data), chunk_size)
         data += chunk

      data = data[:data.index(b'\0')]
      return data.decode(encoding)


   def write_memory(self, pid, address, value):
      payload = struct.pack('<iQi', pid, address, len(value))
      self.send_command(0xBDAA0003, payload)
      self.sock.send(value)
      return self.get_status()

   def write_struct(self, pid, address, format, *value):
      data = struct.pack(format, *value)
      return self.write_memory(pid, address, data)

   def write_int(self, pid, address, value):
      return self.write_struct(pid, address, '<i', value)


   def get_processes(self):
      self.send_command(0xBDAA0001)

      count = int.from_bytes(self.sock.recv(4), 'little')
      bytes_expected = count * 36 # 36 is max string length
      bytes_received = 0
      processes = b''

      while bytes_received < bytes_expected:
         processes += self.sock.recv(bytes_expected - bytes_received)
         bytes_received += len(processes)

      return [(processes[i:processes.index(b'\x00', i)].decode('ascii'),
         int.from_bytes(processes[i+32:i+36], 'little')) for i in range(0, bytes_expected, 36)]

