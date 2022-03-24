import socket
import struct
from enum import Enum
from functools import partial, partialmethod


CMD_VERSION = 0xBD000001
CMD_PROC_LIST = 0xBDAA0001
CMD_PROC_READ = 0xBDAA0002
CMD_PROC_WRITE = 0xBDAA0003
CMD_PROC_MAPS = 0xBDAA0004
CMD_PROC_INSTALL = 0xBDAA0005
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


class ResponseCode(Enum):
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

class VMProtection(Enum):
   VM_PROT_NONE = 0x00
   VM_PROT_READ = 0x01
   VM_PROT_WRITE = 0x02
   VM_PROT_EXECUTE = 0x04
   VM_PROT_DEFAULT = 0x03
   VM_PROT_ALL = 0x07
   VM_PROT_NO_CHANGE = 0x08
   VM_PROT_COPY = 0x10


class AllocatedMemoryContext(object):
   def __init__(self, debugger, pid, length):
      super(AllocatedMemoryContext, self).__init__()
      self.debugger = debugger
      self.pid = pid
      self.length = length

   def __enter__(self):
      self.memory_address = self.debugger.allocate_memory(self.pid, self.length)
      return self.memory_address

   def __exit__(self, type, value, traceback):
      self.debugger.free_memory(self.pid, self.memory_address, self.length)



class PS4Debugger(object):
   """Offers standard ps4debug methods."""

   def __init__(self, host, port=744):
      super(PS4Debugger, self).__init__()
      self.endpoint = (host, port)
      self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      # TODO Define structs to avoid creating them each (un)pack()-call
      pass

   def __enter__(self):
      self.sock.connect(self.endpoint)
      return self

   def __exit__(self, type, value, traceback):
      self.sock.shutdown(socket.SHUT_RDWR)
      self.sock.close()
      del self.sock

   def get_status(self):
      byte_data = self.sock.recv(4)
      return ResponseCode.from_bytes(byte_data)

   def send_command(self, code, payload=None, status=True):
      magic = 0xFFAABBCC
      header = struct.pack('<3I', magic, code, len(payload) if payload else 0)
      self.sock.send(header)

      if payload and len(payload):
         self.sock.send(payload)

      return self.get_status() if status else None

   def get_version(self):
      self.send_command(CMD_VERSION, status=False)

      length = self.sock.recv(4)
      length = int.from_bytes(length, 'little')

      version = self.sock.recv(length)
      return version.decode('ascii')
   def print(self, text):
      text += '\0'
      payload = len(text).to_bytes(4, 'little')
      self.send_command(CMD_CONSOLE_PRINT, payload, status=False)
      self.sock.send(text.encode('ascii'))
      return self.get_status()
   def notify(self, text, message_type=222):
      text += '\0'
      payload = struct.pack('<2I', message_type, len(text))
      self.send_command(CMD_CONSOLE_NOTIFY, payload, status=False)
      self.sock.send(text.encode('ascii'))
      return self.get_status()

   def get_processes(self):
      PROC_LIST_ENTRY_SIZE = 36
      self.send_command(CMD_PROC_LIST)

      count = self.sock.recv(4)
      count = int.from_bytes(count, 'little')
      bytes_expected = count * PROC_LIST_ENTRY_SIZE
      bytes_received = 0
      processes = b''

      while bytes_received < bytes_expected:
         processes += self.sock.recv(bytes_expected - bytes_received)
         bytes_received += len(processes)

      return [self.__parse_proc_entry(processes[i:i+PROC_LIST_ENTRY_SIZE]) for i in range(0, bytes_expected, PROC_LIST_ENTRY_SIZE)]
   def get_process_maps(self, pid):
      PROC_MAP_ENTRY_SIZE = 58
      pid_bytes = pid.to_bytes(4, 'little')
      self.send_command(CMD_PROC_MAPS, pid_bytes)

      count = self.sock.recv(4)
      count = int.from_bytes(count, 'little')

      data = self.sock.recv(count * PROC_MAP_ENTRY_SIZE)
      return [self.__parse_map_entry(data[i:i+PROC_MAP_ENTRY_SIZE]) for i in range(0, count * PROC_MAP_ENTRY_SIZE, PROC_MAP_ENTRY_SIZE)]
   def get_process_info(self, pid):
      PROC_PROC_INFO_SIZE = 184
      pid_bytes = pid.to_bytes(4, 'little')
      self.send_command(CMD_PROC_INFO, pid_bytes)
      data = self.sock.recv(PROC_PROC_INFO_SIZE)

      # TODO this doesn't quite work
      pid = int.from_bytes(data[:4], 'little')
      name = data[4:40].decode('ascii').strip('\0')
      path = data[40:108].decode('ascii').strip('\0')
      title_id = data[108:124].decode('ascii').strip('\0')
      content_id = data[124:188].decode('ascii').strip('\0')

      print(data)
      print(pid, name, path, title_id, content_id)
      return pid, name, path, title_id, content_id

   def allocate_memory(self, pid, length):
      pid_bytes = pid.to_bytes(4, 'little')
      length_bytes = length.to_bytes(4, 'little')
      self.send_command(CMD_PROC_ALLOC, pid_bytes + length_bytes)
      address = self.sock.recv(8)
      return int.from_bytes(address, 'little')
   def free_memory(self, pid, address, length):
      payload = struct.pack('<iQI', pid, address, length)
      return self.send_command(CMD_PROC_FREE, payload)
   def change_protection(self, pid, address, length, new_protection):
      payload = struct.pack('<iQ2I', pid, address, length, new_protection.value)
      return self.send_command(CMD_PROC_PROTECT, payload)

   def memory(self, pid, length):
      return AllocatedMemoryContext(self, pid, length)

   def install_rpc(self, pid):
      pid_bytes = pid.to_bytes(4, 'little')
      self.send_command(CMD_PROC_INSTALL, pid_bytes)
      data = self.sock.recv(8)
      return int.from_bytes(data, 'little')
   def call(self, pid, rpc_stub, address, parameter_format = '', *args):
      CMD_PROC_CALL_PACKET_SIZE = 68
      PROC_CALL_SIZE = 12
      payload = struct.pack('<i2Q', pid, rpc_stub, address)

      assert struct.calcsize(parameter_format) <= CMD_PROC_CALL_PACKET_SIZE - len(payload)
      parameters = struct.pack(parameter_format, *args)
      payload += parameters
      self.send_command(CMD_PROC_CALL, payload)

      rax = self.sock.recv(PROC_CALL_SIZE)
      res, rax = struct.unpack('<iQ', rax)
      assert res == 70
      return rax
   def load_elf(self, pid, elf_path):
      # TODO https://github.com/jogolden/ps4debug/blob/b446dced06009705c6f8d70e79113637d1690210/libdebug/cpp/source/PS4DBG.cpp#L380
      pass


   def read_memory(self, pid, address, length):
      payload = struct.pack('<iQi', pid, address, length)
      self.send_command(CMD_PROC_READ, payload)
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
      self.send_command(CMD_PROC_WRITE, payload)
      self.sock.send(value)
      return self.get_status()
   def write_struct(self, pid, address, format, *value):
      data = struct.pack(format, *value)
      return self.write_memory(pid, address, data)

   def __write_type(self, pid, address, value, format):
      return self.write_struct(pid, address, format, value)

   write_bool = partialmethod(__write_type, format='<?')
   write_char = partialmethod(__write_type, format='<c')
   write_byte = partialmethod(__write_type, format='<b')
   write_ubyte = partialmethod(__write_type, format='<B')
   write_int16 = partialmethod(__write_type, format='<h')
   write_uint16 = partialmethod(__write_type, format='<H')
   write_int32 = partialmethod(__write_type, format='<i')
   write_uint32 = partialmethod(__write_type, format='<I')
   write_int64 = partialmethod(__write_type, format='<q')
   write_uint64 = partialmethod(__write_type, format='<Q')
   write_float = partialmethod(__write_type, format='<f')
   write_double = partialmethod(__write_type, format='<d')

   def write_text(self, pid, address, value, encoding='ascii'):
      data = value.encode(encoding) + b'\x00'
      return self.write_memory(pid, address, data)


   def __parse_proc_entry(self, entry):
      name_end = entry.index(b'\x00')
      name = entry[:name_end].decode('ascii')
      pid = int.from_bytes(entry[-4:], 'little')
      return name, pid

   def __parse_map_entry(self, entry):
      name_end = entry.index(b'\x00')
      name = entry[:name_end].decode('ascii')
      info = struct.unpack('<3QH', entry[32:])
      return name, *info
