# PyPS4debug
ps4debug Implementation in python.

Example usage
```python
import sys
import functools
import ps4debug

def main(ip_address):
  with ps4debug.PS4Debugger(ip_address) as debugger:
    # Get processes
    processes = debugger.get_processes()
    
    # Find specific process id
    pid = next((pid for name, pid in processes if name == 'eboot.bin'), None)
    
    # Read memory
    gold = debugger.read_int32(pid, 0xCA88888)
    
    # Write memory
    if debugger.write_int32(pid, 0xCA44444, 9999) != ps4debug.ResponseCode.SUCCESS:
      print('There was an error!')
      
    # Remotely execute code (Code injection)
    with debugger.memory(pid, 4096) as address_memory:
      # Write your own assembly code to the system
      assembly = b'\x90\x90\x90\x90\xC3\x90'
      debugger.write_memory(pid, address_memory, assembly)
      
      # And call it. Parameters are limited to 48 bytes or 6 values.
      # See https://docs.python.org/3/library/struct.html#format-strings for more information on the '<6Q' part if you're confused.
      rpc_stub = debugger.install_rpc(pid)
      rax = debugger.call(pid, rpc_stub, address_memory, 1, 2, 3, 4, 5, 6, parameter_format='<6Q')
      
      print(f'Thread returned with rax = {rax}')

    # You may also use functools.partial to cleaner calls:
    get_gold = partial(debugger.read_int32, pid=pid, address=0xCA88888)
    set_gold = partial(debugger.write_int32, pid=pid, address=0xCA88888)
    injected_function = partial(debugger.call, pid=pid, rpc_stub=rpc_stub, address=allocated_memory, parameter_format='<6Q')

    gold = get_gold()
    set_gold(gold + 10)
    injected_function(1, 2, 3, 4, 5, 6)

  
if __name__ == '__main__':
  # Normally you would use something like Typer for this
  args = sys.argv[1:]
  ip_address = args[0] if len(args) else input('Enter the IP address of your PS4: ')
  main(ip_address)
```