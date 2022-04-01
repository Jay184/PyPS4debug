# PyPS4debug
ps4debug implementation in python.

## Install (pip)

```
pip install ps4debug
```


Example usage
```python
import sys
import functools
import ps4debug

def main(ip_address):
  # You may also retrieve the IP address using the find_ps4() function
  ip_address = ip_address or ps4debug.PS4Debug.find_ps4()

  with ps4debug.PS4Debug(ip_address) as ps4:
    # Get processes
    processes = ps4.get_processes()
    
    # Find specific process id
    pid = next((pid for name, pid in processes if name == 'eboot.bin'), None)
    
    # Read memory
    gold = ps4.read_int32(pid, 0xCA88888)
    
    # Write memory
    if ps4.write_int32(pid, 0xCA44444, 9999) != ps4debug.ResponseCode.SUCCESS:
      print('There was an error!')
      
    # Remotely execute code (Code injection)
    with ps4.memory(pid, 4096) as address_memory:
      # Write your own assembly code to the system
      assembly = b'\x90\x90\x90\x90\xC3\x90'
      ps4.write_memory(pid, address_memory, assembly)
      
      # And call it. Parameters are limited to 48 bytes or 6 values.
      # See https://docs.python.org/3/library/struct.html#format-strings for more information on the '<6Q' part if you're confused.
      rpc_stub = ps4.install_rpc(pid)
      rax = ps4.call(pid, rpc_stub, address_memory, 1, 2, 3, 4, 5, 6, parameter_format='<6Q')
      
      print(f'Thread returned with rax = {rax}')

    # You may also use functools.partial to cleaner calls:
    get_gold = partial(ps4.read_int32, pid=pid, address=0xCA88888)
    set_gold = partial(ps4.write_int32, pid=pid, address=0xCA88888)
    injected_function = partial(ps4.call, pid=pid, rpc_stub=rpc_stub, address=allocated_memory, parameter_format='<6Q')

    gold = get_gold()
    set_gold(gold + 10)
    injected_function(1, 2, 3, 4, 5, 6)

  
if __name__ == '__main__':
  # Normally you would use something like Typer for this
  args = sys.argv[1:]
  ip_address = args[0] if len(args) else input('Enter the IP address of your PS4: ')
  main(ip_address)
```