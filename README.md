# PyPS4debug
Fully asynchronous ps4debug implementation written in python.

## Install (pip)

```
pip install ps4debug
```


Example usage
```python
import sys
import functools
import asyncio
import ps4debug

async def main(ip_address):
    # You may also retrieve the IP address using the find_ps4() function
    ip_address = ip_address or ps4debug.PS4Debug.find_ps4()

    async with ps4debug.PS4Debug(ip_address) as ps4:
        # Get processes
        processes = await ps4.get_processes()
    
        # Find specific process id
        pid = next((pid for name, pid in processes if name == 'eboot.bin'), None)
    
        # Read memory
        gold = await ps4.read_int32(pid, 0xCA88888)
    
        # Write memory
        status = await ps4.write_int32(pid, 0xCA44444, 9999)
        if status != ps4debug.ResponseCode.SUCCESS:
            print('There was an error!')
            
        # Let's do something where the async features shines
        tasks = [
            asyncio.create_task( ps4.write_int32(pid, 0x123456, 1000) ),
            asyncio.create_task( ps4.write_int32(pid, 0x789ABC, 2000) ),
            asyncio.create_task( ps4.write_int32(pid, 0x654210, 3000) ),
        ]
        
        pending = tasks
        while len(pending):
            # We iterate until all tasks are done but we stop waiting and handle already finished tasks.
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                # Let's say the first task was something special and want its result, we can use 'is' for that:
                # Note: If you use Coroutines, which are wrapped into tasks by asyncio. The following will not work.
                response_code = await t
                if t is tasks[0]:
                    print('0x123456:', response_code)
                else:
                    print(response_code)

        # Remotely execute code (Code injection)
        async with ps4.memory(pid, 4096) as memory:
            # Write your own assembly code to the system
            assembly = b'\x90\x90\x90\x90\xC3\x90'
            await memory.write(assembly)
      
            # And call it. Parameters are limited to 48 bytes or 6 values.
            # See https://docs.python.org/3/library/struct.html#format-strings for more information on the '<6Q' part if you're confused.
            rpc_stub = await ps4.install_rpc(pid)
            rax = await memory.call(1, 2, 3, 4, 5, 6, rpc_stub=rpc_stub, parameter_format='<6Q')
      
            print(f'Thread returned with rax = {rax}')

            # You may also use functools.partial for cleaner calls:
            get_gold = functools.partial(ps4.read_int32, pid=pid, address=0xCA88888)
            set_gold = functools.partial(ps4.write_int32, pid=pid, address=0xCA88888)
            injected_function = functools.partial(ps4.call, pid=pid, rpc_stub=rpc_stub, address=memory, parameter_format='<6Q')

            gold = await get_gold()
            await set_gold(gold + 10)
            await injected_function(1, 2, 3, 4, 5, 6)
            
        # Attaching the debugger works similarly
        async with ps4.debugger(pid, resume=True) as debugger:
            # Inside this context, a server on port 755 is being run to listen for debugger events.
            pass  # Debugging features are not implemented yet ;)


if __name__ == '__main__':
    # Normally you would use something like Typer for this
    args = sys.argv[1:]
    address = args[0] if len(args) else input('Enter the IP address of your PS4: ')
  
    # asyncio.run(main()) might throw an exception because of the ProactorEventLoop closing
    loop = asyncio.new_event_loop()
    loop.run_until_complete(main(address))
```

_Note: Do not run the above code as is. Depending on what game is running your system or the game might crash_
