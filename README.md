# PyPS4debug
Fully asynchronous ps4debug implementation written in python.


## Install (pip)

```
pip install ps4debug
```

## Usage

A full example can be found at the end of this section!

### Basics
1. Running asynchronous code

    ```python
    import asyncio

    async def main():
        # Your asynchronous code goes here!
        ...

    if __name__ == '__main__':
        loop = asyncio.new_event_loop()
        loop.run_until_complete(main())
    ```

1. Sending the PS4Debug

    ```python
    from ps4debug import PS4Debug

    hostname = 'ip address or hostname'

    if PS4Debug.find_ps4() is None:
        await PS4Debug.send_ps4debug(hostname, port=9020)
    ```

1. Creating a PS4Debug instance

    Creating a PS4Debug instance does **not** connect to the PlayStation 4 yet.
    ```python
    from ps4debug import PS4Debug, PS4DebugException

    try:
        # Omitting the first parameter will cause it to search the network for a PlayStation 4 system.
        ps4 = PS4Debug()
    except PS4DebugException:
        # No PlayStation 4 running ps4debug was found.
        hostname = 'ip address or hostname'
        # Either ps4debug is not running.
        await PS4Debug.send_ps4debug('ip address or hostname', port=9020)
        # Or it was not reachable in this network. You should pass a hostname in that case.
        ps4 = PS4Debug('ip address or hostname')
    ```

1. Use the process list

    ```python
    from ps4debug import PS4Debug

    ps4 = PS4Debug()

    processes = await ps4.get_processes()

    for p in processes:
    print(p.name, p.pid)

    # You may search for a specific name and get its process id (pid):
    process_name = 'eboot.bin'
    pid = next((p.pid for p in processes if p.name == process_name), None)

    if pid is None:
       print(process_name, 'is not running!')
    ```

1. Using a factory function

    Using the above snippets we can create a nice factory function to handle creating new PS4Debug objects.
    ```python
    import asyncio
    from ps4debug import PS4Debug


    async def get_ps4(hostname: str | None) -> tuple[PS4Debug, int]:
        ps4 = PS4Debug(hostname)
        processes = await ps4.get_processes()
        pid = next((p.pid for p in processes if p.name == 'eboot.bin'), None)
        return ps4, pid


    async def main():
        ps4, eboot_pid = await get_ps4('10.0.0.0')
        print('hostname:', ps4.pool.host, 'eboot: ', eboot_pid)


    if __name__ == '__main__':
        loop = asyncio.new_event_loop()
        loop.run_until_complete(main())
    ```

1. Reading memory

    You can use the `read_*` functions to read memory from a process' memory.

    1. Raw memory

        Raw memory is returned as a mutable `bytearray`.<br />
        This way you can manipulate it directly like you would an array and parse it yourself.
        ```python
        data = await ps4.read_memory(pid, 0xCA88888, length=32)
        ```

    1. Primitive types

        Primitive data types can be easily read just by passing the process id (pid) and the address.
        ```python
        data = await ps4.read_bool(pid, address)
        data = await ps4.read_char(pid, address)
        data = await ps4.read_byte(pid, address)
        data = await ps4.read_ubyte(pid, address)
        data = await ps4.read_int16(pid, address)
        data = await ps4.read_uint16(pid, address)
        data = await ps4.read_int32(pid, address)
        data = await ps4.read_uint32(pid, address)
        data = await ps4.read_int64(pid, address)
        data = await ps4.read_uint64(pid, address)
        data = await ps4.read_float(pid, address)
        data = await ps4.read_double(pid, address)
        ```

    1. Structure

        For structures you can pass either a format string, a struct.Struct instance or use construct's Struct.<br />
        Here we are retrieving two floats. See the [Python docs](https://docs.python.org/3/library/struct.html#format-strings) for more information on format strings.
        ```python
        f1, f2 = await ps4.read_struct(pid, 0xCC001234, structure='<2f')
        ```

    1. String

        You can specify the encoding by passing the python charset name in the call.<br />
        By default `ascii` is used and the string is null-terminated.
        ```python
        data = await ps4.read_text(pid, 0xABCDEF, encoding='utf8')
        ```
        If a null-terminated string is not what you are looking for, you can also pass a `length` parameter to set a fix length to be read.
        ```python
        data = await ps4.read_text(pid, 0xABCDEF, length=32)
        ```

1. Writing to memory

    You can use the `write_*` functions to write to the process' memory.

    1. Raw memory

        You can pass any `bytes` or `bytearray` sequence as parameter.
        ```python
        status = await ps4.write_memory(pid, 0xCA88888, b'\xC3\xCC\x90')
        ```

    1. Primitive types

        Primitive data types can be easily written just by passing the process id (pid), the address and value.
        ```python
        status = await ps4.write_bool(pid, address, True)
        status = await ps4.write_char(pid, address, 'C')
        status = await ps4.write_byte(pid, address, -128)
        status = await ps4.write_ubyte(pid, address, 255)
        status = await ps4.write_int16(pid, address, -32000)
        status = await ps4.write_uint16(pid, address, 65000)
        status = await ps4.write_int32(pid, address, -1000000)
        status = await ps4.write_uint32(pid, address, 1000000)
        status = await ps4.write_int64(pid, address, -2 ** 42)
        status = await ps4.write_uint64(pid, address, 2 ** 42)
        status = await ps4.write_float(pid, address, -128e-2)
        status = await ps4.write_double(pid, address, 128e5)
        ```

    1. Structure

        For structures you can pass either a format string, a struct.Struct instance or use construct's Struct.<br />
        Here we are writing two floats. See the [Python docs](https://docs.python.org/3/library/struct.html#format-strings) for more information on format strings.
        ```python
        status = await ps4.write_struct(pid, 0xCC001234, structure='<2f', 2.5, -1.0)
        ```

    1. String

        You can specify the encoding by passing the python charset name in the call.<br />
        The null character is appended automatically if not provided.<br />
        By default `ascii` is used.
        ```python
        status = await ps4.write_text(pid, 0xABCDEF, 'We are injecting text here!', encoding='ascii')
        ```


### Advanced

1. Getting process information

    Using `get_process_info` You can find out what exact CUSA is running.

    ```python
    info = await ps4.get_process_info(pid)

    if info.title_id != 'CUSA012345':
        print('This program only works with CUSA012345!')
        return
    ```

    `get_process_maps` is helpful for getting an overview of the memory layout and find the base address.

    ```python
    maps_ = await ps4.get_process_maps(pid)

    # Filter for 'executable'
    maps_ = [m for m in maps_ if 'executable' in m.name]
    maps_.sort(key=lambda m: m.start)

    base_address = maps_[0].start if len(maps_) else None
    ```

1. Allocating Memory

    Allocating memory works by using the two methods `allocate_memory` and `free_memory`.
    For the length, try to use multiples of 4096, the default page size.

    ```python
    length = 4096
    address = await ps4.allocate_memory(pid, length)

    # Do something with your own memory section
    ...

    await ps4.free_memory(pid, address, length)

    ```

    You can easily wrap these methods to create a memory manager using closures.

    ```python
    ps4 = ...
    pid = ...
    allocated = {}

    async def allocate(id_: int = None, length: int = 4096) -> int:
        address = await ps4.allocate_memory(pid, length)
        if id_ in allocated:
            await free_memory(id_)
        allocated[id_] = (address, length)

    async def free(id_: int):
        if id_ in allocated:
            address, length = allocated[id_]
            await ps4.free_memory(pid, address, length)

    addr1 = allocate(100)
    addr2 = allocate(101)
    ...
    addr3 = allocate(100) # Frees old #100
    free(100)
    free(101)
    ```

    1. Using the allocation context

    The above `allocate_memory`, `free_memory` combination works fine but preferably you should stick to using an allocation context.

    ```python
    async with ps4.memory(pid) as memory:
        ...
    ```

    When this with-block is entered, memory will be allocated, and will be automatically freed when the block is exited.<br />
    You can use the `memory` variable to operate on the memory section assigned to you.

    ```python
    async with ps4.memory(pid) as memory:
        await ps4.write_int32(pid, memory.address, 42)
        # The context variable offers some useful methods too
        await memory.write(b'\x90' * 100)
    ```

1. Remote code execution

    1. Executing by address

        Executing code is as simple as calling `call` and telling it at which address to start executing a new thread.<br />

        ```python
        await ps4.call(pid, 0x8475610)
        ```

        The executing thread will have all its registers set to 0 and start with a bare minimum stack so be cautious when calling random functions in your debugging applications.

    1. Injecting assembly and executing it

        By allocating memory as above and executing the data we write in our memory section as assembly code we are able to execute code remotely.

        ```python
        async with ps4.memory(pid) as memory:
            assembly = b'\x90\x90\x90\xC3'
            await memory.write(assembly)
            await memory.call()
        ```

        `await memory.call()` is a shortcut for `await ps4.call(pid, memory.address)`

    1. Passing parameters

        PS4Debug allows 6 quadwords (more specifically 48 bytes) to be passed as parameters.<br />
        By default you can pass up to 6 integers to the call that are serialized to 1 quadword each.

        ```python
        await memory.call(1, 2, 3, 4, 5, 6)
        ```

        or outside of a context

        ```python
        await ps4.call(pid, address, 1, 2, 3, 4, 5, 6)
        ```

        This will cause PS4Debug to fill the registers before starting execution in reverse order:
        - `rdi` = `1`
        - `rsi` = `2`
        - `rdx` = `3`
        - `rcx` = `4`
        - `rbx` = `5`
        - `rax` = `6`

        In case you want to pass for example a float, you may use the keyword argument `parameter_format`.<br />
        See the [Python docs](https://docs.python.org/3/library/struct.html#format-strings) for more information on format strings.

        ```python
        await memory.call(1.0, 2.0, 3, 4, 5, 6, parameter_format='<2f4Q')
        ```

        The registers will still be filled the same way, so the remote code has to parse it (In this case by using bitwise operations).
        - `rdi` = `1.0` | `2.0`
        - `rsi` = `3`
        - `rdx` = `4`
        - `rcx` = `5`
        - `rbx` = `6`
        - `rax` = `0` &#129044; Because we are using 8 bytes less than before, we could even pass one more value!

    1. Retrieving return values

        Return values are taken from the `rax` register when remote execution ends.<br />
        To get your desired value back, make sure to `mov` it to the `rax` register.<br />
        See [stdcall](https://en.wikipedia.org/wiki/X86_calling_conventions#stdcall) for more information.

        ```asm
        mov rax, rdi ; rax <- rdi
        ret
        ```

        With the above injected assembly code, we can use the following call to echo its parameter back to us.

        ```python
        rax = await memory.call(1, 2, parameter_format='<2i')
        print(rax) # Will print '8589934593' (0x200000001)
        ```

        As with passing the parameters, this will return the two integers (4 bytes each) packed in one `long` (8 bytes).<br />
        You can either parse the data yourself using `int.from_bytes(rax[0:4], 'little')` or use the `output_format` parameter.

        ```python
        ret1, ret2 = await memory.call(50, -100, parameter_format='<2i', output_format='<2i')
        print(ret1, ret2) # Will correctly print '1 2'
        ```

        See the [Python docs](https://docs.python.org/3/library/struct.html#format-strings) for more information on format strings.

1. Debugging

    Similarly to allocating memory, a debugging context can be used to fire up the PS4Debug server and notify the PlayStation 4 system to connect to it.

    ```python
    async with ps4.debugger(pid, resume=True) as debugger:
        ...
    ```

    Entering this context will start a server on port 755, so make sure it is reachable for the PlayStation 4.
    When python exits this with-block the debugger and all breakpoints are stopped.

    Inside this with-block you are able to register breakpoints and do other relevant debugging operations like setting a breakpoint.

    ```python
    async def callback(event: ps4debug.BreakpointEvent):
        thread_id = event.interrupt.lwpid
        registers = event.interrupt.regs
        registers.rax = 42
        event.debugger.set_registers(thread_id, registers)
        

    async with ps4.debugger(pid, resume=True) as debugger:
        debugger.set_breakpoint(0, True, address, on_hit=callback)
    ```

1. Using async features

    Being completely asynchronous, it makes sense to use the full advantage of it.

    ```python
    tasks = [
        asyncio.create_task( ps4.write_int32(pid, 0x123456, 1000) ),
        asyncio.create_task( ps4.write_int32(pid, 0x789ABC, 2000) ),
        asyncio.create_task( ps4.write_int32(pid, 0x654210, 3000) ),
    ]

    pending = tasks
    while len(pending):
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        
        for task in done:
            response_code = await t

            if t is tasks[0]:
                print('0x123456:', response_code)
            else:
                print(response_code)

    ```

    The above code creates 3 tasks that each write an integer to a different address.<br />
    We then loop until all tasks are done (`while len(pending)`) and retrieve all completed tasks.<br />
    You can then iterate all completed tasks (in `done`) and `await` them individiually to get their return value.<br />
    The `is` operator is ideal to check which task completed.

1. Using `functools` to make code cleaner

    Sometimes always passing the same ps4debu object, the pid and the address gets quite tedious and unclean.<br />
    You can wrap it in a function, like so:

    ```python
    async def get_score():
        return await ps4.read_int32(pid=pid, address=0xABCDEF)

    score = await get_score()
    ```

    Or even build a repository/service class for your game:

    ```python
    class GameRepository(object):
        def __init__(self, ps4, pid):
            super(GameRepository, self).__init__()
            self.ps4 = ps4
            self.pid = pid

        async def get_score(self):
            return await self.ps4.read_int32(pid=self.pid, address=0xABCDEF)

    repository = GameRepository(ps4, pid)
    score = await repository.get_score()
    ```

    But that is very verbose. A more lightweight solution is to use the functools module.

    ```python
    import functools
    get_score = functools.partial(ps4.read_int32, pid=pid, address=0xABCDEF)

    score = await get_score()
    ```

    This would even work for calls!

    ```python
    injected_function = functools.partial(ps4.call, pid=pid, address=address, parameter_format='<2I')
    rax = await injected_function(42, 10)
    ```

### Full example

```python
import sys
import functools
import asyncio
import ps4debug

async def main(ip_address):
    # You may also retrieve the IP address using the find_ps4() function
    ip_address = ip_address or ps4debug.PS4Debug.find_ps4()

    ps4 = ps4debug.PS4Debug(ip_address)
    
    # Get processes
    processes = await ps4.get_processes()
    
    # Find specific process id
    pid = next((p.pid for p in processes if p.name == 'eboot.bin'), None)
    
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
        rax = await memory.call(1, 2, 3, 4, 5, 6, parameter_format='<6Q')
      
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
        async def breakpoint_hit(event: ps4debug.BreakpointEvent):
            ...
            # Do something with your breakpoint here!
        
        await debugger.set_breakpoint(0, True, 0x444111, on_hit=breakpoint_hit)
        # Alternatively to 'on_hit=...' you can use register_callback
        debugger.register_callback(breakpoint_hit)
    
    # Note! When the with block is exited, the debugger stops and all breakpoints will be disabled.
    # You can use asyncio.Event for example to keep the with block spinning.
    
    # Wait for everything to finish
    await asyncio.gather(*asyncio.all_tasks() - {asyncio.current_task()})


if __name__ == '__main__':
    # Normally you would use something like Typer for this
    args = sys.argv[1:]
    address = args[0] if len(args) else input('Enter the IP address of your PS4: ')
  
    # asyncio.run(main()) might throw an exception because of the ProactorEventLoop closing on Windows
    loop = asyncio.new_event_loop()
    loop.run_until_complete(main(address))

    # If you insist on using asyncio.run on Windows try to set the following snippet
    if sys.platform:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main(address))
```

_Note: Do NOT run the above code as is. Depending on what game is running your system or the game might crash_
