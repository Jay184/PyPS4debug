# PyPS4debug

A modern, asynchronous Python client for interacting with a PlayStation 4 running a compatible debug payload.

This library provides high-level APIs for process inspection, memory access, debugging, and remote code execution over a TCP interface.

Tested with `ps4debug` v1.0.15 and v1.1.19.

---

## ⚠️ Disclaimer

Interacting with system memory and debugging processes can **damage your device**, cause instability, or lead to permanent hardware failure.

This project does **not** implement the payload or server running on the target device—it only provides a client for communicating with it.

**You assume all responsibility** for any damage, data loss, or unintended behavior resulting from the use of this library.

---

## ⚠️ Important Notes

* Code examples in this documentation are **not directly runnable**.
* Values such as:

  * IP addresses
  * Process IDs (PID)
  * Memory addresses
    will differ depending on your environment and target system.

You are expected to adapt examples to your specific setup.

---

## Features

* Automatic device discovery on local network
* Async TCP client with connection pooling
* Process enumeration and inspection
* Memory read/write and allocation
* Kernel memory access
* Remote procedure calls (RPC)
* ELF and raw payload injection
* Debugging session management
* Memory scanning utilities
* Console output and notifications

---

## Installation

```bash
pip install ps4debug
```

---

## Quick Start

```python
import asyncio
from ps4debug import PS4Debug

async def main():
    # Discover a PS4 running the debug payload
    ps4 = await PS4Debug.discover()

    # Get version info
    version = await ps4.get_version()
    print("Version:", version)

    # List processes
    processes = await ps4.get_processes()
    for proc in processes:
        print(proc)

asyncio.run(main())
```

---

## Core Concepts

### Client

The `PS4Debug` class is the main entry point. It manages connections and exposes all high-level functionality.

```python
from ps4debug import PS4Debug

ps4 = PS4Debug("192.168.0.10")
```

---

### Processes

Retrieve and inspect running processes:

```python
processes = await ps4.get_processes()
info = await ps4.get_process_info(pid)
maps = await ps4.get_process_maps(pid)
```

---

### Payloads

#### Raw Payload

```python
await ps4.send_payload(payload_bytes)
```

#### ELF Injection

```python
await ps4.send_elf(pid, elf_bytes)
```

---

### Console Interaction

```python
await ps4.print("Hello from Python")
await ps4.notify("Done")
```

---

### System Control

```python
await ps4.reboot()

kernel_base = await ps4.get_kernel_base()
data = await ps4.read_kernel_memory(address, length)
```

---

### Memory Access

#### Raw Memory

```python
data = await ps4.read_memory(pid, address, length)
await ps4.write_memory(pid, address, b"\x90\x90")
```

---

### Allocated Memory (Recommended)

The preferred way to work with memory is through `MemoryContext`, which manages allocation and cleanup automatically.

```python
async with ps4.memory(pid, length=1024) as mem:
    await mem.write(b"hello")
    data = await mem.read(5)
```

Key properties:

* Memory is allocated on `__aenter__`
* Memory is **always freed on `__aexit__`**
* Safe bounds checking is enforced for reads/writes
* Prevents leaks and invalid memory reuse

**Important:**
Once the context exits, the memory is no longer valid on the target system.

---

#### Structured Memory Access

`MemoryContext` supports structured data using `ConstructModel`:

```python
value = await mem.read_model(MyModel)
await mem.write_model(my_model_instance)
```

---

### Memory Views (Typed Access)

`MemoryView` provides a type-safe interface over memory.

#### Creating a View

```python
view = ps4.view(pid, address)
```

Or from an allocation:

```python
view = mem.view()
```

#### Reading Values

```python
value = await view.uint32(offset=0x10).get()
```

Shorthand:

```python
flag = await view.boolean(offset=0x20)
```

#### Writing Values

```python
await view.uint32(offset=0x10).set(1337)
```

Shorthand:

```python
await view.uint32(offset=0x10)(1337)
```

#### Offsetting Views

```python
sub = view.offset(by=0x100)
value = await sub.uint16()
```

#### Supported Types

* Integers: `int8`, `uint8`, `int16`, `uint16`, `int32`, `uint32`, `int64`, `uint64`
* Floating point: `floating`, `double`
* Boolean: `boolean`
* Raw bytes: `bytes(size)`
* Strings: `string(length)`
* Structured models: `model(MyModel)`

#### Strings

```python
text = await view.string(length=32, offset=0x0)
```

Or null-terminated:

```python
text = await view.read_variable_text()
```

---

### Memory Protection

```python
await mem.change_protection(prot)
```

---

### Executing Code from Allocated Memory

Allocated memory can be used as an execution target:

```python
result = await mem.call(params=my_model, result_model=MyReturnModel)
```

This is a convenience wrapper around `PS4Debug.call()` using the allocated address.

---

## Remote Procedure Calls (RPC)

Execute functions inside a target process:

```python
result = await ps4.call(
    pid=pid,
    address=0x12345678,
    params=my_model,
    return_model=MyReturnModel
)
```

There is a `CallRegisters` model that can be used to get started.
Its values are serialized to 8-byte unsigned integers each.

```python
from ps4debug import CallRegisters

registers = CallRegisters(
    rdi=1,
    rsi=2,
    rdx=3,
    rcx=4,
    r8=5,
    r9=6,
)
```

### Return Model Requirements

Return values can be parsed into a model using a custom base class:

```python
from typing import Annotated
from construct import Int32ul
from pydantic_construct import ConstructModel

class MyReturnModel(ConstructModel):
    number: Annotated[int, Int32ul]
```

Constraints:

* The model must inherit from `ConstructModel`
* The total size must not exceed **8 bytes** (size of the `RAX` register)
* If no return model is provided, raw bytes are returned

---

## Debugging

Debugging is exposed through an async context manager returning a `DebuggingContext`.

```python
async with ps4.debugger(pid) as dbg:
    await dbg.resume_process()
```

Only one debugging session can be active at a time.

---

### Breakpoints

Breakpoints are managed using indexed slots.

```python
index = await dbg.add_breakpoint(address=0x12345678, callback=lambda event: ...)
```

You can also configure them manually:

```python
await dbg.set_breakpoint(index, address, callback, enabled=True)
```

* Limited number of breakpoint slots
* Managed internally via index and address mapping

---

### Breakpoint Callbacks

Callbacks are async functions triggered when a breakpoint is hit:

```python
async def on_break(event):
    print("Breakpoint hit at", hex(event.interrupt.regs.rip))
    event.resume = True  # resume execution automatically

await dbg.add_breakpoint(address, on_break)
```

You can also register a global callback:

```python
dbg.register_callback(global_handler)
```

Execution order:

1. Global callback
2. Breakpoint-specific callback

---

### Watchpoints

Hardware watchpoints can be configured:

```python
await dbg.set_watchpoint(index, address, enabled=True)
```

* Supports read/write monitoring
* Limited hardware slots

---

### Process Control

```python
await dbg.stop_process()
await dbg.resume_process()
await dbg.kill_process()
```

---

### Threads

```python
threads = await dbg.get_threads()
info = await dbg.get_thread_info(thread_id)
```

Thread-level control exists but may depend on server-side support:

```python
await dbg.stop_thread(thread_id)
await dbg.resume_thread(thread_id)
```

---

### Registers

#### General Purpose

```python
regs = await dbg.get_registers(thread_id)
await dbg.set_registers(thread_id, regs)
```

#### Floating Point

```python
fp = await dbg.get_fp_registers(thread_id)
```

#### Debug Registers

```python
dbg_regs = await dbg.get_debug_registers(thread_id)
```

---

### Single Stepping

```python
await dbg.single_step()
```

Executes exactly one instruction.

---

### Event Handling Model

* Debug events are received over a local TCP server
* Events are processed asynchronously
* Callbacks are awaited, the debugger will not continue until all callbacks ran
* Execution can optionally resume automatically via `event.resume = True` (default behavior)

---

## Memory Scanning

Memory scanning is performed using a builder-based query system.

`PS4Debug.scan` returns a **local scanner**, meaning:

* Memory is downloaded from the target
* Scanning happens on the client side

---

### Basic Usage

There are three ways to run scan queries.

#### Bounded queries

`scanner.query()` returns a builder object that can run itself.

```python
scanner = ps4.scan(pid)

results = await (
    scanner
    .query()
    .int32()
    .exact(100)
    .execute()
)
```

#### Context builder

```python
async with scanner.executor() as q:
    q.int32()
    q.exact(100)
```

The query will execute when the context is exited.

#### Manual

If the above two methods don't suit your needs you can simply create a builder.

```python
builder = ScanBuilder()
builder.int32().exact(100)

scanner.execute(builder)
```

---

### Builder Pattern

The `ScanBuilder` allows incremental query construction:

```python
builder = scanner.query()

builder.int32().bigger(100).aligned(True)
results = await builder.execute()
```

---

### Common Scan Types

#### Exact Match

```python
.int32().exact(1337)
```

#### Range

```python
.int32().between(low=100, high=200)
```

#### Increased / Decreased

```python
.increased(to=150)
.decreased(to=50)
.changed(None)
```

#### Unknown Initial Value

```python
.unknown_initial_value()
```

---

### Filtering

#### Memory Bounds

```python
.bounds(start, end)
```

#### Module Filtering

```python
.only_module("libSce.*")
```

#### Pause Target

```python
.pause(True)
```

---

### Iterative Scanning

```python
async for addr, value in scanner.query().int32().exact(100).execute_iter():
    print(hex(addr), value)
```

* Supports large result sets
* Updates internal scan state automatically

---

### Scan Lifecycle

Each session tracks:

* `initial` values
* `previous` values

Subsequent scans operate as refinements rather than full scans.

---

## Error Handling

Operations may raise multiple exception types depending on the failure source:

* `PS4DebugException` – protocol-level or server-side failures
* `ValueError`, `RuntimeError` – invalid usage or state
* `asyncio` exceptions – timeouts, cancellations
* Parsing/validation errors from underlying libraries (e.g. model decoding from `Pydantic` or `construct`)

Example:

```python
from ps4debug.exceptions import PS4DebugException

try:
    await ps4.reboot()
except PS4DebugException as e:
    print("Operation failed:", e)
```

---

## License

This project is licensed under the **0BSD License**.

You are free to use, modify, and distribute this software with minimal restrictions.

---

## Contributing

The project is considered functionally complete, but improvements and refinements are welcome. Focus areas:

* Improving API ergonomics
* Expanding documentation and examples
* Adding test coverage

---

## Acknowledgements

- [`ps4debug`](https://github.com/GoldHEN/ps4debug)
