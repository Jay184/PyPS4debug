import pytest
from tests.fakes import FakePool, FakeWriter, FakeReader

from ps4debug import PS4Debug, PS4DebugException, ResponseCode


@pytest.mark.asyncio
async def test_get_version_reads_string():
    # length = 4, data = "1.00"
    data = (4).to_bytes(4, "little") + b"1.00"

    reader = FakeReader(data)
    writer = FakeWriter()

    client = PS4Debug("127.0.0.1", pool=FakePool(reader, writer))

    version = await client.get_version()

    assert version == "1.00"


@pytest.mark.asyncio
async def test_call_rejects_large_params():
    client = PS4Debug("127.0.0.1")

    class BigModel:
        struct = type("S", (), {"sizeof": lambda: 999999})

    import pytest
    with pytest.raises(ValueError):
        await client.call(1, 0x1000, params=BigModel())


@pytest.mark.asyncio
async def test_command_failure_raises():
    # ResponseCode.FAILURE assumed encoded as non-zero
    failure_code = (1).to_bytes(4, "little")

    reader = FakeReader(failure_code)
    writer = FakeWriter()

    client = PS4Debug("127.0.0.1", pool=FakePool(reader, writer))

    with pytest.raises(ValueError):
        await client.reboot()


@pytest.mark.asyncio
async def test_print_writes_data():
    success_bytes = ResponseCode.SUCCESS.to_bytes(4, "little")
    reader = FakeReader(success_bytes)  # SUCCESS
    writer = FakeWriter()

    client = PS4Debug("127.0.0.1", pool=FakePool(reader, writer))

    await client.print("hello")

    assert b"hello\x00" in writer.written


@pytest.mark.asyncio
async def test_notify_writes_data():
    success_bytes = ResponseCode.SUCCESS.to_bytes(4, "little")
    reader = FakeReader(success_bytes)  # SUCCESS
    writer = FakeWriter()

    client = PS4Debug("127.0.0.1", pool=FakePool(reader, writer))

    await client.notify("hello")

    assert b"hello\x00" in writer.written
