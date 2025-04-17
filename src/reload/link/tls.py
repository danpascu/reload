# SPDX-FileCopyrightText: 2024-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

__all__ = 'TLSEndpoint',  # noqa: COM818


import asyncio
import contextlib
import ssl
from collections.abc import Hashable
from functools import lru_cache
from itertools import count
from typing import Protocol, Self

from reload import aio
from reload.link.common import FramedMessageBuffer, OutgoingMessage, PendingMessage
from reload.messages import AckFrame, DataFrame, FramedMessage
from reload.messages.datamodel import FramedMessageType


class X509IdentityProvider(Hashable, Protocol):
    def configure(self, context: ssl.SSLContext) -> None:
        """Configure the SSL context with the X509 certificate, private key and authority"""
        ...


class TLSEndpoint:
    max_packet_size: int = 16384

    tls_close_timeout: int = 3  # how long to wait for confirmation on TLS shutdown

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, identity: X509IdentityProvider) -> None:
        self.identity = identity
        self._reader = reader
        self._writer = writer
        self._input_buffer: FramedMessageBuffer = FramedMessageBuffer()
        self._recv_channel = aio.Channel[bytes](10)
        self._send_channel = aio.Channel[OutgoingMessage](10)
        self._frame_sequence = count(1)
        self._pending_message: PendingMessage | None = None
        self._closed = False
        self._done: asyncio.Future[None] = asyncio.Future()
        self._control_task: asyncio.Task = asyncio.create_task(self._link_manager())

    @property
    def closed(self) -> bool:
        return self._closed

    @staticmethod
    @lru_cache
    def get_tls_context(purpose: ssl.Purpose, identity: X509IdentityProvider) -> ssl.SSLContext:
        context = ssl.create_default_context(purpose)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
        identity.configure(context)
        return context

    @classmethod
    async def connect(cls, address: str, port: int, identity: X509IdentityProvider) -> Self:
        ...

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._send_channel.close()
        self._notify_done()
        await self._control_task

    async def receive(self) -> bytes:
        # if self._closed:
        #     raise aio.ClosedResourceError
        try:
            return await self._recv_channel.receive()
        except aio.EndOfChannel as exc:
            raise aio.ClosedResourceError from exc

    async def send(self, data: bytes) -> None:
        if self._closed:
            raise aio.ClosedResourceError
        await self._send_channel.send(message := OutgoingMessage(data))
        await message

    def _notify_done(self, status: type[Exception] | Exception | None = None) -> None:
        if not self._done.done():
            if status is None:
                self._done.set_result(None)
            else:
                self._done.set_exception(status)

    async def _link_manager(self) -> None:
        self._done = asyncio.Future()
        try:
            async with asyncio.TaskGroup() as group:
                receiver_task = group.create_task(self._receiver_loop(), name=f'TLS Link {self!r} receiver')  # NOTE: change self to nodeid
                __sender_task = group.create_task(self._sender_loop(), name=f'TLS Link {self!r} sender')
                await self._done
                self._writer.close()
                await self._writer.wait_closed()
                await receiver_task
        except* (BrokenPipeError, ConnectionError, TimeoutError, aio.BrokenResourceError, aio.ClosedResourceError):
            # The TLS connection is down, TLS was closed by the peer or we're not getting ACKs
            # for our messages. In all these cases attempting a TLS shutdown is pointless.
            pass
        finally:
            async for message in self._send_channel:
                message.notify_sender(status=aio.ClosedResourceError)
            await self._recv_channel

    async def _receiver_loop(self) -> None:
        connection_status = None
        try:
            self._input_buffer.clear()
            with self._recv_channel:
                while True:
                    data = await self._reader.read(self.max_packet_size)
                    if not data:
                        connection_status = aio.ClosedResourceError
                        break
                    self._input_buffer.write(data)
                    try:
                        await self._process_incoming_messages()
                    except ValueError:
                        self._writer.close()
                        await self._writer.wait_closed()
                        connection_status = aio.ClosedResourceError
                        break
        except (BrokenPipeError, TimeoutError):
            connection_status = aio.BrokenResourceError
        except ConnectionError:
            connection_status = aio.ClosedResourceError
        finally:
            # NO async code should be called after calling self._notify_done
            # as it will be automatically cancelled.
            self._closed = True
            self._send_channel.close()
            if self._pending_message is not None:
                self._pending_message.notify_done(status=connection_status)
                self._pending_message = None
            self._notify_done(status=connection_status)

    async def _process_incoming_messages(self) -> None:
        for message in self._input_buffer:
            match message.frame:
                case AckFrame() as frame:
                    if self._pending_message is not None and self._pending_message.match(frame):
                        self._pending_message.notify_done()
                        self._pending_message = None
                case DataFrame() as frame:
                    ack = FramedMessage(type=FramedMessageType.ack, frame=AckFrame(sequence=frame.sequence, received=0xffffffff))
                    self._writer.write(ack.to_wire())
                    await self._writer.drain()
                    await self._recv_channel.send(frame.message)

    async def _sender_loop(self) -> None:
        # Send one message at a time and wait for the ACK before moving to the next message
        # (this implies that the DataFrame and the FramedMessage can be reused, which is
        # cheaper than recreating them for every message).
        data_frame = DataFrame(sequence=0, message=b'')  # sequence and message will be set for each transmission
        framed_message = FramedMessage(type=FramedMessageType.data, frame=data_frame)

        with self._send_channel:
            async for message in self._send_channel:
                data_frame.message = message.data
                self._pending_message = pending_message = PendingMessage(framed_message)
                timeout = 0.5
                for _ in range(5):
                    if self._closed:
                        message.notify_sender(status=aio.ClosedResourceError)
                        self._pending_message = None
                        return
                    sequence = next(self._frame_sequence)
                    data_frame.sequence = sequence
                    pending_message.sequence_numbers.add(sequence)
                    try:
                        self._writer.write(pending_message.message.to_wire())
                        await self._writer.drain()
                    except (BrokenPipeError, TimeoutError):
                        message.notify_sender(status=aio.BrokenResourceError)
                        self._pending_message = None
                        return
                    except ConnectionError:
                        message.notify_sender(status=aio.ClosedResourceError)
                        self._pending_message = None
                        return
                    else:
                        message.notify_sender()
                    try:
                        async with asyncio.timeout(timeout):
                            await asyncio.shield(pending_message.done)
                    except TimeoutError:
                        timeout *= 2
                        continue
                    except (aio.ClosedResourceError, aio.BrokenResourceError):
                        return
                    else:
                        break
                else:
                    # No ACK for the message after 5 transmissions. Consider the connection dead.
                    self._pending_message = None
                    with contextlib.suppress(BrokenPipeError, ConnectionError, TimeoutError):
                        self._writer.close()
                        await self._writer.wait_closed()
                    return

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: object, exc_value: object, exc_traceback: object) -> None:
        await self.close()

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> bytes:
        try:
            return await self.receive()
        except aio.ClosedResourceError as exc:
            raise StopAsyncIteration from exc
