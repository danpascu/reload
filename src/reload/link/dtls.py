# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio
import enum
import struct
from collections.abc import Generator, Hashable, Iterator
from dataclasses import dataclass, field
from functools import lru_cache
from itertools import count
from typing import Any, ClassVar, Protocol, Self, overload

from aioice.candidate import Candidate
from aioice.ice import Connection as ICEConnection
from cryptography.hazmat.bindings.openssl.binding import Binding
from OpenSSL import SSL

from reload import aio
from reload.messages import AckFrame, DataFrame, FramedMessage
from reload.messages.datamodel import FramedMessageType

__all__ = 'DTLSEndpoint', 'Purpose', 'ICEPeer', 'BadRecord'  # noqa: RUF022


binding = Binding()
_ffi: Any = binding.ffi
_lib: Any = binding.lib

SSL_OP_NO_RENEGOTIATION: int = _lib.SSL_OP_NO_RENEGOTIATION

OPTIMAL_MTU = 1500 - 48
MINIMAL_MTU = 576 - 28


class DTLSConnection(SSL.Connection):
    def bio_pending(self) -> int:
        """
        Get the amount of data that can be read from the BIO.

        Call the OpenSSL function BIO_get_mem_data with a NULL pointer
        on the outgoing BIO, to obtain the amount of data in the BIO.
        See the OpenSSL manual for more details.

        :return: how many bytes are available to read from the BIO
        """
        if self._from_ssl is None:
            raise TypeError('Connection sock was not None')

        return _lib.BIO_get_mem_data(self._from_ssl, _ffi.NULL)

    def get_dtls_timeout(self) -> float | None:
        """
        Get the DTLS timeout for the current operation.

        Call the OpenSSL function DTLSv1_get_timeout on this connection.
        See the OpenSSL manual for more details.

        :return: the timeout value in seconds as a floating point number or
                  None if the timeout is undefined in the current context.
        """
        s = _ffi.new('time_t *')
        u = _ffi.new('long *')
        result = _lib.Cryptography_DTLSv1_get_timeout(self._ssl, s, u)
        return s[0] + u[0] / 1_000_000 if result == 1 else None

    def handle_dtls_timeout(self) -> bool:
        """
        Handle retransmissions after a timeout during the DTLS handshake.

        Call the OpenSSL function DTLSv1_handle_timeout on this connection.
        See the OpenSSL manual for more details.

        :return: a boolean value indicating if retransmissions were sent
        """
        # DTLSv1_handle_timeout return value:
        # -1 - error
        #  0 - it didn't do anything (the timer is not expired)
        #  1 - it successfully handled retransmissions
        result = _lib.DTLSv1_handle_timeout(self._ssl)
        if result < 0:
            self._raise_ssl_error(self._ssl, result)
        return result > 0


class BadRecord(Exception):
    pass


type RecordFieldOwner = Record


class RecordHeaderFieldDescriptor:
    name: str | None
    size: int
    _slice: slice


class RecordHeaderBytesField(RecordHeaderFieldDescriptor):
    def __init__(self, size: int) -> None:
        self.name = None
        self.size = size

    def __set_name__(self, owner: type[RecordFieldOwner], name: str) -> None:
        if self.name is None:
            self.name = name
            self._slice = slice(index := sum(field.size for field in owner._header_fields_), index + self.size)
            owner._header_fields_ += (self, )
        elif name != self.name:
            raise TypeError(f'cannot assign the same {self.__class__.__name__} to two different names: {self.name} and {name}')

    @overload
    def __get__(self, instance: None, owner: type[RecordFieldOwner]) -> Self: ...

    @overload
    def __get__(self, instance: RecordFieldOwner, owner: type[RecordFieldOwner] | None = None) -> bytes: ...

    def __get__(self, instance: RecordFieldOwner | None, owner: type[RecordFieldOwner] | None = None) -> Self | bytes:
        if instance is None:
            return self
        if self.name is None:
            raise TypeError(f'cannot use {self.__class__.__name__} instance without calling __set_name__ on it.')
        return instance.__dict__.setdefault(self.name, instance[self._slice])


class RecordHeaderIntField(RecordHeaderFieldDescriptor):
    def __init__(self, size: int) -> None:
        self.name = None
        self.size = size

    def __set_name__(self, owner: type[RecordFieldOwner], name: str) -> None:
        if self.name is None:
            self.name = name
            self._slice = slice(index := sum(field.size for field in owner._header_fields_), index + self.size)
            owner._header_fields_ += (self, )
        elif name != self.name:
            raise TypeError(f'cannot assign the same {self.__class__.__name__} to two different names: {self.name} and {name}')

    @overload
    def __get__(self, instance: None, owner: type[RecordFieldOwner]) -> Self: ...

    @overload
    def __get__(self, instance: RecordFieldOwner, owner: type[RecordFieldOwner] | None = None) -> int: ...

    def __get__(self, instance: RecordFieldOwner | None, owner: type[RecordFieldOwner] | None = None) -> Self | int:
        if instance is None:
            return self
        if self.name is None:
            raise TypeError(f'cannot use {self.__class__.__name__} instance without calling __set_name__ on it.')
        return instance.__dict__.setdefault(self.name, int.from_bytes(instance[self._slice]))


class Record(bytes):
    """
    Byte representation of a DTLS record.

    The record has the following structure:
     - 1 byte content type
     - 2 bytes version
     - 2 bytes epoch
     - 6 bytes sequence_no
     - 2 bytes payload length (unsigned big-endian)
     - payload
    """

    _header_struct_: ClassVar[struct.Struct] = struct.Struct('!11xH')
    _header_fields_: ClassVar[tuple[RecordHeaderFieldDescriptor, ...]] = ()

    # All header fields must be specified and they need to be in order,
    # as their position in the header is calculated based on all the
    # other header fields defined before them.

    content_type = RecordHeaderIntField(size=1)
    version = RecordHeaderBytesField(size=2)
    epoch = RecordHeaderIntField(size=2)
    sequence_no = RecordHeaderIntField(size=6)

    def __new__(cls, data: bytes, position: int = 0) -> Self:
        if not 0 <= position < len(data):
            raise ValueError('position is outside of the data stream')
        try:
            payload_length, = cls._header_struct_.unpack_from(data, position)
        except struct.error as exc:
            raise BadRecord('invalid DTLS record header') from exc
        if position + cls._header_struct_.size + payload_length > len(data):
            raise BadRecord('record too short')
        record_length = cls._header_struct_.size + payload_length
        record = data[position : position + record_length]
        return super().__new__(cls, record)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: content_type={self.content_type}, version={self.version.hex()}, epoch={self.epoch}, sequence_no={self.sequence_no}, payload={self.payload!r}>'

    @property
    def payload(self) -> bytes:
        return self[self._header_struct_.size:]


class Packetizer:
    """
    Split a byte stream into groups of packets that honor to the MTU.

    Take the byte stream produced by OpenSSL and split it into individual
    DTLS records. When iterated, the packetizer combines the DTLS records
    to create network packets according to the specified MTU.
    The original DTLS records are available through the records attribute.
    """

    def __init__(self, data: bytes, mtu: int) -> None:
        records = []
        position = 0
        while position < len(data):
            record = Record(data, position=position)
            position += len(record)
            records.append(record)
        self.records = records
        self.mtu = mtu

    def __iter__(self) -> Iterator[bytearray]:
        packet = bytearray()
        for record in self.records:
            if not packet or len(packet) + len(record) <= self.mtu:
                packet.extend(record)
            else:
                yield packet
                packet = bytearray(record)
        if packet:
            yield packet


class Purpose(enum.Enum):
    AttachRequest = 'attach-request'
    AttachResponse = 'attach-response'


@dataclass
class ICEPeer:
    username: str
    password: str
    candidates: list[Candidate]


@dataclass
class OutgoingMessage:
    data: bytes
    sent: asyncio.Future[None] = field(init=False, default_factory=asyncio.Future)

    def __await__(self) -> Generator[Any, None, None]:
        return self.sent.__await__()

    def notify_sender(self, *, status: Exception | type[Exception] | None = None) -> None:
        if self.sent.done():
            return
        if status is None:
            self.sent.set_result(None)
        else:
            self.sent.set_exception(status)


@dataclass
class PendingMessage:
    message: FramedMessage
    sequence_numbers: set[int] = field(init=False, default_factory=set)
    done: asyncio.Future[None] = field(init=False, default_factory=asyncio.Future)


class FramedMessageBuffer(Iterator[FramedMessage]):
    _ack_structure: ClassVar[struct.Struct] = struct.Struct('!BII')
    _data_preamble: ClassVar[struct.Struct] = struct.Struct('!BIBH')  # emulate a 24 bit unsigned integer with a high/low pair of 8/16 bit unsigned integers

    def __init__(self, initial_data: bytes | bytearray = b'', /) -> None:
        self._buffer = bytearray(initial_data)

    def __repr__(self) -> str:
        return f'{self.__class__.__qualname__}({bytes(self._buffer)!r})'

    def __len__(self) -> int:
        return len(self._buffer)

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> FramedMessage:
        buffer_length = len(self._buffer)
        if buffer_length == 0:
            raise StopIteration
        frame_type = self._buffer[0]
        match frame_type:
            case FramedMessageType.ack:
                message_length = self._ack_structure.size
                if buffer_length < message_length:
                    raise StopIteration
                message = FramedMessage.from_wire(self._buffer[:message_length])
                self._buffer[0:message_length] = b''
                return message
            case FramedMessageType.data:
                prefix_length = self._data_preamble.size
                if buffer_length < prefix_length:
                    raise StopIteration
                _, _, len_hi, len_lo = self._data_preamble.unpack_from(self._buffer)
                data_length = (len_hi << 16) + len_lo
                message_length = prefix_length + data_length
                if buffer_length < message_length:
                    raise StopIteration
                message = FramedMessage.from_wire(self._buffer[:message_length])
                self._buffer[0:message_length] = b''
                return message
            case _:
                raise ValueError(f'Input data does not contain a FramedMessage structure: {frame_type} is not a valid FramedMessageType')

    def clear(self) -> None:
        self._buffer.clear()

    def write(self, data: bytes | bytearray) -> None:
        self._buffer.extend(data)


class X509IdentityProvider(Hashable, Protocol):
    def configure(self, context: SSL.Context) -> None:
        """Configure the SSL context with the X509 certificate, private key and authority"""
        ...


class DTLSEndpoint:  # NOTE @dan: rename to DTLSLink?
    stun_server: tuple[str, int] | None = 'stun.antisip.com', 3478

    ice_connect_timeout: int = 30   # how long to wait for ice to establish connection
    dtls_hello_timeout: int = 30    # how long the server waits for a client hello
    dtls_shutdown_timeout: int = 3  # how long to wait for confirmation on DTLS shutdown

    max_packet_size: int = 16384
    max_retransmissions: int = 2

    def __init__(self, purpose: Purpose, identity: X509IdentityProvider, *, mtu: int = OPTIMAL_MTU) -> None:
        ice_controlling = purpose is Purpose.AttachRequest
        self.identity = identity
        self.ice = ICEConnection(ice_controlling=ice_controlling, stun_server=self.stun_server)
        self.dtls = DTLSConnection(self.get_dtls_context(identity))
        self._input_buffer: FramedMessageBuffer = FramedMessageBuffer()
        self._recv_channel = aio.Channel[bytes](10)
        self._send_channel = aio.Channel[OutgoingMessage](10)
        self._connect_lock = asyncio.Lock()
        self._connected = False
        self._closed = False
        self._purpose = purpose
        self._done: asyncio.Future[None] = NotImplemented  # will be set when connected
        self._control_task: asyncio.Task | None = None
        self._receiver_task: asyncio.Task | None = None
        self._sender_task: asyncio.Task | None = None
        self._frame_sequence = count(1)
        self._pending_message: PendingMessage | None = None
        self.mtu = mtu  # NOTE @dan: rename to handshake_mtu/link_mtu?

    @property
    def mtu(self) -> int:
        return self.__dict__['mtu']

    @mtu.setter
    def mtu(self, value: int) -> None:
        self.__dict__['mtu'] = value
        self.dtls.set_ciphertext_mtu(value)

    @property
    def data_mtu(self) -> int:
        return self.dtls.get_cleartext_mtu()

    @staticmethod
    @lru_cache
    def get_dtls_context(identity: X509IdentityProvider) -> SSL.Context:
        context = SSL.Context(SSL.DTLS_METHOD)
        context.set_options(SSL.OP_NO_QUERY_MTU | SSL_OP_NO_RENEGOTIATION)
        context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT)
        identity.configure(context)
        context.check_privatekey()
        return context

    async def prepare(self) -> None:
        await self.ice.gather_candidates()

    async def connect(self, ice_peer: ICEPeer) -> None:  # noqa: C901, PLR0912, PLR0915
        async with self._connect_lock:  # noqa: PLR1702
            if self._closed:
                raise aio.ClosedResourceError

            if self._connected:
                return

            # Connect with the ICE peer

            for candidate in ice_peer.candidates:
                await self.ice.add_remote_candidate(candidate)
            await self.ice.add_remote_candidate(None)
            self.ice.remote_username = ice_peer.username
            self.ice.remote_password = ice_peer.password
            async with asyncio.timeout(self.ice_connect_timeout):  # NOTE @dan: is this needed? it will timeout after a while (60 seconds or longer and it will raise ConnectionError)
                await self.ice.connect()

            # Do the DTLS handshake

            if self._purpose is Purpose.AttachRequest:
                # The endpoint sending the attach request will be the TLS server
                self.dtls.set_accept_state()
                async with asyncio.timeout(self.dtls_hello_timeout):
                    while True:
                        data = await self.ice.recv()
                        self.dtls.bio_write(data)
                        try:
                            self.dtls.do_handshake()
                        except SSL.WantReadError:
                            if self.dtls.bio_pending() > 0:
                                # we got a valid DTLS client hello
                                break
            else:
                # The endpoint receiving the attach request will be the TLS client
                self.dtls.set_connect_state()

            while True:
                try:
                    self.dtls.do_handshake()
                except SSL.WantReadError:
                    await self._send_pending_data()
                    transmissions = 1  # NOTE @dan: decide if 2 transmissions or 2 retransmissions
                    while True:
                        try:
                            async with asyncio.timeout(self.dtls.get_dtls_timeout()):
                                data = await self.ice.recv()
                        except TimeoutError:
                            if transmissions == self.max_retransmissions:  # use max_retransmissions+1 for retransmissions
                                self.mtu = MINIMAL_MTU
                            if self.dtls.handle_dtls_timeout():
                                transmissions += 1
                                await self._send_pending_data()
                        else:
                            break
                    self.dtls.bio_write(data)
                except SSL.Error:
                    self._closed = True
                    await self._send_pending_data()
                    await self.ice.close()
                    raise
                else:
                    await self._send_pending_data()
                    break

            # Handshake done successfully
            self._connected = True
            self._control_task = asyncio.create_task(self._link_manager())

    async def close(self) -> None:
        async with self._connect_lock:
            if self._closed:
                return
            self._closed = True
            self._send_channel.close()
            if self._control_task is not None:
                self._notify_done()
                await self._control_task
            else:
                await self.ice.close()  # safety net in case connect() failed/was cancelled halfway through.

    async def receive(self) -> bytes:
        # if self._closed:
        #     raise aio.ClosedResourceError
        if not self._connected:
            raise aio.ResourceNotConnectedError
        try:
            return await self._recv_channel.receive()
        except aio.EndOfChannel as exc:
            raise aio.ClosedResourceError from exc

    async def send(self, data: bytes) -> None:
        # NOTE @dan: need some send lock to keep all packets in a volley together?
        if self._closed:
            raise aio.ClosedResourceError
        if not self._connected:
            raise aio.ResourceNotConnectedError
        await self._send_channel.send(message := OutgoingMessage(data))
        await message

    def _notify_done(self, reason: type[Exception] | Exception | None = None) -> None:
        if not self._done.done():
            if reason is None:
                self._done.set_result(None)
            else:
                self._done.set_exception(reason)

    async def _link_manager(self) -> None:
        self._done = asyncio.Future()
        try:
            async with asyncio.TaskGroup() as group:
                receiver_task = group.create_task(self._receiver_loop(), name=f'Link {self!r} receiver')  # NOTE: change self to nodeid
                __sender_task = group.create_task(self._sender_loop(), name=f'Link {self!r} sender')
                await self._done
                self.dtls.shutdown()
                await self._send_pending_data()
                try:
                    async with asyncio.timeout(self.dtls_shutdown_timeout):
                        await receiver_task
                except TimeoutError as exc:
                    raise aio.BrokenResourceError from exc
        except* (ConnectionError, aio.ClosedResourceError, aio.BrokenResourceError):
            # The ICE connection is down, DTLS was closed by the peer or we're not getting ACKs
            # for our messages. In all these cases attempting a DTLS shutdown is pointless.
            pass
        finally:
            async for message in self._send_channel:
                message.notify_sender(status=aio.ClosedResourceError)
            await self._recv_channel

    async def _receiver_loop(self) -> None:
        # the receiver loop will run until it receives a DTLS shutdown or the ICE connection ends/breaks.
        try:
            self._input_buffer.clear()
            with self._recv_channel:
                while True:
                    # If we get ConnectionError at any point, it means that either the ICE connection was
                    # closed or it did timeout. In either case there is nothing we can do
                    try:
                        data = await self.ice.recv()
                    except ConnectionError:
                        if self._pending_message is not None:
                            self._pending_message.done.set_exception(aio.ClosedResourceError)
                            self._pending_message = None
                        self._notify_done(reason=aio.ClosedResourceError)
                        break  # NOTE @dan: raise or break here?
                    self.dtls.bio_write(data)
                    try:
                        data = self.dtls.recv(self.max_packet_size)
                    except (SSL.WantReadError, SSL.WantWriteError):
                        await self._send_pending_data()
                    except SSL.ZeroReturnError:
                        self.dtls.shutdown()
                        await self._send_pending_data()
                        if self._pending_message is not None:
                            self._pending_message.done.set_exception(aio.ClosedResourceError)
                            self._pending_message = None
                        self._notify_done(reason=aio.ClosedResourceError)
                        break
                    except SSL.Error:
                        # NOTE: After SSL.Error DTLS shutdown should not be attempted
                        await self._send_pending_data()
                        if self._pending_message is not None:
                            self._pending_message.done.set_exception(aio.BrokenResourceError)
                            self._pending_message = None
                        self._notify_done(reason=aio.BrokenResourceError)
                        break
                    else:
                        self._input_buffer.write(data)
                        await self._process_incoming_messages()
        finally:
            self._closed = True
            self._pending_message = None
            self._send_channel.close()
            await self.ice.close()

    async def _process_incoming_messages(self) -> None:
        try:
            for message in self._input_buffer:
                match message.frame:
                    case AckFrame() as frame:
                        if self._pending_message is not None and frame.sequence in self._pending_message.sequence_numbers:
                            self._pending_message.done.set_result(None)
                            self._pending_message = None
                    case DataFrame() as frame:
                        ack = FramedMessage(type=FramedMessageType.ack, frame=AckFrame(sequence=frame.sequence, received=0xffffffff))
                        self.dtls.send(ack.to_wire())
                        await self._send_pending_data()
                        await self._recv_channel.send(frame.message)
        except ValueError:
            self.dtls.shutdown()
            await self._send_pending_data()

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
                        self.dtls.send(pending_message.message.to_wire())
                    except SSL.Error:
                        message.notify_sender(status=aio.BrokenResourceError)
                        self._pending_message = None
                        await self._send_pending_data()
                        await self.ice.close()
                        return
                    else:
                        message.notify_sender()
                        await self._send_pending_data()
                    try:
                        async with asyncio.timeout(timeout):
                            await pending_message.done
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
                    await self.ice.close()
                    return

    async def _send_pending_data(self) -> None:
        pending = self.dtls.bio_pending()
        if pending > 0:
            data = self.dtls.bio_read(pending)
            for packet in Packetizer(data, mtu=self.mtu):
                await self.ice.send(packet)  # type: ignore[arg-type]

    async def __aenter__(self) -> Self:
        if not self._connected:
            raise aio.ResourceNotConnectedError
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
