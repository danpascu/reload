# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio
import contextlib
import enum
import struct
from collections import deque
from collections.abc import Hashable, Iterator
from dataclasses import dataclass
from functools import cached_property, lru_cache
from itertools import count
from typing import Any, ClassVar, Protocol, Self, overload

from aioice.candidate import Candidate
from aioice.ice import Connection as ICEConnection
from cryptography.hazmat.bindings.openssl.binding import Binding
from OpenSSL import SSL

from reload import aio
from reload.messages import AckFrame, DataFrame, FramedMessage
from reload.messages.datamodel import FramedMessageType

from .common import FramedMessageBuffer, NodeCertificate, OutgoingMessage, PendingMessage

__all__ = 'DTLSLink', 'Purpose', 'ICEPeer', 'BadRecord'  # noqa: RUF022


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


class X509IdentityProvider(Hashable, Protocol):
    def configure(self, context: SSL.Context) -> None:
        """Configure the SSL context with the X509 certificate, private key and authority"""
        ...


class DTLSLink:
    stun_server: tuple[str, int] | None = 'stun.antisip.com', 3478

    ice_connect_timeout: int = 30   # how long to wait for ice to establish connection
    dtls_hello_timeout: int = 30    # how long the server waits for a client hello
    dtls_shutdown_timeout: int = 3  # how long to wait for confirmation on DTLS shutdown

    max_packet_size: int = 2**14    # max TLS/DTLS record size
    max_retransmissions: int = 2

    def __init__(self, purpose: Purpose, identity: X509IdentityProvider, *, mtu: int = OPTIMAL_MTU) -> None:
        ice_controlling = purpose is Purpose.AttachRequest
        self.identity = identity
        self.ice = ICEConnection(ice_controlling=ice_controlling, stun_server=self.stun_server)
        self.dtls = DTLSConnection(self.get_context(identity))
        self.mtu = mtu
        self._purpose = purpose
        self._recv_channel = aio.Channel[bytes](10)
        self._send_channel = aio.Channel[OutgoingMessage](10)
        self._input_buffer: FramedMessageBuffer = FramedMessageBuffer()
        self._output_queue: deque[bytes] = deque()
        self._connect_lock = asyncio.Lock()
        self._connected = False
        self._closed = False
        self._shutdown = False
        self._done: asyncio.Future[None] = NotImplemented  # will be set when connected
        self._control_task: asyncio.Task | None = None
        self._frame_sequence = count(1)
        self._pending_message: PendingMessage | None = None

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

    @property
    def closed(self) -> bool:
        return self._closed

    @cached_property
    def peer_cert(self) -> NodeCertificate:
        peer_cert = self.dtls.get_peer_certificate(as_cryptography=True)
        assert peer_cert is not None  # noqa: S101 (used by type checkers)
        return NodeCertificate(peer_cert)

    @staticmethod
    @lru_cache
    def get_context(identity: X509IdentityProvider) -> SSL.Context:
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

    async def _link_manager(self) -> None:
        self._done = asyncio.Future()
        try:
            async with asyncio.TaskGroup() as group:
                receiver_task = group.create_task(self._receiver_loop(), name=f'DTLS Link {self!r} receiver')  # NOTE: change self to nodeid
                __sender_task = group.create_task(self._sender_loop(), name=f'DTLS Link {self!r} sender')
                await self._done
                async with asyncio.timeout(self.dtls_shutdown_timeout):
                    await self._shutdown_dtls()
                    await receiver_task
        except* (ConnectionError, TimeoutError, aio.ClosedResourceError, aio.BrokenResourceError):
            # The ICE connection is down, DTLS was closed by the peer or we're not getting ACKs
            # for our messages. In all these cases attempting a DTLS shutdown is pointless.
            pass
        finally:
            async for message in self._send_channel:
                message.notify_sender(status=aio.ClosedResourceError)
            await self.ice.close()
            await self._recv_channel

    async def _receiver_loop(self) -> None:
        # the receiver loop will run until it receives a DTLS shutdown or the ICE connection ends/breaks.
        connection_status = None
        try:
            self._input_buffer.clear()
            with self._recv_channel:
                while True:
                    data = await self._read_data()
                    self._input_buffer.write(data)
                    try:
                        await self._process_incoming_messages()
                    except ValueError:
                        await self._shutdown_dtls()
        except (aio.BrokenResourceError, aio.ClosedResourceError) as exc:
            connection_status = exc
        finally:
            # NO async code should be called after calling self._notify_done
            # as it will be automatically cancelled.
            self._closed = True
            self._send_channel.close()
            self._output_queue.clear()
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
                    await self._send_data(ack.to_wire())
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
                        await self._send_data(pending_message.message.to_wire())
                    except (aio.BrokenResourceError, aio.ClosedResourceError) as exc:
                        message.notify_sender(status=exc)
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
                    with contextlib.suppress(ConnectionError):
                        await self.ice.close()
                    return

    async def _read_data(self) -> bytearray:
        while True:
            try:
                async with asyncio.timeout(self.dtls_shutdown_timeout if self._shutdown else None):
                    data = await self.ice.recv()
            except TimeoutError as exc:
                raise aio.BrokenResourceError from exc
            except ConnectionError as exc:
                raise aio.ClosedResourceError from exc

            self.dtls.bio_write(data)

            input_data = bytearray()
            while True:
                try:
                    chunk = self.dtls.recv(self.max_packet_size)
                except SSL.WantReadError:
                    break
                except SSL.ZeroReturnError as exc:
                    self._closed = True
                    self.dtls.shutdown()
                    await self._send_pending_data()
                    await self.ice.close()
                    raise aio.ClosedResourceError from exc
                except SSL.Error as exc:
                    # NOTE: After SSL.Error dtls.shutdown() must not be called. See:
                    # https://docs.openssl.org/1.1.1/man3/SSL_get_error/#return-values
                    # about SSL_ERROR_SSL (which translates to SSL.Error).
                    self._closed = True
                    await self._send_pending_data()
                    await self.ice.close()
                    raise aio.BrokenResourceError from exc
                else:
                    input_data.extend(chunk)

            await self._try_send_queued_data()

            if input_data:
                return input_data

    async def _send_data(self, data: bytes) -> None:
        if self._closed:
            raise aio.ClosedResourceError
        self._output_queue.append(data)
        await self._try_send_queued_data()

    async def _try_send_queued_data(self) -> None:
        if self._closed:
            # Ingore the output queue after the DTLS shutdown alert was sent,
            # as dtls.send() doesn't work after that (raises SSL.Error) and
            # raising an exception here would kill the receiver loop and
            # discard the remaining messages, including the peer's close alert
            # which we're expecting in order to finish closing the connection.
            return
        while self._output_queue:
            data = self._output_queue[0]
            try:
                self.dtls.send(data)
            except SSL.WantReadError:
                await self._send_pending_data()
                break
            except SSL.Error as exc:
                # NOTE: After SSL.Error dtls.shutdown() must not be called. See:
                # https://docs.openssl.org/1.1.1/man3/SSL_get_error/#return-values
                # about SSL_ERROR_SSL (which translates to SSL.Error).
                self._closed = True
                await self._send_pending_data()
                await self.ice.close()
                raise aio.BrokenResourceError from exc
            else:
                self._output_queue.popleft()
                await self._send_pending_data()

    async def _send_pending_data(self) -> None:
        pending = self.dtls.bio_pending()
        if pending > 0:
            data = self.dtls.bio_read(pending)
            for packet in Packetizer(data, mtu=self.mtu):
                await self.ice.send(packet)  # type: ignore[arg-type]

    async def _shutdown_dtls(self) -> None:
        if self._shutdown:
            return
        self._shutdown = True
        self._closed = True
        self.dtls.shutdown()
        await self._send_pending_data()

    def _notify_done(self, status: type[Exception] | Exception | None = None) -> None:
        if not self._done.done():
            if status is None:
                self._done.set_result(None)
            else:
                self._done.set_exception(status)

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
