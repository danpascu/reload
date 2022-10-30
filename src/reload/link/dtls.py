# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio
import aioice
import contextlib
import enum
import struct

from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, ClassVar, TypeVar

from OpenSSL import SSL
# noinspection PyProtectedMember
from OpenSSL.SSL import _ffi, _lib

from reload import aio
from .common import NodeIdentity


__all__ = 'DTLSEndpoint', 'Purpose', 'ICEPeer', 'BadRecord'


OPTIMAL_MTU = 1500 - 48
MINIMAL_MTU = 576 - 28


# noinspection PyAbstractClass
class DTLSConnection(SSL.Connection):
    def bio_pending(self) -> int:
        """
        Call the OpenSSL function BIO_ctrl_pending on the outgoing BIO.
        See the OpenSSL manual for more details.

        :return: how many bytes are available to read from the BIO
        """
        if self._from_ssl is None:
            raise TypeError("Connection sock was not None")

        return _lib.BIO_ctrl_pending(self._from_ssl)

    def get_dtls_timeout(self) -> 'float | None':
        """
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


T = TypeVar('T')


class RecordHeaderField:
    _type_handlers = {
        bytes: lambda x: x,
        int: lambda x: int.from_bytes(x, byteorder='big'),
    }

    # noinspection PyShadowingBuiltins
    def __init__(self, size: int, type: Callable[[bytes], T] = bytes):
        self.name = None
        self.size = size
        self.type = self._type_handlers.get(type, type)
        self.slice = None  # will be set from __set_name__

    def __set_name__(self, owner, name):
        if not hasattr(owner, '__header_fields__'):
            owner.__header_fields__ = ()
        if self.name is None:
            self.name = name
            self.slice = slice(index := sum(field.size for field in owner.__header_fields__), index + self.size)
            owner.__header_fields__ += self,
        elif name != self.name:
            raise TypeError(f'cannot assign the same {self.__class__.__name__} to two different names: {self.name} and {name}')

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        if self.name is None:
            raise TypeError(f'cannot use {self.__class__.__name__} instance without calling __set_name__ on it.')
        return instance.__dict__.setdefault(self.name, self.type(instance[self.slice]))


class Record(bytes):
    """
    Representation of a DTLS record which has the following structure:
     - 1 byte content type
     - 2 bytes version
     - 2 bytes epoch
     - 6 bytes sequence_no
     - 2 bytes payload length (unsigned big-endian)
     - payload
    """

    header: ClassVar = struct.Struct('!11xH')

    # All header fields must be specified and they need to be in order,
    # as their position in the header is calculated based on all the
    # other header fields defined before them.

    content_type = RecordHeaderField(size=1, type=int)
    version = RecordHeaderField(size=2, type=bytes)
    epoch = RecordHeaderField(size=2, type=int)
    sequence_no = RecordHeaderField(size=6, type=int)

    def __new__(cls, data: bytes, position: int = 0):
        if not 0 <= position < len(data):
            raise ValueError('position is outside of the data stream')
        try:
            payload_length, = cls.header.unpack_from(data, position)
        except struct.error as exc:
            raise BadRecord('invalid DTLS record header') from exc
        if position + cls.header.size + payload_length > len(data):
            raise BadRecord('record too short')
        record_length = cls.header.size + payload_length
        record = data[position:position+record_length]
        return super().__new__(cls, record)

    def __repr__(self):
        return f'<{self.__class__.__name__}: content_type={self.content_type}, version={self.version.hex()}, epoch={self.epoch}, sequence_no={self.sequence_no}, payload={self.payload!r}>'

    @property
    def payload(self):
        return self[self.header.size:]


class Packetizer:
    """
    Take the byte stream produced by OpenSSL and split it into individual
    DTLS records. When iterated, the packetizer combines the DTLS records
    to create network packets according to the specified MTU.
    The original DTLS records are available through the records attribute.
    """

    def __init__(self, data: bytes, mtu: int):
        records = []
        position = 0
        while position < len(data):
            record = Record(data, position=position)
            position += len(record)
            records.append(record)
        self.records = records
        self.mtu = mtu

    def __iter__(self):
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
    candidates: list


class DTLSEndpoint:  # todo: rename to DTLSLink?
    stun_server = 'stun.antisip.com', 3478

    ice_connect_timeout = 30   # how long to wait for ice to establish connection #
    dtls_hello_timeout = 30    # how long the server waits for a client hello
    dtls_shutdown_timeout = 3  # how long to wait for confirmation on DTLS shutdown

    max_packet_size = 16384

    def __init__(self, purpose: Purpose, identity: NodeIdentity, *, mtu=OPTIMAL_MTU):
        if type(purpose) is not Purpose:
            raise TypeError('purpose needs to be of type Purpose')
        ice_controlling = purpose is Purpose.AttachRequest
        self.identity = identity
        self.ice = aioice.Connection(ice_controlling=ice_controlling, stun_server=self.stun_server)
        self.dtls = DTLSConnection(self.get_dtls_context(identity))
        self._channel = aio.Channel(10)
        self._connect_lock = asyncio.Lock()
        self._connected = False
        self._closed = False
        self._purpose = purpose
        self._receiver_task = None
        self.mtu = mtu  # todo: rename to handshake_mtu/link_mtu?

    @property
    def mtu(self):
        return self.__dict__['mtu']

    @mtu.setter
    def mtu(self, value):
        self.__dict__['mtu'] = value
        self.dtls.set_ciphertext_mtu(value)

    @property
    def data_mtu(self):
        return self.dtls.get_cleartext_mtu()

    @staticmethod
    @lru_cache
    def get_dtls_context(identity: NodeIdentity):
        context = SSL.Context(SSL.DTLS_METHOD)
        context.set_options(SSL.OP_NO_QUERY_MTU | SSL.OP_NO_RENEGOTIATION)
        context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT)
        identity.configure(context)
        context.check_privatekey()
        return context

    async def prepare(self):
        await self.ice.gather_candidates()

    async def connect(self, ice_peer: ICEPeer):
        # todo: split into _connect_ice() and _do_dtls_handshake()? (need to cleanup in case of error while connecting (CM or try/except))
        async with self._connect_lock:
            if self._closed:
                raise aio.ClosedResourceError

            if self._connected:
                return

            # Connect with the ICE peer

            for candidate in ice_peer.candidates:
                await self.ice.add_remote_candidate(candidate)
            # noinspection PyTypeChecker
            await self.ice.add_remote_candidate(None)
            self.ice.remote_username = ice_peer.username
            self.ice.remote_password = ice_peer.password
            async with aio.timeout(self.ice_connect_timeout):  # todo: is this needed? it will timeout after a while (60 seconds or longer and it will raise ConnectionError)
                await self.ice.connect()

            # Do the DTLS handshake

            if self._purpose is Purpose.AttachRequest:
                # The endpoint sending the attach request will be the TLS server
                self.dtls.set_accept_state()
                async with aio.timeout(self.dtls_hello_timeout):
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
                    transmissions = 1  # todo: decide if 2 transmissions or 2 retransmissions
                    while True:
                        try:
                            async with aio.timeout(self.dtls.get_dtls_timeout()):
                                data = await self.ice.recv()
                        except asyncio.TimeoutError:
                            if transmissions == 2:
                                self.mtu = MINIMAL_MTU
                            if self.dtls.handle_dtls_timeout():
                                transmissions += 1
                                await self._send_pending_data()
                        else:
                            break
                    self.dtls.bio_write(data)
                else:
                    await self._send_pending_data()
                    break

            # Handshake done successfully
            self._connected = True
            self._receiver_task = asyncio.create_task(self._receiver_loop())

    async def close(self):
        async with self._connect_lock:
            if self._closed:
                return
            self._closed = True
            if self._connected:
                self.dtls.shutdown()
                await self._send_pending_data()
                # without DTLS shutdown confirmation from the peer, _receiver_task won't terminate.
                # this can happen because of a bad peer implementation or packet loss.
                with contextlib.suppress(asyncio.TimeoutError):
                    async with aio.timeout(self.dtls_shutdown_timeout):
                        await self._receiver_task
                # self._receiver_task = None
            else:
                await self.ice.close()  # safety net in case connect() failed/was cancelled halfway through.

    async def receive(self):
        # if self._closed:
        #     raise aio.ClosedResourceError
        if not self._connected:
            raise aio.ResourceNotConnectedError
        try:
            return await self._channel.receive()
        except aio.EndOfChannel:
            raise aio.ClosedResourceError

    async def send(self, message):
        # todo: need some send lock to keep all packets in a volley together?
        if self._closed:
            raise aio.ClosedResourceError
        if not self._connected:
            raise aio.ResourceNotConnectedError
        self.dtls.send(message)
        await self._send_pending_data()

    async def _receiver_loop(self):
        # the receiver loop will run until it receives a DTLS shutdown or the ICE connection ends/breaks.
        try:
            with self._channel:
                while True:
                    try:
                        data = await self.ice.recv()
                    except ConnectionError:
                        break
                    self.dtls.bio_write(data)
                    try:
                        data = self.dtls.recv(self.max_packet_size)
                    except (SSL.WantReadError, SSL.WantWriteError):
                        await self._send_pending_data()
                    except SSL.ZeroReturnError:
                        self.dtls.shutdown()
                        await self._send_pending_data()
                        break
                    except SSL.Error:
                        # todo: what to do about this? fail or ignore? (note: after SSL.Error DTLS shutdown should not be attempted)
                        pass
                    else:
                        await self._channel.send(data)
        finally:
            self._closed = True
            await self.ice.close()
            await self._channel

    async def _send_pending_data(self):
        pending = self.dtls.bio_pending()
        if pending > 0:
            data = self.dtls.bio_read(pending)
            for packet in Packetizer(data, mtu=self.mtu):
                await self.ice.send(packet)
            # print(f'sent {pending} bytes from {self.dtls}')

    async def __aenter__(self):
        if not self._connected:
            raise aio.ResourceNotConnectedError
        return self

    async def __aexit__(self, exc_type, exc_value, exc_traceback):
        await self.close()

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await self.receive()
        except aio.ClosedResourceError:
            raise StopAsyncIteration
