# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio
import struct
from collections.abc import Generator, Iterator
from dataclasses import dataclass, field
from os.path import expanduser, realpath
from ssl import SSLContext
from typing import Any, ClassVar, Self, assert_never

from OpenSSL import SSL

from reload.messages import FramedMessage
from reload.messages.datamodel import FramedMessageType

__all__ = 'NodeIdentity', 'OutgoingMessage', 'PendingMessage', 'FramedMessageBuffer'  # noqa: RUF022


class PathAttribute:
    name: str = NotImplemented

    def __set_name__(self, owner: type, name: str) -> None:
        if self.name is NotImplemented:
            self.name = name
        elif name != self.name:
            raise TypeError(f'cannot assign the same {self.__class__.__name__} to two different names: {self.name} and {name}')

    def __get__(self, instance: object | None, owner: type | None = None) -> str:
        if instance is None:
            raise AttributeError
        return instance.__dict__[self.name]

    def __set__(self, instance: object, value: str) -> None:
        instance.__dict__[self.name] = realpath(expanduser(value))  # noqa: PTH111


@dataclass(frozen=True)
class NodeIdentity:
    certificate_file: PathAttribute = PathAttribute()
    private_key_file: PathAttribute = PathAttribute()
    authority_file:   PathAttribute = PathAttribute()

    def configure(self, context: SSLContext | SSL.Context) -> None:
        """Configure the SSL context with this object's certificate and authority files"""
        match context:
            case SSLContext():
                context.load_verify_locations(cafile=self.authority_file)
                context.load_cert_chain(certfile=self.certificate_file, keyfile=self.private_key_file)
            case SSL.Context():
                context.load_verify_locations(self.authority_file)
                context.use_certificate_chain_file(self.certificate_file)
                context.use_privatekey_file(self.private_key_file)
            case _:
                assert_never(context)


@dataclass
class OutgoingMessage:
    data: bytes
    sent: asyncio.Future[None] = field(init=False, default_factory=asyncio.Future)

    def __await__(self) -> Generator[Any, None, None]:
        return self.sent.__await__()

    def notify_sender(self, *, status: type[Exception] | Exception | None = None) -> None:
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
