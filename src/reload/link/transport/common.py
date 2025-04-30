# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio
import struct
from collections.abc import Generator, Iterator
from dataclasses import InitVar, dataclass, field
from functools import cached_property
from typing import Any, ClassVar, Self
from urllib.parse import urlparse

from cryptography import x509

from reload.messages import AckFrame, FramedMessage
from reload.messages.datamodel import FramedMessageType, NodeID
from reload.trust.x509 import idna_decode

__all__ = 'NodeCertificate', 'OutgoingMessage', 'PendingMessage', 'FramedMessageBuffer'  # noqa: RUF022


@dataclass
class NodeCertificate:
    certificate: x509.Certificate
    node_id_idx: InitVar[int] = field(default=0, kw_only=True)

    _valid_name_types_: ClassVar[frozenset[type[x509.GeneralName]]] = frozenset({x509.UniformResourceIdentifier, x509.RFC822Name})

    def __post_init__(self, node_id_idx: int) -> None:
        try:
            alternative_name = self.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound as exc:
            raise ValueError('The node certificate is missing the SubjectAlternativeName extension') from exc
        name_types = [type(name) for name in alternative_name.value]
        if set(name_types) != self._valid_name_types_ or name_types.count(x509.RFC822Name) != 1:
            raise ValueError('The node certificate subject alternative name must contain exactly one or more reload URIs and one RFC822Name')
        if node_id_idx < 0 or node_id_idx >= len(name_types) - 1:
            raise ValueError('The index into the certificate node_id list is out of bounds')
        self._node_id_idx = node_id_idx

    def __repr__(self) -> str:
        return f'<{self.__class__.__qualname__}: {self.node_id.hex()}; {self.user}>'

    @cached_property
    def node_id_list(self) -> list[NodeID]:
        alternative_name = self.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = alternative_name.value.get_values_for_type(x509.UniformResourceIdentifier)
        return [self._node_id_from_uri(uri) for uri in uris]

    @cached_property
    def node_ids(self) -> set[NodeID]:
        return set(self.node_id_list)

    @cached_property
    def node_id(self) -> NodeID:
        return self.node_id_list[self._node_id_idx]

    @cached_property
    def user(self) -> str:
        alternative_name = self.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        rfc822name = alternative_name.value.get_values_for_type(x509.RFC822Name)[0]
        if rfc822name.count('@') != 1:
            raise ValueError(f'Invalid RFC822Name: {rfc822name!r}')
        user, _, domain = rfc822name.partition('@')
        return f'{user}@{idna_decode(domain)}'

    @staticmethod
    def _node_id_from_uri(uri: str) -> NodeID:
        parsed_uri = urlparse(uri)
        if parsed_uri.scheme != 'reload':
            raise ValueError(f'Invalid scheme {parsed_uri.scheme!r}. Expected a reload URI.')
        if parsed_uri.netloc.count('@') != 1:
            raise ValueError(f'Invalid reload URI: {uri!r}')
        user, _, _domain = parsed_uri.netloc.partition('@')
        return NodeID.fromhex(user)


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

    def match(self, frame: AckFrame) -> bool:
        return frame.sequence in self.sequence_numbers

    def notify_done(self, status: type[Exception] | Exception | None = None) -> None:
        if self.done.done():
            return
        if status is None:
            self.done.set_result(None)
        else:
            self.done.set_exception(status)


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
