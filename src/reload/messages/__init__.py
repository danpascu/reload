# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
6.3. Message Structure

   RELOAD is a message-oriented request/response protocol.  The messages
   are encoded using binary fields.  All integers are represented in
   network byte order.  The general philosophy behind the design was to
   use Type, Length, Value (TLV) fields to allow for extensibility.
   However, for the parts of a structure that were required in all
   messages, we just define these in a fixed position, as adding a type
   and length for them is unnecessary and would only increase bandwidth
   and introduce new potential interoperability issues.

   Each message has three parts, which are concatenated, as shown below:

     +-------------------------+
     |    Forwarding Header    |
     +-------------------------+
     |    Message Contents     |
     +-------------------------+
     |     Security Block      |
     +-------------------------+

   The contents of these parts are as follows:

   Forwarding Header:  Each message has a generic header which is used
      to forward the message between peers and to its final destination.
      This header is the only information that an intermediate peer
      (i.e., one that is not the target of a message) needs to examine.
      Section 6.3.2 describes the format of this part.

   Message Contents:  The message being delivered between the peers.
      From the perspective of the forwarding layer, the contents are
      opaque; however, they are interpreted by the higher layers.
      Section 6.3.3 describes the format of this part.

   Security Block:  A security block containing certificates and a
      digital signature over the "Message Contents" section.  Note that
      this signature can be computed without parsing the message
      contents.  All messages MUST be signed by their originator.
      Section 6.3.4 describes the format of this part.

"""

import hashlib
import struct
from collections.abc import Mapping, MutableMapping, Sequence
from functools import lru_cache
from io import BytesIO
from secrets import randbelow
from typing import ClassVar, Self

from reload.configuration import Configuration

from .datamodel import (
    CertificateType,
    ChordLeaveType,
    CompositeAdapter,
    DestinationType,
    ErrorCode,
    ForwardingFlags,
    ForwardingOptionType,
    HashAlgorithm,
    MessageExtensionType,
    NodeID,
    Opaque8Adapter,
    Opaque16,
    Opaque16Adapter,
    Opaque32,
    Opaque32Adapter,
    OpaqueID,
    ResourceID,
    SignatureAlgorithm,
    SignerIdentityType,
    UInt8,
    UInt8Adapter,
    UInt16,
    UInt16Adapter,
    UInt32,
    UInt32Adapter,
    UInt64Adapter,
    WireData,
)
from .elements import AnnotatedStructure, Element, LinkedElement, ListElement, Structure

__all__ = (  # noqa: RUF022
    'Message',

    # composite types
    'Destination',
    'ForwardingOption',
    'MessageExtension',
    'GenericCertificate',
    'SignatureAndHashAlgorithm',
    'CertificateHash',
    'NodeIDCertificateHash',
    'Empty',
    'SignerIdentity',
    'Signature',

    # messages
    'JoinRequest',
    'JoinResponse',
    'LeaveRequest',
    'LeaveResponse',
    'PingRequest',
    'PingResponse',
    'ErrorResponse',

    # extension support
    'ChordLeaveData',

    # high level structures
    'ForwardingHeader',
    'MessageContents',
    'SecurityBlock',

    # helpers
    'new_transaction_id',
    'overlay_id',
)


RELOAD_VERSION = 10  # The version of the RELOAD protocol being implemented times 10 (currently 1.0)
RELO_TOKEN = b'\xd2ELO'  # 'RELO' with the high bit of the 1st character set to 1


class Destination(AnnotatedStructure):
    """Destination structure on the wire:

    typedef { uint16 opaque_id } Destination  // top bit MUST be 1

    or

    type DestinationType = enum { invalid(0), node(1), resource(2), opaque_id_type(3) (255) }  // 128-255 not allowed
    type DestinationData = NodeID | ResourceID | OpaqueID  // based on destination type

    typedef {
        DestinationType type
        uint8           length  // length of destination data
        DestinationData data
    } Destination

    """

    _destination_type_map: ClassVar[Mapping[DestinationType, type]] = {
        DestinationType.node: NodeID,
        DestinationType.resource: ResourceID,
        DestinationType.opaque_id_type: OpaqueID,
    }

    type: Element[DestinationType] = Element(DestinationType)
    data: LinkedElement[NodeID | ResourceID | OpaqueID, DestinationType] = LinkedElement(type_map=_destination_type_map, key_field=type)

    def __repr__(self) -> str:
        return f'<{self.__class__.__qualname__}: {self.type.name} {self.data.hex()}>'

    @property
    def is_opaque_id(self) -> bool:
        return self.type is DestinationType.opaque_id_type and len(self.data) == 2 and self.data[0] & 0x80 != 0  # noqa: PLR2004

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if not isinstance(buffer, BytesIO):
            buffer = BytesIO(buffer)
        data = buffer.read(2)
        if data[0] & 0x80:
            return cls(type=DestinationType.opaque_id_type, data=OpaqueID(data))
        instance = super(Structure, cls).__new__(cls)
        instance.type = DestinationType(data[0])
        # NOTE @dan:
        # The length in data[1] is not useful at the moment as the data element is either fixed size or size-prefixed.
        # If the structure is extended to support other types of data, verifying that there are enough bytes left may
        # be needed, depending of the type of the data. For now we skip this to avoid an unnecessary slowdown.
        cls.data.from_wire(instance, buffer)
        return instance

    def to_wire(self) -> bytes:
        if self.is_opaque_id:
            return bytes(self.data)
        return self.type.to_wire() + UInt8(self.data.wire_length()).to_wire() + self.data.to_wire()

    def wire_length(self) -> int:
        if self.is_opaque_id:
            return 2
        return self.type._size_ + UInt8._size_ + self.data.wire_length()


class ForwardingOptionAdapter(CompositeAdapter[ForwardingOptionType | UInt8]):
    pass


class ForwardingOption(AnnotatedStructure):
    # currently there are no options defined in the RFC
    _forwarding_option_type_map: ClassVar[Mapping[ForwardingOptionType | UInt8, type]] = {}

    type: Element[ForwardingOptionType | UInt8] = Element(ForwardingOptionType | UInt8, adapter=ForwardingOptionAdapter)
    flags: Element[ForwardingFlags] = Element(ForwardingFlags)
    option: LinkedElement[Opaque16, ForwardingOptionType | UInt8] = LinkedElement(type_map=_forwarding_option_type_map, key_field=type, fallback_type=Opaque16, default=Opaque16())

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if not isinstance(buffer, BytesIO):
            buffer = BytesIO(buffer)
        instance = super(Structure, cls).__new__(cls)
        cls.type.from_wire(instance, buffer)
        cls.flags.from_wire(instance, buffer)
        option_type = cls.option.type_map.get(instance.type, None)
        if option_type is not None:
            length = UInt16.from_wire(buffer)
            instance.option = option_type.from_wire(buffer.read(length))
        else:
            instance.option = Opaque16.from_wire(buffer)
        return instance

    def to_wire(self) -> bytes:
        match self.option:
            case Opaque16() as option:
                return self.type.to_wire() + self.flags.to_wire() + option.to_wire()
            case option:
                return self.type.to_wire() + self.flags.to_wire() + UInt16(option.wire_length()).to_wire() + option.to_wire()  # type: ignore[unreachable]

    def wire_length(self) -> int:
        match self.option:
            case Opaque16() as option:
                return self.type._size_ + self.flags._size_ + option.wire_length()
            case option:
                return self.type._size_ + self.flags._size_ + UInt16._size_ + option.wire_length()  # type: ignore[unreachable]


class MessageExtensionAdapter(CompositeAdapter[MessageExtensionType | UInt16]):
    pass


class MessageExtension(AnnotatedStructure):
    # currently there are no message extensions defined in the RFC
    _message_extension_type_map: ClassVar[Mapping[MessageExtensionType | UInt16, type]] = {}

    type: Element[MessageExtensionType | UInt16] = Element(MessageExtensionType | UInt16, adapter=MessageExtensionAdapter)
    critical: Element[bool] = Element(bool)
    extension: LinkedElement[Opaque32, MessageExtensionType | UInt16] = LinkedElement(type_map=_message_extension_type_map, key_field=type, fallback_type=Opaque32, default=Opaque32())

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if not isinstance(buffer, BytesIO):
            buffer = BytesIO(buffer)
        instance = super(Structure, cls).__new__(cls)
        cls.type.from_wire(instance, buffer)
        cls.critical.from_wire(instance, buffer)
        extension_type = cls.extension.type_map.get(instance.type, None)
        if extension_type is not None:
            length = UInt32.from_wire(buffer)
            instance.extension = extension_type.from_wire(buffer.read(length))
        else:
            instance.extension = Opaque32.from_wire(buffer)
        return instance

    def to_wire(self) -> bytes:
        match self.extension:
            case Opaque32() as extension:
                return self.type.to_wire() + self.__class__.critical.to_wire(self) + extension.to_wire()
            case extension:
                return self.type.to_wire() + self.__class__.critical.to_wire(self) + UInt32(extension.wire_length()).to_wire() + extension.to_wire()  # type: ignore[unreachable]

    def wire_length(self) -> int:
        match self.extension:
            case Opaque32() as extension:
                return self.type._size_ + 1 + extension.wire_length()
            case extension:
                return self.type._size_ + 1 + UInt32._size_ + extension.wire_length()  # type: ignore[unreachable]


class GenericCertificate(AnnotatedStructure):
    type: Element[CertificateType] = Element(CertificateType)
    certificate: Element[bytes] = Element(bytes, adapter=Opaque16Adapter)


class SignatureAndHashAlgorithm(AnnotatedStructure):
    hash: Element[HashAlgorithm] = Element(HashAlgorithm)
    signature: Element[SignatureAlgorithm] = Element(SignatureAlgorithm)


class CertificateHash(AnnotatedStructure):
    hash_algorithm: Element[HashAlgorithm] = Element(HashAlgorithm)
    certificate_hash: Element[bytes] = Element(bytes, adapter=Opaque8Adapter)


class NodeIDCertificateHash(CertificateHash):
    pass


class Empty(AnnotatedStructure):
    pass


class SignerIdentity(AnnotatedStructure):
    _signer_identity_type_map: ClassVar[Mapping[SignerIdentityType, type]] = {
        SignerIdentityType.cert_hash: CertificateHash,
        SignerIdentityType.cert_hash_node_id: NodeIDCertificateHash,
        SignerIdentityType.none: Empty,
    }

    type: Element[SignerIdentityType] = Element(SignerIdentityType)
    identity: LinkedElement[CertificateHash | NodeIDCertificateHash | Empty, SignerIdentityType] = LinkedElement(type_map=_signer_identity_type_map, key_field=type)

    def __repr__(self) -> str:
        return f'<{self.__class__.__qualname__}: {self.type.name} {self.identity!r}>'

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if not isinstance(buffer, BytesIO):
            buffer = BytesIO(buffer)
        instance = super(Structure, cls).__new__(cls)
        cls.type.from_wire(instance, buffer)
        length = UInt16.from_wire(buffer)
        cls.identity.from_wire(instance, buffer.read(length))
        return instance

    def to_wire(self) -> bytes:
        return self.type.to_wire() + UInt16(self.identity.wire_length()).to_wire() + self.identity.to_wire()

    def wire_length(self) -> int:
        return self.type._size_ + UInt16._size_ + self.identity.wire_length()


class Signature(AnnotatedStructure):
    algorithm: Element[SignatureAndHashAlgorithm] = Element(SignatureAndHashAlgorithm)
    identity: Element[SignerIdentity] = Element(SignerIdentity)
    value: Element[bytes] = Element(bytes, adapter=Opaque16Adapter)


# Requests and Responses

type MessageType = type[Message]


class Message(AnnotatedStructure):
    # message code 0 is invalid and should not be used anywhere
    # the message code should be overridden by subclasses

    _code_: ClassVar[UInt16] = UInt16()
    _registry_: ClassVar[MutableMapping[int, MessageType]] = {}

    def __init_subclass__(cls, *, code: int = 0, **kw: object) -> None:
        super().__init_subclass__(**kw)
        cls._code_ = UInt16(code)
        if cls._code_ != 0 and cls._registry_.setdefault(cls._code_, cls) is not cls:
            raise TypeError(f'Message code 0x{cls._code_:x} is already used by {cls._registry_[cls._code_]}')

    def __class_getitem__(cls, code: int) -> MessageType:
        try:
            return cls._registry_[code]
        except KeyError as exc:
            raise TypeError(f'Unknown message code 0x{code:x}') from exc


class JoinRequest(Message, code=0x0f):
    node_id: Element[NodeID] = Element(NodeID)
    overlay_data: Element[bytes] = Element(bytes, default=b'', adapter=Opaque16Adapter)


class JoinResponse(Message, code=0x10):
    overlay_data: Element[bytes] = Element(bytes, default=b'', adapter=Opaque16Adapter)


class LeaveRequest(Message, code=0x11):
    node_id: Element[NodeID] = Element(NodeID)
    overlay_data: Element[bytes] = Element(bytes, default=b'', adapter=Opaque16Adapter)


class LeaveResponse(Message, code=0x12):
    pass


class PingRequest(Message, code=0x17):
    padding: Element[bytes] = Element(bytes, default=b'', adapter=Opaque16Adapter)


class PingResponse(Message, code=0x18):
    id: Element[int] = Element(int, adapter=UInt64Adapter)
    time: Element[int] = Element(int, adapter=UInt64Adapter)


class ErrorResponse(Message, code=0xffff):
    code: Element[ErrorCode] = Element(ErrorCode)
    info: Element[bytes] = Element(bytes, default=b'', adapter=Opaque16Adapter)


# Extension support

class ChordLeaveData(AnnotatedStructure):
    type: Element[ChordLeaveType] = Element(ChordLeaveType)
    node_list: ListElement[NodeID] = ListElement(NodeID, maxsize=2**16 - 1)


# helpers

def new_transaction_id() -> int:
    return randbelow(2**64 - 1)


@lru_cache
def overlay_id(overlay: str | bytes) -> int:
    if isinstance(overlay, str):
        overlay = overlay.encode()
    return int.from_bytes(hashlib.sha1(overlay, usedforsecurity=False).digest()[-4:])


# High level structures

class ForwardingHeader(AnnotatedStructure):
    """
    Forwarding header structure:

        uint32             relo_token
        uint32             overlay
        uint16             configuration_sequence
        uint8              version
        uint8              ttl
        uint32             fragment
        uint32             length
        uint64             transaction_id
        uint32             max_response_length
        uint16             via_list_length
        uint16             destination_list_length
        uint16             options_length
        Destination        via_list[via_list_length]
        Destination        destination_list[destination_list_length]
        ForwardingOption   options[options_length]
    """

    _preamble_ = struct.Struct('!4sIHBBIIQIHHH')

    # preamble start

    # relo_token -> b'\xd2ELO'
    overlay: Element[int] = Element(int, adapter=UInt32Adapter)
    configuration_sequence: Element[int] = Element(int, adapter=UInt16Adapter)
    version: Element[int] = Element(int, adapter=UInt8Adapter, default=RELOAD_VERSION)
    ttl: Element[int] = Element(int, adapter=UInt8Adapter)
    fragment: Element[int] = Element(int, adapter=UInt32Adapter)
    length: Element[int] = Element(int, adapter=UInt32Adapter)
    transaction_id: Element[int] = Element(int, adapter=UInt64Adapter)
    max_response_length: Element[int] = Element(int, adapter=UInt32Adapter, default=0)
    # via_list_length -> uint16
    # destination_list_length -> uint16
    # option_list_length -> uint16

    # preamble end

    via_list: ListElement[Destination] = ListElement(Destination)
    destination_list: ListElement[Destination] = ListElement(Destination)
    options: ListElement[ForwardingOption] = ListElement(ForwardingOption, default=())

    @classmethod
    def new(cls, *,  # noqa: PLR0913
            configuration: Configuration,
            fragment: int,
            length: int = 0,
            transaction_id: int,
            via_list: Sequence[Destination],
            destination_list: Sequence[Destination],
            options: Sequence[ForwardingOption] = (),
            max_response_length: int = 0,
            ) -> Self:
        return cls(
            overlay=overlay_id(configuration.instance_name),
            configuration_sequence=configuration.sequence or 1,
            version=RELOAD_VERSION,
            ttl=configuration.initial_ttl or 100,
            fragment=fragment | 0x8000_0000,
            length=length,
            transaction_id=transaction_id,
            max_response_length=max_response_length,
            via_list=via_list,
            destination_list=destination_list,
            options=options,
        )

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if not isinstance(buffer, BytesIO):
            buffer = BytesIO(buffer)
        preamble = buffer.read(cls._preamble_.size)
        if len(preamble) != cls._preamble_.size:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__qualname__!r}')
        try:
            relo_token, *preamble_values, via_length, destination_length, options_length = cls._preamble_.unpack(preamble)
        except struct.error as exc:
            raise ValueError(f'Cannot extract {cls.__qualname__!r} from buffer: {exc!s}') from exc
        if relo_token != RELO_TOKEN:
            raise ValueError(f'The buffer does not contain valid {cls.__qualname__!r} data')
        via_data = buffer.read(via_length)
        destination_data = buffer.read(destination_length)
        options_data = buffer.read(options_length)
        if len(via_data) + len(destination_data) + len(options_data) != via_length + destination_length + options_length:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__qualname__!r}')
        instance = super(Structure, cls).__new__(cls)
        for name, value in zip(cls._fields_, preamble_values, strict=False):
            instance.__dict__[name] = value
        instance.__dict__['via_list'] = cls.via_list.list_type.from_wire(via_data)
        instance.__dict__['destination_list'] = cls.destination_list.list_type.from_wire(destination_data)
        instance.__dict__['options'] = cls.options.list_type.from_wire(options_data)
        return instance

    def to_wire(self) -> bytes:
        preamble = self._preamble_.pack(
            RELO_TOKEN,
            self.overlay,
            self.configuration_sequence,
            self.version,
            self.ttl,
            self.fragment,
            self.length,
            self.transaction_id,
            self.max_response_length,
            self.via_list.wire_length(),
            self.destination_list.wire_length(),
            self.options.wire_length(),
        )
        return preamble + self.via_list.to_wire() + self.destination_list.to_wire() + self.options.to_wire()

    def wire_length(self) -> int:
        return self._preamble_.size + self.via_list.wire_length() + self.destination_list.wire_length() + self.options.wire_length()


class MessageContents(AnnotatedStructure):
    code: Element[UInt16] = Element(UInt16)
    body: Element[bytes] = Element(bytes, adapter=Opaque32Adapter)
    extensions: ListElement[MessageExtension] = ListElement(MessageExtension, default=(), maxsize=2**32 - 1)

    @classmethod
    def for_message(cls, message: Message, extensions: Sequence[MessageExtension] = ()) -> Self:
        if message._code_ == 0:
            raise TypeError(f'Cannot use abstract message type {message.__class__.__qualname__!r}')
        return cls(code=message._code_, body=message.to_wire(), extensions=extensions)


class SecurityBlock(AnnotatedStructure):
    certificates: ListElement[GenericCertificate] = ListElement(GenericCertificate, default=(), maxsize=2**16 - 1)
    signature: Element[Signature] = Element(Signature)
