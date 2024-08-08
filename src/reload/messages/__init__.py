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
from collections.abc import MutableMapping, Sequence
from contextvars import ContextVar
from functools import lru_cache
from io import BytesIO
from ipaddress import IPv4Address, IPv6Address, ip_address
from secrets import randbelow
from typing import ClassVar, Self

from aioice.candidate import Candidate

from reload.configuration import Configuration
from reload.python.contextvars import run_in_context

from .datamodel import (
    AddressType,
    CandidateType,
    CertificateType,
    ChordLeaveType,
    ChordUpdateType,
    CompositeAdapter,
    ConfigUpdateType,
    DestinationType,
    ErrorCode,
    ForwardingFlags,
    ForwardingOptionType,
    FramedMessageType,
    HashAlgorithm,
    IPv4AddressAdapter,
    IPv6AddressAdapter,
    LiteralStringAdapter,
    MessageExtensionType,
    NodeID,
    NoLength,
    Opaque8,
    Opaque8Adapter,
    Opaque16,
    Opaque16Adapter,
    Opaque24,
    Opaque24Adapter,
    Opaque32,
    Opaque32Adapter,
    OpaqueID,
    OverlayLinkType,
    ProbeInformationType,
    ResourceID,
    SignatureAlgorithm,
    SignerIdentityType,
    String8Adapter,
    String16Adapter,
    UInt8,
    UInt8Adapter,
    UInt16,
    UInt16Adapter,
    UInt32,
    UInt32Adapter,
    UInt64Adapter,
    VariableLengthList,
    WireData,
)
from .elements import AnnotatedStructure, ContextVarDependentElement, DependentElementSpec, Element, FieldDependentElement, ListElement, Structure
from .exceptions import UnknownKindError
from .kinds import DataModel, Kind, KindID

__all__ = (  # noqa: RUF022
    # Generic elements
    'Empty',
    'KindDescriptionList',

    # Link related elements
    'IPv4AddrPort',
    'IPv6AddrPort',
    'IPAddressPort',
    'ICEExtension',
    'ICECandidate',

    # Routing and topology elements
    'Destination',
    'ForwardingOption',
    'MessageExtension',
    'NodeNeighbors',
    'NodeNeighborsFingers',
    'ProbeInformation',

    # Signature elements
    'CertificateHash',
    'CertificateHashNodeID',
    'GenericCertificate',
    'SignatureAndHashAlgorithm',
    'SignerIdentity',
    'Signature',

    # Storage elements
    'data_model',

    'DataValue',
    'ArrayEntry',
    'DictionaryEntry',
    'StoredData',
    'StoreKindData',
    'StoreKindResponse',

    # Framing elements
    'AckFrame',
    'DataFrame',

    # Messages (the requests and responses for the overlay methods)
    'Message',

    'ProbeRequest',
    'ProbeResponse',
    'AttachRequest',
    'AttachResponse',
    'StoreRequest',
    'StoreResponse',
    'JoinRequest',
    'JoinResponse',
    'LeaveRequest',
    'LeaveResponse',
    'UpdateRequest',
    'UpdateResponse',
    'RouteQueryRequest',
    'RouteQueryResponse',
    'PingRequest',
    'PingResponse',
    'AppAttachRequest',
    'AppAttachResponse',
    'ConfigUpdateRequest',
    'ConfigUpdateResponse',
    'ErrorResponse',

    # Overlay specific message extensions
    'ChordLeaveData',

    # Toplevel structures
    'ForwardingHeader',
    'MessageContents',
    'SecurityBlock',

    # Helpers
    'new_transaction_id',
    'overlay_id',
)


RELOAD_VERSION = 10  # The version of the RELOAD protocol being implemented times 10 (currently 1.0)
RELO_TOKEN = b'\xd2ELO'  # 'RELO' with the high bit of the 1st character set to 1


# Generic elements

class Empty(AnnotatedStructure):
    pass


# Holds one or more XML kind-block elements encoded as Opaque16 bytes
class KindDescriptionList(VariableLengthList[Opaque16], maxsize=2**24 - 1):
    pass


# Link related elements

class IPv4AddrPort(AnnotatedStructure):
    addr: Element[IPv4Address] = Element(IPv4Address, adapter=IPv4AddressAdapter)
    port: Element[int] = Element(int, adapter=UInt16Adapter)


class IPv6AddrPort(AnnotatedStructure):
    addr: Element[IPv6Address] = Element(IPv6Address, adapter=IPv6AddressAdapter)
    port: Element[int] = Element(int, adapter=UInt16Adapter)


class IPAddressPort(AnnotatedStructure):
    # AddressType type       // the type of IP address in addr_port
    # uint8       length     // length of addr_port (not exposed)
    # IPAddrPort  addr_port  // either IPv4AddrPort or IPv6AddrPort based on type

    _addr_port_specification: ClassVar = DependentElementSpec[IPv4AddrPort | IPv6AddrPort, AddressType](
        type_map={
            AddressType.ipv4_address: IPv4AddrPort,
            AddressType.ipv6_address: IPv6AddrPort,
        },
        length_type=UInt8,
    )

    type: Element[AddressType] = Element(AddressType)
    addr_port: FieldDependentElement[IPv4AddrPort | IPv6AddrPort, AddressType] = FieldDependentElement(control_field=type, specification=_addr_port_specification)

    @classmethod
    def from_address(cls, host: str, port: int) -> Self:
        address = ip_address(host)
        match address:
            case IPv4Address():
                return cls(type=AddressType.ipv4_address, addr_port=IPv4AddrPort(addr=address, port=port))
            case IPv6Address():
                return cls(type=AddressType.ipv6_address, addr_port=IPv6AddrPort(addr=address, port=port))


class ICEExtension(AnnotatedStructure):
    name: Element[str] = Element(str, adapter=String16Adapter)
    value: Element[str] = Element(str, default='', adapter=String16Adapter)


class ICECandidate(AnnotatedStructure):
    _related_address_specification: ClassVar = DependentElementSpec[IPAddressPort | Empty, CandidateType](
        type_map={
            CandidateType.host: Empty,
            CandidateType.srflx: IPAddressPort,
            CandidateType.relay: IPAddressPort,
        },
        length_type=NoLength,
    )

    addr_port: Element[IPAddressPort] = Element(IPAddressPort)
    link_type: Element[OverlayLinkType] = Element(OverlayLinkType, default=OverlayLinkType.DTLS_UDP_SR)
    foundation: Element[str] = Element(str, adapter=String8Adapter)
    priority: Element[int] = Element(int, adapter=UInt32Adapter)
    type: Element[CandidateType] = Element(CandidateType)
    related_address: FieldDependentElement[IPAddressPort | Empty, CandidateType] = FieldDependentElement(control_field=type, specification=_related_address_specification)
    extensions: ListElement[ICEExtension] = ListElement(ICEExtension, default=(), maxsize=2**16 - 1)

    @classmethod
    def from_candidate(cls, candidate: Candidate) -> Self:
        if candidate.related_address is not None and candidate.related_port is not None:
            related_address = IPAddressPort.from_address(candidate.related_address, candidate.related_port)
        else:
            related_address = Empty()
        return cls(
            addr_port=IPAddressPort.from_address(candidate.host, candidate.port),
            foundation=candidate.foundation,
            priority=candidate.priority,
            type=CandidateType[candidate.type],
            related_address=related_address,
        )

    def to_candidate(self) -> Candidate:
        ice_address = self.addr_port.addr_port
        match self.related_address:
            case IPAddressPort(addr_port=addr_port):
                related_address = str(addr_port.addr)
                related_port = addr_port.port
            case Empty():
                related_address = None
                related_port = None
        return Candidate(
            foundation=self.foundation,
            component=1,
            transport='udp',
            priority=self.priority,
            host=str(ice_address.addr),
            port=ice_address.port,
            type=self.type.name,
            related_address=related_address,
            related_port=related_port,
        )


# Routing and topology elements

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

    _data_specification: ClassVar = DependentElementSpec[NodeID | ResourceID | OpaqueID, DestinationType](
        type_map={
            DestinationType.node: NodeID,
            DestinationType.resource: ResourceID,
            DestinationType.opaque_id_type: OpaqueID,
        },
        length_type=UInt8,
    )

    type: Element[DestinationType] = Element(DestinationType)
    data: FieldDependentElement[NodeID | ResourceID | OpaqueID, DestinationType] = FieldDependentElement(control_field=type, specification=_data_specification)

    def __repr__(self) -> str:
        return f'<{self.__class__.__qualname__}: {self.type.name} {self.data.hex()}>'

    @property
    def is_opaque_id(self) -> bool:
        return self.type is DestinationType.opaque_id_type and len(self.data) == 2 and self.data[0] & 0x80 != 0  # noqa: PLR2004

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if not isinstance(buffer, BytesIO):
            buffer = BytesIO(buffer)
        buffer_bytes = buffer.getvalue()
        if len(buffer_bytes) < 2:  # noqa: PLR2004
            raise ValueError(f'Insufficient data in buffer to extract {cls.__qualname__!r}')
        if buffer_bytes[0] & 0x80:
            return cls(type=DestinationType.opaque_id_type, data=OpaqueID(buffer.read(2)))
        return super().from_wire(buffer)

    def to_wire(self) -> bytes:
        if self.is_opaque_id:
            return bytes(self.data)
        return super().to_wire()

    def wire_length(self) -> int:
        if self.is_opaque_id:
            return 2
        return super().wire_length()


class ForwardingOptionAdapter(CompositeAdapter[ForwardingOptionType | UInt8]):
    pass


class ForwardingOption(AnnotatedStructure):
    _option_specification: ClassVar = DependentElementSpec[Opaque16, ForwardingOptionType | UInt8](
        type_map={
            # currently there are no forwarding options defined in the RFC
        },
        fallback_type=Opaque16,
        length_type=UInt16,
    )

    type: Element[ForwardingOptionType | UInt8] = Element(ForwardingOptionType | UInt8, adapter=ForwardingOptionAdapter)
    flags: Element[ForwardingFlags] = Element(ForwardingFlags)
    option: FieldDependentElement[Opaque16, ForwardingOptionType | UInt8] = FieldDependentElement(control_field=type, specification=_option_specification, default=Opaque16())


class MessageExtensionAdapter(CompositeAdapter[MessageExtensionType | UInt16]):
    pass


class MessageExtension(AnnotatedStructure):
    _extension_specification: ClassVar = DependentElementSpec[Opaque32, MessageExtensionType | UInt16](
        type_map={
            # currently there are no message extensions defined in the RFC
        },
        fallback_type=Opaque32,
        length_type=UInt32,
    )

    type: Element[MessageExtensionType | UInt16] = Element(MessageExtensionType | UInt16, adapter=MessageExtensionAdapter)
    critical: Element[bool] = Element(bool)
    extension: FieldDependentElement[Opaque32, MessageExtensionType | UInt16] = FieldDependentElement(control_field=type, specification=_extension_specification, default=Opaque32())


class NodeNeighbors(AnnotatedStructure):
    predecessors: ListElement[NodeID] = ListElement(NodeID, maxsize=2**16 - 1)
    successors: ListElement[NodeID] = ListElement(NodeID, maxsize=2**16 - 1)


class NodeNeighborsFingers(AnnotatedStructure):
    predecessors: ListElement[NodeID] = ListElement(NodeID, maxsize=2**16 - 1)
    successors: ListElement[NodeID] = ListElement(NodeID, maxsize=2**16 - 1)
    fingers: ListElement[NodeID] = ListElement(NodeID, maxsize=2**16 - 1)


class ProbeInformationAdapter(CompositeAdapter[ProbeInformationType | UInt8]):
    pass


class ProbeInformation(AnnotatedStructure):
    _value_specification: ClassVar = DependentElementSpec[UInt32 | Opaque8, ProbeInformationType | UInt8](
        type_map={
            ProbeInformationType.responsible_set: UInt32,
            ProbeInformationType.num_resources: UInt32,
            ProbeInformationType.uptime: UInt32,
        },
        fallback_type=Opaque8,
        length_type=UInt8,
    )

    type: Element[ProbeInformationType | UInt8] = Element(ProbeInformationType | UInt8, adapter=ProbeInformationAdapter)
    value: FieldDependentElement[UInt32 | Opaque8, ProbeInformationType | UInt8] = FieldDependentElement(control_field=type, specification=_value_specification)


# Signature elements

class CertificateHash(AnnotatedStructure):
    hash_algorithm: Element[HashAlgorithm] = Element(HashAlgorithm)
    certificate_hash: Element[bytes] = Element(bytes, adapter=Opaque8Adapter)


class CertificateHashNodeID(CertificateHash):
    pass


class GenericCertificate(AnnotatedStructure):
    type: Element[CertificateType] = Element(CertificateType)
    certificate: Element[bytes] = Element(bytes, adapter=Opaque16Adapter)


class SignatureAndHashAlgorithm(AnnotatedStructure):
    hash: Element[HashAlgorithm] = Element(HashAlgorithm)
    signature: Element[SignatureAlgorithm] = Element(SignatureAlgorithm)


class SignerIdentity(AnnotatedStructure):
    _identity_specification: ClassVar = DependentElementSpec[CertificateHash | CertificateHashNodeID | Empty, SignerIdentityType](
        type_map={
            SignerIdentityType.cert_hash: CertificateHash,
            SignerIdentityType.cert_hash_node_id: CertificateHashNodeID,
            SignerIdentityType.none: Empty,
        },
        length_type=UInt16,
    )

    type: Element[SignerIdentityType] = Element(SignerIdentityType)
    identity: FieldDependentElement[CertificateHash | CertificateHashNodeID | Empty, SignerIdentityType] = FieldDependentElement(control_field=type, specification=_identity_specification)

    def __repr__(self) -> str:
        return f'<{self.__class__.__qualname__}: {self.type.name} {self.identity!r}>'


class Signature(AnnotatedStructure):
    algorithm: Element[SignatureAndHashAlgorithm] = Element(SignatureAndHashAlgorithm)
    identity: Element[SignerIdentity] = Element(SignerIdentity)
    value: Element[bytes] = Element(bytes, adapter=Opaque16Adapter)


# Storage elements

data_model: ContextVar[DataModel] = ContextVar('data_model')

_unknown_kinds: ContextVar[list[KindID]] = ContextVar('_unknown_kinds')


def data_model_context_setter(value: KindID) -> None:
    try:
        kind = Kind.lookup(value)
    except KeyError as exc:
        unknown_kinds = _unknown_kinds.get(None)
        if unknown_kinds is None:
            _unknown_kinds.set([value])
        else:
            unknown_kinds.append(value)
        raise UnknownKindError(value) from exc
    data_model.set(kind.data_model)


class DataValue(AnnotatedStructure):
    exists: Element[bool] = Element(bool)
    value: Element[bytes] = Element(bytes, adapter=Opaque32Adapter)


class ArrayEntry(AnnotatedStructure):
    index: Element[int] = Element(int, adapter=UInt32Adapter)
    value: Element[DataValue] = Element(DataValue)


class DictionaryEntry(AnnotatedStructure):
    key: Element[bytes] = Element(bytes, adapter=Opaque16Adapter)
    value: Element[DataValue] = Element(DataValue)


class StoredData(AnnotatedStructure):
    _value_specification: ClassVar = DependentElementSpec[DataValue | ArrayEntry | DictionaryEntry, DataModel](
        type_map={
            DataModel.SINGLE: DataValue,
            DataModel.ARRAY: ArrayEntry,
            DataModel.DICTIONARY: DictionaryEntry,
        },
        length_type=NoLength,
    )

    # There is an unsigned 32-bit length field here in the structure that precedes the
    # other fields and contains the size of the rest of the elements in the structure.
    storage_time: Element[int] = Element(int, adapter=UInt64Adapter)
    lifetime: Element[int] = Element(int, adapter=UInt32Adapter)
    value: ContextVarDependentElement[DataValue | ArrayEntry | DictionaryEntry, DataModel] = ContextVarDependentElement(control_var=data_model, specification=_value_specification)
    signature: Element[Signature] = Element(Signature)

    @classmethod
    @run_in_context(sentinel=Structure._from_wire_running_)
    def from_wire(cls, buffer: WireData) -> Self:
        if not isinstance(buffer, BytesIO):
            buffer = BytesIO(buffer)
        try:
            UInt32Adapter.from_wire(buffer)
        except ValueError as exc:
            raise ValueError(f'Could not read the length of {cls.__qualname__} from wire: {exc}') from exc
        return super().from_wire(buffer)

    def to_wire(self) -> bytes:
        return UInt32Adapter.to_wire(len(wire_data := super().to_wire())) + wire_data

    def wire_length(self) -> int:
        return super().wire_length() + UInt32._size_


class StoreKindData(AnnotatedStructure):
    kind_id: Element[int] = Element(int, adapter=UInt32Adapter, context_setter=data_model_context_setter)
    generation_counter: Element[int] = Element(int, adapter=UInt64Adapter)
    values: ListElement[StoredData] = ListElement(StoredData, default=(), maxsize=2**32 - 1)

    @classmethod
    @run_in_context(sentinel=Structure._from_wire_running_)
    def from_wire(cls, buffer: WireData) -> Self:
        if not isinstance(buffer, BytesIO):
            buffer = BytesIO(buffer)
        instance = super(Structure, cls).__new__(cls)
        try:
            cls.kind_id.from_wire(instance, buffer)
        except UnknownKindError:
            cls.generation_counter.from_wire(instance, buffer)
            list_length = UInt32Adapter.from_wire(buffer)
            list_data = buffer.read(list_length)
            if len(list_data) < list_length:
                raise ValueError(f'Insufficient data in buffer to read {cls.__qualname__}.values') from None
            instance.values = cls.values.list_type()  # Ignore all values since we do not understand the Kind and return an empty list instead
        else:
            cls.generation_counter.from_wire(instance, buffer)
            cls.values.from_wire(instance, buffer)
        return instance


class StoreKindResponse(AnnotatedStructure):
    kind_id: Element[int] = Element(int, adapter=UInt32Adapter)
    generation_counter: Element[int] = Element(int, adapter=UInt64Adapter)
    replicas: ListElement[NodeID] = ListElement(NodeID, default=(), maxsize=2**16 - 1)


# Framing elements

class AckFrame(AnnotatedStructure):
    sequence: Element[int] = Element(int, adapter=UInt32Adapter)  # This is the sequence number of the data frame being acknowledged
    received: Element[int] = Element(int, adapter=UInt32Adapter)


class DataFrame(AnnotatedStructure):
    sequence: Element[int] = Element(int, adapter=UInt32Adapter)
    message: Element[bytes] = Element(bytes, adapter=Opaque24Adapter)


# Custom adapters for messages

class ActiveRoleAdapter(LiteralStringAdapter, value='active', maxsize=2**8 - 1):
    pass


class PassiveRoleAdapter(LiteralStringAdapter, value='passive', maxsize=2**8 - 1):
    pass


class ConfigUpdateAdapter(CompositeAdapter[ConfigUpdateType | UInt8]):
    pass


# Messages (the requests and responses for the overlay methods)

type MessageType = type[Message]


class Message(AnnotatedStructure):
    # message code 0 is invalid and should not be used anywhere
    # the message code should be overridden by subclasses

    _code_: ClassVar[UInt16] = UInt16()
    _registry_: ClassVar[MutableMapping[int, MessageType]] = {}

    def __init_subclass__(cls, *, code: int = 0, **kw: object) -> None:
        super().__init_subclass__(**kw)
        if cls._code_ != 0 and code == 0:
            raise TypeError('When inheriting a message type with a non-zero code, the new type code must be different from 0')
        cls._code_ = UInt16(code)
        if cls._code_ != 0 and cls._registry_.setdefault(cls._code_, cls) is not cls:
            raise TypeError(f'Message code 0x{cls._code_:02x} is already used by {cls._registry_[cls._code_].__qualname__!r}')

    def __class_getitem__(cls, code: int) -> MessageType:
        try:
            return cls._registry_[code]
        except KeyError as exc:
            raise TypeError(f'Unknown message code 0x{code:x}') from exc


class ProbeRequest(Message, code=0x01):
    requested_info: ListElement[ProbeInformationType] = ListElement(ProbeInformationType, default=(), maxsize=2**8 - 1)


class ProbeResponse(Message, code=0x02):
    probe_info: ListElement[ProbeInformation] = ListElement(ProbeInformation, default=(), maxsize=2**16 - 1)


class AttachRequest(Message, code=0x03):
    username: Element[str] = Element(str, adapter=String8Adapter)
    password: Element[str] = Element(str, adapter=String8Adapter)
    role: Element[str] = Element(str, default=PassiveRoleAdapter._static_value_, adapter=PassiveRoleAdapter)
    candidates: ListElement[ICECandidate] = ListElement(ICECandidate, maxsize=2**16 - 1)
    send_update: Element[bool] = Element(bool, default=False)


# The response has the same structure as the request, but with a different code and a different role value
class AttachResponse(AttachRequest, code=0x04):
    role: Element[str] = Element(str, default=ActiveRoleAdapter._static_value_, adapter=ActiveRoleAdapter)


class StoreRequest(Message, code=0x07):
    resource: Element[ResourceID] = Element(ResourceID)
    replica_number: Element[int] = Element(int, adapter=UInt8Adapter)
    kind_data: ListElement[StoreKindData] = ListElement(StoreKindData, default=(), maxsize=2**32 - 1)

    @classmethod
    @run_in_context(sentinel=Structure._from_wire_running_)
    def from_wire(cls, buffer: WireData) -> Self:
        instance = super().from_wire(buffer)
        unknown_kinds = _unknown_kinds.get([])
        if unknown_kinds:
            raise UnknownKindError(*unknown_kinds)
        return instance


class StoreResponse(Message, code=0x08):
    kind_responses: ListElement[StoreKindResponse] = ListElement(StoreKindResponse, default=(), maxsize=2**16 - 1)


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


class UpdateRequest(Message, code=0x13):
    _data_specification: ClassVar = DependentElementSpec[NodeNeighbors | NodeNeighborsFingers | Empty, ChordUpdateType](
        type_map={
            ChordUpdateType.peer_ready: Empty,
            ChordUpdateType.neighbors: NodeNeighbors,
            ChordUpdateType.full: NodeNeighborsFingers,
        },
        length_type=NoLength,
    )
    uptime: Element[int] = Element(int, adapter=UInt32Adapter)
    type: Element[ChordUpdateType] = Element(ChordUpdateType)
    data: FieldDependentElement[NodeNeighbors | NodeNeighborsFingers | Empty, ChordUpdateType] = FieldDependentElement(control_field=type, specification=_data_specification)


class UpdateResponse(Message, code=0x14):
    pass


class RouteQueryRequest(Message, code=0x15):
    send_update: Element[bool] = Element(bool)
    destination: Element[Destination] = Element(Destination)
    overlay_data: Element[bytes] = Element(bytes, default=b'', adapter=Opaque16Adapter)


# This response is Chord specific
class RouteQueryResponse(Message, code=0x16):
    next_peer: Element[NodeID] = Element(NodeID)


class PingRequest(Message, code=0x17):
    padding: Element[bytes] = Element(bytes, default=b'', adapter=Opaque16Adapter)


class PingResponse(Message, code=0x18):
    id: Element[int] = Element(int, adapter=UInt64Adapter)
    time: Element[int] = Element(int, adapter=UInt64Adapter)


class AppAttachRequest(Message, code=0x1d):
    username: Element[str] = Element(str, adapter=String8Adapter)
    password: Element[str] = Element(str, adapter=String8Adapter)
    application: Element[int] = Element(int, adapter=UInt16Adapter)
    role: Element[str] = Element(str, default=PassiveRoleAdapter._static_value_, adapter=PassiveRoleAdapter)
    candidates: ListElement[ICECandidate] = ListElement(ICECandidate, maxsize=2**16 - 1)


# The response has the same structure as the request, but with a different code and a different role value
class AppAttachResponse(AppAttachRequest, code=0x1e):
    role: Element[str] = Element(str, default=ActiveRoleAdapter._static_value_, adapter=ActiveRoleAdapter)


class ConfigUpdateRequest(Message, code=0x21):
    _data_specification: ClassVar = DependentElementSpec[KindDescriptionList | Opaque24 | Opaque32, ConfigUpdateType | UInt8](
        type_map={
            ConfigUpdateType.config: Opaque24,
            ConfigUpdateType.kind: KindDescriptionList,
        },
        fallback_type=Opaque32,
        length_type=UInt32,
    )

    type: Element[ConfigUpdateType | UInt8] = Element(ConfigUpdateType | UInt8, adapter=ConfigUpdateAdapter)
    data: FieldDependentElement[KindDescriptionList | Opaque24 | Opaque32, ConfigUpdateType | UInt8] = FieldDependentElement(control_field=type, specification=_data_specification)


class ConfigUpdateResponse(Message, code=0x22):
    pass


class ErrorResponse(Message, code=0xffff):
    code: Element[ErrorCode] = Element(ErrorCode)
    info: Element[bytes] = Element(bytes, default=b'', adapter=Opaque16Adapter)


# Overlay specific message extensions

class ChordLeaveData(AnnotatedStructure):
    type: Element[ChordLeaveType] = Element(ChordLeaveType)
    node_list: ListElement[NodeID] = ListElement(NodeID, maxsize=2**16 - 1)


# Toplevel structures

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

    via_list: ListElement[Destination] = ListElement(Destination, default=())
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


class FramedMessage(AnnotatedStructure):
    _frame_specification = DependentElementSpec[DataFrame | AckFrame, FramedMessageType](
        type_map={
            FramedMessageType.data: DataFrame,
            FramedMessageType.ack: AckFrame,
        },
        length_type=NoLength,
    )

    type: Element[FramedMessageType] = Element(FramedMessageType)
    frame: FieldDependentElement[DataFrame | AckFrame, FramedMessageType] = FieldDependentElement(control_field=type, specification=_frame_specification)


# Helpers

def new_transaction_id() -> int:
    return randbelow(2**64 - 1)


@lru_cache
def overlay_id(overlay: str | bytes) -> int:
    if isinstance(overlay, str):
        overlay = overlay.encode()
    return int.from_bytes(hashlib.sha1(overlay, usedforsecurity=False).digest()[-4:])
