# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from collections.abc import Sequence
from contextvars import ContextVar
from io import BytesIO
from ipaddress import IPv4Address, IPv6Address
from typing import ClassVar, Self

import pytest
from reload.configuration import Configuration
from reload.messages import (
    AckFrame,
    AppAttachRequest,
    AppAttachResponse,
    ArrayEntry,
    ArrayEntryMeta,
    ArrayRangeList,
    AttachRequest,
    AttachResponse,
    CertificateHash,
    ChordLeaveData,
    ConfigUpdateRequest,
    ConfigUpdateResponse,
    DataFrame,
    DataValue,
    DataValueMeta,
    Destination,
    DictionaryEntry,
    DictionaryEntryMeta,
    DictionaryKeyList,
    Empty,
    ErrorResponse,
    FetchKindResponse,
    FetchRequest,
    FetchResponse,
    FindKindData,
    FindRequest,
    FindResponse,
    ForwardingHeader,
    ForwardingOption,
    ForwardingOptionAdapter,
    FramedMessage,
    GenericCertificate,
    ICECandidate,
    IPAddressPort,
    IPv4AddrPort,
    JoinRequest,
    JoinResponse,
    KindDescriptionList,
    LeaveRequest,
    LeaveResponse,
    Message,
    MessageContents,
    MessageExtension,
    NodeNeighbors,
    NodeNeighborsFingers,
    PingRequest,
    PingResponse,
    ProbeInformation,
    ProbeRequest,
    ProbeResponse,
    RouteQueryRequest,
    RouteQueryResponse,
    SecurityBlock,
    Signature,
    SignatureAndHashAlgorithm,
    SignerIdentity,
    StatKindResponse,
    StatRequest,
    StatResponse,
    StoredData,
    StoredDataSpecifier,
    StoredMetaData,
    StoreKindData,
    StoreKindResponse,
    StoreRequest,
    StoreResponse,
    UpdateRequest,
    UpdateResponse,
    data_model,
    new_transaction_id,
)
from reload.messages.datamodel import (
    AdapterRegistry,
    AddressType,
    BooleanAdapter,
    CandidateType,
    CertificateType,
    ChordLeaveType,
    ChordUpdateType,
    CompositeAdapter,
    ConfigUpdateType,
    DataWireAdapter,
    DataWireProtocol,
    DestinationType,
    Enum,
    ErrorCode,
    FixedSize,
    Flag,
    ForwardingFlags,
    ForwardingOptionType,
    FramedMessageType,
    HashAlgorithm,
    Int8,
    Int8Adapter,
    Int16,
    Int16Adapter,
    Int32,
    Int32Adapter,
    Int64,
    Int64Adapter,
    Int128,
    Int128Adapter,
    Integer,
    IntegerAdapter,
    IPv4AddressAdapter,
    IPv6AddressAdapter,
    List,
    LiteralBytes,
    LiteralBytesAdapter,
    LiteralStringAdapter,
    NodeID,
    NoLength,
    Opaque,
    Opaque8,
    Opaque8Adapter,
    Opaque16,
    Opaque16Adapter,
    Opaque24,
    Opaque24Adapter,
    Opaque32,
    Opaque32Adapter,
    OpaqueAdapter,
    OpaqueID,
    ProbeInformationType,
    RELOToken,
    ResourceID,
    SignatureAlgorithm,
    SignerIdentityType,
    SizedDataWireProtocol,
    String8Adapter,
    String16Adapter,
    String24Adapter,
    String32Adapter,
    StringAdapter,
    UInt8,
    UInt8Adapter,
    UInt16,
    UInt16Adapter,
    UInt32,
    UInt32Adapter,
    UInt64,
    UInt64Adapter,
    UInt128,
    UInt128Adapter,
    UnsignedInteger,
    UnsignedIntegerAdapter,
    VariableLengthList,
)
from reload.messages.elements import (
    AnnotatedStructure,
    ContextFieldDependentElement,
    ContextStructure,
    ContextVarDependentElement,
    DependentElementSpec,
    Element,
    FieldDependentElement,
    ListElement,
    Structure,
    _reprproxy,
)
from reload.messages.exceptions import UnknownKindError
from reload.messages.kinds import AccessControl, CertificateByUser, DataModel, Kind, SIPRegistration
from reload.python.contextvars import ContextSpec


class TestDataModel:

    def test_protocols(self) -> None:
        # The isinstance/issubclass tests only checks that the types have the
        # protocol members present but it does not check if their signature
        # or the involved types are correct. Still, this can be useful to
        # detect if the types forgot to implement some protocol member.

        # DaraWire Adapter implementers.
        #
        # Adapters can't be tested with issubclass because they have non-method
        # members, but they can be (surprisingly) tested with isinstance.
        # Derivative adapters (like UInt8Adapter, ...) do not need to be tested
        # as they inherit their protocol members from their parents.

        assert isinstance(BooleanAdapter, DataWireAdapter)

        assert isinstance(IntegerAdapter, DataWireAdapter)
        assert isinstance(UnsignedIntegerAdapter, DataWireAdapter)

        assert isinstance(OpaqueAdapter, DataWireAdapter)
        assert isinstance(StringAdapter, DataWireAdapter)
        assert isinstance(LiteralBytesAdapter, DataWireAdapter)
        assert isinstance(LiteralStringAdapter, DataWireAdapter)

        assert isinstance(IPv4AddressAdapter, DataWireAdapter)
        assert isinstance(IPv6AddressAdapter, DataWireAdapter)

        assert isinstance(CompositeAdapter, DataWireAdapter)

        # DataWireProtocol implementers.
        #
        # The derivative types (like UInt8, subclasses of Structure, ...) don't
        # need to be tested as they inherit their protocol members from their
        # parent and will automatically test true. The only case where they
        # would test false, is if a subclass explicitly sets some protocol
        # member to None, which we never do throughout the code.

        assert issubclass(Integer, DataWireProtocol)
        assert issubclass(UnsignedInteger, DataWireProtocol)

        assert issubclass(Enum, DataWireProtocol)
        assert issubclass(Flag, DataWireProtocol)

        assert issubclass(LiteralBytes, DataWireProtocol)
        assert issubclass(FixedSize, DataWireProtocol)
        assert issubclass(Opaque, DataWireProtocol)

        assert issubclass(List, DataWireProtocol)
        assert issubclass(VariableLengthList, DataWireProtocol)

        assert issubclass(Structure, DataWireProtocol)

    def test_adapter_registry(self) -> None:
        class MyInt(int):
            pass

        AdapterRegistry.associate(MyInt, UInt32Adapter)

        assert AdapterRegistry.get_adapter(bool) is BooleanAdapter  # this is pre-registered
        assert AdapterRegistry.get_adapter(MyInt) is UInt32Adapter

        with pytest.raises(TypeError, match=r'Adapters for types that already implement DataWireProtocol must .*'):
            AdapterRegistry.associate(UInt32, UInt32Adapter)

    def test_boolean_adapter(self) -> None:
        assert BooleanAdapter.from_wire(BytesIO(b'\x00')) is False
        assert BooleanAdapter.from_wire(b'\x00') is False
        assert BooleanAdapter.from_wire(b'\x01') is True
        with pytest.raises(ValueError, match='Invalid boolean value: '):
            BooleanAdapter.from_wire(b'\x02')
        with pytest.raises(ValueError, match='Insufficient data in buffer to extract boolean value'):
            BooleanAdapter.from_wire(b'')
        for value in (False, True):
            assert BooleanAdapter.from_wire(BooleanAdapter.to_wire(value)) is value
            assert BooleanAdapter.wire_length(value) == 1
            assert len(BooleanAdapter.to_wire(value)) == BooleanAdapter.wire_length(value)

    def test_integer_adapters(self) -> None:
        for adapter in (Int8Adapter, Int16Adapter, Int32Adapter, Int64Adapter, Int128Adapter):
            min_value = -adapter._mean_
            max_value = +adapter._mean_ - 1

            assert adapter.from_wire(BytesIO(bytes(16))) == 0

            assert adapter.from_wire(adapter.to_wire(0)) == 0
            assert adapter.from_wire(adapter.to_wire(min_value)) == min_value
            assert adapter.from_wire(adapter.to_wire(max_value)) == max_value

            assert len(adapter.to_wire(0)) == adapter.wire_length(0) == adapter._size_
            assert len(adapter.to_wire(min_value)) == adapter.wire_length(min_value) == adapter._size_
            assert len(adapter.to_wire(max_value)) == adapter.wire_length(max_value) == adapter._size_

            with pytest.raises(ValueError, match='Insufficient data in buffer to extract'):
                adapter.from_wire(b'')
            with pytest.raises(ValueError, match='Value is out of range for'):
                adapter.validate(min_value - 1)
            with pytest.raises(ValueError, match='Value is out of range for'):
                adapter.validate(max_value + 1)

            assert adapter.validate(0) == 0
            assert adapter.validate(min_value) == min_value
            assert adapter.validate(max_value) == max_value

            with pytest.raises(ValueError, match='Value is out of range for '):
                adapter.validate(min_value - 1)
            with pytest.raises(ValueError, match='Value is out of range for '):
                adapter.validate(max_value + 1)

    def test_unsigned_adapters(self) -> None:
        for adapter in (UInt8Adapter, UInt16Adapter, UInt32Adapter, UInt64Adapter, UInt128Adapter):
            min_value = 0
            max_value = 2**adapter._bits_ - 1

            assert adapter.from_wire(BytesIO(bytes(16))) == 0

            assert adapter.from_wire(adapter.to_wire(0)) == 0
            assert adapter.from_wire(adapter.to_wire(min_value)) == min_value
            assert adapter.from_wire(adapter.to_wire(max_value)) == max_value

            assert len(adapter.to_wire(0)) == adapter.wire_length(0) == adapter._size_
            assert len(adapter.to_wire(min_value)) == adapter.wire_length(min_value) == adapter._size_
            assert len(adapter.to_wire(max_value)) == adapter.wire_length(max_value) == adapter._size_

            with pytest.raises(ValueError, match='Insufficient data in buffer to extract'):
                adapter.from_wire(b'')
            with pytest.raises(ValueError, match='Value is out of range for'):
                adapter.validate(min_value - 1)
            with pytest.raises(ValueError, match='Value is out of range for'):
                adapter.validate(max_value + 1)

            assert adapter.validate(0) == 0
            assert adapter.validate(min_value) == min_value
            assert adapter.validate(max_value) == max_value

            with pytest.raises(ValueError, match='Value is out of range for '):
                adapter.validate(min_value - 1)
            with pytest.raises(ValueError, match='Value is out of range for '):
                adapter.validate(max_value + 1)

    def test_bytes_adapters(self) -> None:
        for adapter in (Opaque8Adapter, Opaque16Adapter, Opaque24Adapter, Opaque32Adapter):
            assert adapter.from_wire(adapter.to_wire(b'')) == b''
            assert adapter.from_wire(adapter.to_wire(b'test')) == b'test'

            assert len(adapter.to_wire(b'')) == adapter.wire_length(b'')
            assert len(adapter.to_wire(b'test')) == adapter.wire_length(b'test')

            with pytest.raises(ValueError, match='Insufficient data in buffer to extract the opaque bytes length'):
                adapter.from_wire(b'')
            with pytest.raises(ValueError, match='Insufficient data in buffer to extract the opaque bytes'):
                adapter.from_wire(adapter.to_wire(b'test')[:-1])

            assert adapter.validate(b'') == b''
            assert adapter.validate(b'test') == b'test'

            # Only test the types that have a reasonable max size
            if adapter in {Opaque8Adapter, Opaque16Adapter, Opaque24Adapter}:
                with pytest.raises(ValueError, match='Value is too long for opaque bytes '):
                    adapter.validate(bytes(adapter._maxsize_ + 1))

        class Opaque7Adapter(OpaqueAdapter, maxsize=2**7 - 1):
            pass

        with pytest.raises(ValueError, match='Data length is too big for opaque bytes'):
            Opaque7Adapter.from_wire(b'\x80')

        token = b'RELO'

        with pytest.raises(TypeError, match='The literal value has more than maxsize bytes'):
            class TestTokenAdapter(LiteralBytesAdapter, value=300 * b'0', maxsize=2**8 - 1):
                pass

        class RELOTokenAdapter(LiteralBytesAdapter, value=token):
            pass

        class RELOTokenWithSizeAdapter(LiteralBytesAdapter, value=token, maxsize=2**8 - 1):
            pass

        for adapter in (RELOTokenAdapter, RELOTokenWithSizeAdapter):
            assert adapter.from_wire(BytesIO(adapter.to_wire(token))) == token
            assert adapter.from_wire(adapter.to_wire(token)) == token
            assert len(adapter.to_wire(token)) == adapter.wire_length(token)

            with pytest.raises(ValueError, match='Insufficient data in buffer to extract literal bytes'):
                adapter.from_wire(b'')
            with pytest.raises(ValueError, match='Value on wire does not match literal bytes'):
                adapter.from_wire(Opaque8(token[::-1]).to_wire() if adapter is RELOTokenWithSizeAdapter else token[::-1])

            assert adapter.validate(token) is token
            with pytest.raises(ValueError, match='Invalid literal bytes value'):
                assert adapter.validate(b'test')

    def test_string_adapters(self) -> None:
        for adapter in (String8Adapter, String16Adapter, String24Adapter, String32Adapter):
            assert adapter.from_wire(adapter.to_wire('')) == ''
            assert adapter.from_wire(adapter.to_wire('test')) == 'test'
            assert adapter.from_wire(adapter.to_wire('\u0080test')) == '\u0080test'

            assert len(adapter.to_wire('')) == adapter.wire_length('')
            assert len(adapter.to_wire('test')) == adapter.wire_length('test')
            assert len(adapter.to_wire('\u0080test')) == adapter.wire_length('\u0080test')

            with pytest.raises(ValueError, match='Insufficient data in buffer to extract the length of the string'):
                adapter.from_wire(b'')
            with pytest.raises(ValueError, match='Insufficient data in buffer to extract the bytes representation of the string'):
                adapter.from_wire(adapter.to_wire('test')[:-1])

            assert adapter.validate('') == ''
            assert adapter.validate('test') == 'test'

            # Only test the types that have a reasonable max size
            if adapter in {String8Adapter, String16Adapter, String24Adapter}:
                with pytest.raises(ValueError, match='Value is too long for string '):
                    adapter.validate((adapter._maxsize_ + 1) * '0')

        assert String8Adapter.to_wire('\u0080test') == Opaque8('\u0080test'.encode()).to_wire()  # The encoding on the wire should be UTF-8

        with pytest.raises(ValueError, match='Cannot decode bytes to string'):
            String8Adapter.from_wire(b'\x04\x80abc')

        class String7Adapter(StringAdapter, maxsize=2**7 - 1):
            pass

        with pytest.raises(ValueError, match='Data length is too big for the string'):
            String7Adapter.from_wire(b'\x80')

        token = 'RELO'

        with pytest.raises(TypeError, match='The literal value has more than maxsize bytes'):
            class TestTokenAdapter(LiteralStringAdapter, value=300 * '0', maxsize=2**8 - 1):
                pass

        class RELOTokenAdapter(LiteralStringAdapter, value=token):
            pass

        class RELOTokenWithSizeAdapter(LiteralStringAdapter, value=token, maxsize=2**8 - 1):
            pass

        for adapter in (RELOTokenAdapter, RELOTokenWithSizeAdapter):
            assert adapter.from_wire(BytesIO(adapter.to_wire(token))) == token
            assert adapter.from_wire(adapter.to_wire(token)) == token
            assert len(adapter.to_wire(token)) == adapter.wire_length(token)

            with pytest.raises(ValueError, match='Insufficient data in buffer to extract literal string'):
                adapter.from_wire(b'')
            with pytest.raises(ValueError, match='Value on wire does not match literal string'):
                adapter.from_wire(Opaque8(token[::-1].encode()).to_wire() if adapter is RELOTokenWithSizeAdapter else token[::-1].encode())

            assert adapter.validate(token) is token
            with pytest.raises(ValueError, match='Invalid literal string value'):
                assert adapter.validate('test')

    def test_ip_address_adapters(self) -> None:
        ipv4_address = IPv4Address('127.0.0.1')
        ipv6_address = IPv6Address('::1')

        assert IPv4AddressAdapter.from_wire(BytesIO(IPv4AddressAdapter.to_wire(ipv4_address))) == ipv4_address
        assert IPv6AddressAdapter.from_wire(BytesIO(IPv6AddressAdapter.to_wire(ipv6_address))) == ipv6_address

        assert IPv4AddressAdapter.from_wire(IPv4AddressAdapter.to_wire(ipv4_address)) == ipv4_address
        assert IPv6AddressAdapter.from_wire(IPv6AddressAdapter.to_wire(ipv6_address)) == ipv6_address

        assert len(IPv4AddressAdapter.to_wire(ipv4_address)) == IPv4AddressAdapter.wire_length(ipv4_address)
        assert len(IPv6AddressAdapter.to_wire(ipv6_address)) == IPv6AddressAdapter.wire_length(ipv6_address)

        assert IPv4AddressAdapter.validate(ipv4_address) is ipv4_address
        assert IPv6AddressAdapter.validate(ipv6_address) is ipv6_address

        with pytest.raises(ValueError, match='Insufficient data in buffer to extract an IPv4Address'):
            IPv4AddressAdapter.from_wire(b'')
        with pytest.raises(ValueError, match='Insufficient data in buffer to extract an IPv6Address'):
            IPv6AddressAdapter.from_wire(b'')

    def test_composite_adapters(self) -> None:
        class AbstractCompositeAdapter[T: SizedDataWireProtocol](CompositeAdapter[T]):
            pass

        class TestAdapter(CompositeAdapter[ForwardingOptionType | FramedMessageType]):
            pass

        # Test restrictions when defining composite adapters

        with pytest.raises(TypeError, match='type can only be parameterized with a union of types or a type variable'):
            class TestAdapter1(CompositeAdapter[UInt8]):
                pass

        with pytest.raises(TypeError, match='All type members must have defined their byte size'):
            class TestAdapter2(CompositeAdapter[UnsignedInteger | Integer]):
                pass

        with pytest.raises(TypeError, match='All types must have the same byte size'):
            class TestAdapter3(CompositeAdapter[ForwardingOptionType | UInt16]):
                pass

        assert AbstractCompositeAdapter._abstract_ is True
        assert ForwardingOptionAdapter._abstract_ is False
        assert TestAdapter._abstract_ is False

        assert ForwardingOptionAdapter.from_wire(ForwardingOptionAdapter.to_wire(ForwardingOptionType.invalid)) is ForwardingOptionType.invalid
        assert ForwardingOptionAdapter.from_wire(ForwardingOptionAdapter.to_wire(UInt8(0x99))) == 0x99

        assert len(ForwardingOptionAdapter.to_wire(ForwardingOptionType.invalid)) == ForwardingOptionAdapter.wire_length(ForwardingOptionType.invalid)

        with pytest.raises(ValueError, match='Insufficient data in buffer to extract'):
            ForwardingOptionAdapter.from_wire(b'')

        with pytest.raises(ValueError, match='is not a valid'):
            TestAdapter.from_wire(b'\x99')

    def test_integer_types(self) -> None:
        with pytest.raises(TypeError, match='Cannot instantiate abstract integer type'):
            Integer()

        with pytest.raises(TypeError, match='Cannot instantiate abstract integer type'):
            Integer.from_wire(b'')

        for _type in (Int8, Int16, Int32, Int64, Int128):
            min_value = -_type._mean_
            max_value = +_type._mean_ - 1

            # Integer types support all the ways a python int can be instantiated

            assert _type(42) == 42
            assert _type('42') == 42
            assert _type('0x42', base=16) == 0x42
            assert _type() == 0

            assert _type.from_wire(BytesIO(bytes(16))) == 0

            value = _type(0)
            assert _type.from_wire(value.to_wire()) == value
            assert len(value.to_wire()) == value.wire_length() == _type._size_

            value = _type(min_value)
            assert _type.from_wire(value.to_wire()) == value
            assert len(value.to_wire()) == value.wire_length() == _type._size_

            value = _type(max_value)
            assert _type.from_wire(value.to_wire()) == value
            assert len(value.to_wire()) == value.wire_length() == _type._size_

            with pytest.raises(ValueError, match='Value is out of range for'):
                _type(min_value - 1)

            with pytest.raises(ValueError, match='Value is out of range for'):
                _type(max_value + 1)

            with pytest.raises(ValueError, match='Insufficient data in buffer to extract'):
                _type.from_wire(b'')

    def test_unsigned_types(self) -> None:
        with pytest.raises(TypeError, match='Cannot instantiate abstract unsigned integer type'):
            UnsignedInteger()

        with pytest.raises(TypeError, match='Cannot instantiate abstract unsigned integer type'):
            UnsignedInteger.from_wire(b'')

        for _type in (UInt8, UInt16, UInt32, UInt64, UInt128):
            min_value = 0
            max_value = 2**_type._bits_ - 1

            # Unsigned integer types support all the ways a python int can be instantiated

            assert _type(42) == 42
            assert _type('42') == 42
            assert _type('0x42', base=16) == 0x42
            assert _type() == 0

            assert _type.from_wire(BytesIO(bytes(16))) == 0

            value = _type(0)
            assert _type.from_wire(value.to_wire()) == value
            assert len(value.to_wire()) == value.wire_length() == _type._size_

            value = _type(min_value)
            assert _type.from_wire(value.to_wire()) == value
            assert len(value.to_wire()) == value.wire_length() == _type._size_

            value = _type(max_value)
            assert _type.from_wire(value.to_wire()) == value
            assert len(value.to_wire()) == value.wire_length() == _type._size_

            with pytest.raises(ValueError, match='Value is out of range for'):
                _type(min_value - 1)

            with pytest.raises(ValueError, match='Value is out of range for'):
                _type(max_value + 1)

            with pytest.raises(ValueError, match='Insufficient data in buffer to extract'):
                _type.from_wire(b'')

        no_length = NoLength()
        assert no_length == 0
        assert NoLength.from_wire(no_length.to_wire()) == no_length
        assert len(no_length.to_wire()) == no_length.wire_length() == NoLength._size_
        assert repr(no_length) == 'NoLength()'

    def test_enums(self) -> None:
        assert DestinationType.from_wire(BytesIO(DestinationType.node.to_wire())) is DestinationType.node
        assert DestinationType.from_wire(DestinationType.node.to_wire()) is DestinationType.node
        assert len(DestinationType.node.to_wire()) == DestinationType.node.wire_length() == DestinationType._size_
        assert len(ErrorCode.Forbidden.to_wire()) == ErrorCode.Forbidden.wire_length() == ErrorCode._size_

        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            DestinationType.from_wire(b'')

        with pytest.raises(ValueError, match=r'.*? is not a valid .*'):
            DestinationType.from_wire(b'\x99')

    def test_flags(self) -> None:
        assert ForwardingFlags.from_wire(BytesIO(ForwardingFlags.FORWARD_CRITICAL.to_wire())) is ForwardingFlags.FORWARD_CRITICAL
        assert ForwardingFlags.from_wire(ForwardingFlags.FORWARD_CRITICAL.to_wire()) is ForwardingFlags.FORWARD_CRITICAL
        assert len(ForwardingFlags.FORWARD_CRITICAL.to_wire()) == ForwardingFlags.FORWARD_CRITICAL.wire_length() == ForwardingFlags._size_

        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            ForwardingFlags.from_wire(b'')

        # Return an int for values that don't match any of the flag values
        value = ForwardingFlags.from_wire(b'\x99')
        assert value == 0x99
        assert isinstance(value, int)

        value = ForwardingFlags(0x99)
        assert value == 0x99
        assert isinstance(value, int)

    def test_literal_bytes(self) -> None:
        with pytest.raises(TypeError, match='Cannot instantiate abstract literal bytes type'):
            LiteralBytes()

        with pytest.raises(TypeError, match='Cannot instantiate abstract literal bytes type'):
            LiteralBytes.from_wire(b'')

        token = RELOToken()
        assert RELOToken.from_wire(BytesIO(token.to_wire())) == token
        assert RELOToken.from_wire(token.to_wire()) == token
        assert len(token.to_wire()) == token.wire_length()

        assert repr(token) == 'RELOToken()'

        with pytest.raises(ValueError, match='Insufficient data in buffer to extract'):
            RELOToken.from_wire(b'')

        with pytest.raises(ValueError, match='Value on wire does not match'):
            RELOToken.from_wire(token.to_wire()[::-1])

    def test_fixed_size_bytes(self) -> None:
        with pytest.raises(TypeError, match=r'Cannot instantiate fixed size bytes type .*? that does not define its size'):
            FixedSize()

        with pytest.raises(TypeError, match=r'Cannot instantiate fixed size bytes type .*? that does not define its size'):
            FixedSize.from_wire(b'')

        with pytest.raises(ValueError, match=r'.*? objects must have \d+ bytes'):
            NodeID(b'invalid')

        node_id = NodeID.generate()
        assert NodeID.from_wire(BytesIO(node_id.to_wire())) == node_id
        assert NodeID.from_wire(node_id.to_wire()) == node_id
        assert len(node_id.to_wire()) == node_id.wire_length() == NodeID._size_

        with pytest.raises(ValueError, match='Insufficient data in buffer to extract'):
            NodeID.from_wire(b'')

        null_node_id = NodeID(bytes(NodeID._size_))
        assert repr(null_node_id) == f'<NodeID: {NodeID._size_ * 2 * '0'}>'
        assert null_node_id.value == 0

        class Dummy(FixedSize, size=0):
            pass

        dummy = Dummy()
        assert repr(dummy) != repr(bytes(dummy))  # FixedSize instances have their own representation

    def test_opaque_bytes(self) -> None:
        with pytest.raises(TypeError, match='Cannot instantiate abstract variable length bytes type'):
            Opaque()

        with pytest.raises(TypeError, match='Cannot instantiate abstract variable length bytes type'):
            Opaque.from_wire(b'')

        for _type in (Opaque8, Opaque16, Opaque24, Opaque32):
            # Opaque byte types support all the ways a python bytes can be instantiated
            assert _type(b'test') == b'test'
            assert _type(bytearray(b'test')) == b'test'
            assert _type(list(b'test')) == b'test'
            assert _type('test', encoding='ascii') == b'test'
            assert _type(4) == bytes(4)
            assert _type() == b''

            value = _type(b'')
            assert _type.from_wire(BytesIO(value.to_wire())) == value
            assert _type.from_wire(value.to_wire()) == value
            assert len(value.to_wire()) == value.wire_length()

            value = _type(b'test')
            assert _type.from_wire(BytesIO(value.to_wire())) == value
            assert _type.from_wire(value.to_wire()) == value
            assert len(value.to_wire()) == value.wire_length()

            assert repr(value) != repr(bytes(value))  # Opaque instances have their own representation

            with pytest.raises(ValueError, match='Insufficient data in buffer to extract the data length for'):
                _type.from_wire(b'')

            with pytest.raises(ValueError, match='Insufficient data in buffer to extract the data for'):
                _type.from_wire(value.to_wire()[:-1])

            # Only test the types that have a reasonable max size
            if _type in {Opaque8, Opaque16, Opaque24}:
                with pytest.raises(ValueError, match=r'.*? objects can have at most \d+ bytes'):
                    _type(bytes(_type._maxsize_ + 1))

        class Opaque7(Opaque, maxsize=2**7 - 1):
            pass

        with pytest.raises(ValueError, match='Data length is too big for'):
            Opaque7.from_wire(b'\x80')

        # OpaqueID and ResourceID

        null_opaque_id = OpaqueID(bytes(5))
        assert repr(null_opaque_id) == f'<OpaqueID: {5 * 2 * '0'}>'
        assert null_opaque_id.value == 0

        resource_id = ResourceID.for_resource('user@example.org')
        assert len(resource_id) == NodeID._size_

    def test_list_types(self) -> None:
        # Test restrictions when defining list types

        with pytest.raises(TypeError, match='type can only be parameterized with a single base type or a type variable'):
            class TestList(List[UInt8 | UInt16]):
                pass

        class AbstractList[T: DataWireProtocol](List[T]):
            pass

        with pytest.raises(TypeError, match='Cannot instantiate abstract list'):
            AbstractList()
        with pytest.raises(TypeError, match='Cannot instantiate abstract list'):
            AbstractList.from_wire(b'')

        with pytest.raises(TypeError, match='Cannot instantiate abstract variable length list'):
            VariableLengthList()
        with pytest.raises(TypeError, match='Cannot instantiate abstract variable length list'):
            VariableLengthList.from_wire(b'')

        class NodeIDList(VariableLengthList[NodeID], maxsize=2**16 - 1):
            pass

        assert NodeIDList._type_ is NodeID

        node_list = NodeIDList([NodeID.generate() for _ in range(3)])

        assert NodeIDList.from_wire(BytesIO(node_list.to_wire())) == node_list
        assert NodeIDList.from_wire(node_list.to_wire()) == node_list
        assert len(node_list.to_wire()) == node_list.wire_length()

        with pytest.raises(ValueError, match='Insufficient data in buffer to extract list length for'):
            NodeIDList.from_wire(b'')

        with pytest.raises(ValueError, match='Insufficient data in buffer to extract list values for'):
            NodeIDList.from_wire(node_list.to_wire()[:-1])

        assert repr(node_list) != repr(list(node_list))  # By default List types have their own representation

        class PlainList(List[NodeID], custom_repr=False):
            pass

        assert repr(PlainList()) == '[]'  # Lists with custom_repr=False use the default list representation


destination_type: ContextVar[DestinationType] = ContextVar('destination_type')


class TestElements:

    def test_helpers(self) -> None:
        assert repr(_reprproxy(AddressType.ipv4_address)) == 'AddressType.ipv4_address'
        assert repr(_reprproxy(AddressType | UInt8)) == 'AddressType | UInt8'
        assert repr(_reprproxy(Opaque8)) == 'Opaque8'
        assert repr(_reprproxy('test')) == repr('test')

    def test_element(self) -> None:
        with pytest.raises(TypeError, match='When the element type is a union of types a composite adapter for the same types must be provided'):
            class Structure1(AnnotatedStructure):
                test: Element[ForwardingOptionType | UInt8] = Element(ForwardingOptionType | UInt8)  # pyright: ignore[reportArgumentType]

        with pytest.raises(TypeError, match='Either the element type must implement the DataWireProtocol or an adapter must be provided'):
            class Structure2(AnnotatedStructure):
                test: Element[int] = Element(int)

        with pytest.raises(TypeError, match='Cannot use abstract adapter'):
            class Structure3(AnnotatedStructure):
                test: Element[int] = Element(int, adapter=UnsignedIntegerAdapter)

        with pytest.raises(TypeError, match=r'Cannot assign the same .*? to two different names'):
            class Structure4(AnnotatedStructure):
                test: Element[int] = Element(int, adapter=UInt8Adapter)
                alias: Element[int] = test

        # The following errors need to be emulated as they won't happen under normal usage

        element = Element(bool)
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):
            element.__get__(Empty())
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):
            element.__set__(Empty(), True)  # noqa: FBT003
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):
            element.from_wire(Empty(), b'')

        class Test(AnnotatedStructure):
            elem: Element[NodeID] = Element(NodeID)

            @classmethod
            def new(cls) -> Self:
                # Bypass normal instance creation and return a bare-bone instance with no attributes set
                return super(Structure, cls).__new__(cls)

        assert isinstance(Test.elem, Element)  # Accessing the element on the class returns the element instance
        repr(Test.elem)  # Trigger element representation to test if it raises any exception

        struct = Test.new()
        with pytest.raises(AttributeError):
            _ = struct.elem
        with pytest.raises(AttributeError, match=r'Attribute .*? of .*? object cannot be deleted'):
            del struct.elem

        with pytest.raises(ValueError, match=r'Failed to read the .*? element from wire'):
            Test.from_wire(b'123')

    def test_dependent_element_spec(self) -> None:
        # Test DependentElementSpec restrictions

        with pytest.raises(TypeError, match='The length type cannot be an abstract UnsignedInteger type that does not define its size'):
            DependentElementSpec(type_map={}, fallback_type=None, length_type=UnsignedInteger)
        with pytest.raises(TypeError, match=r'A .*? that has no length prefix must have a non-empty type_map'):
            DependentElementSpec(type_map={}, fallback_type=None, length_type=NoLength)
        with pytest.raises(TypeError, match=r'A .*? that has no length prefix must have fallback_type=None'):
            DependentElementSpec[IPv4AddrPort | Opaque8, AddressType](type_map={AddressType.ipv4_address: IPv4AddrPort}, fallback_type=Opaque8, length_type=NoLength)
        with pytest.raises(TypeError, match=r'A .*? that has no length prefix must have check_length=False'):
            DependentElementSpec[IPv4AddrPort, AddressType](type_map={AddressType.ipv4_address: IPv4AddrPort}, fallback_type=None, length_type=NoLength, check_length=True)
        with pytest.raises(TypeError, match=r'A .*? with a length prefix and an empty type_map must specify a fallback type'):
            DependentElementSpec(type_map={}, fallback_type=None, length_type=UInt8)
        with pytest.raises(TypeError, match='The fallback type should either be None or an Opaque type which defines its size'):
            DependentElementSpec(type_map={}, fallback_type=UInt8, length_type=UInt8)
        with pytest.raises(TypeError, match='The fallback type should either be None or an Opaque type which defines its size'):
            DependentElementSpec(type_map={}, fallback_type=Opaque, length_type=UInt8)
        with pytest.raises(TypeError, match='The fallback type size length does not match the length type size'):
            DependentElementSpec(type_map={}, fallback_type=Opaque16, length_type=UInt8)

    def test_context_var_dependent_element(self) -> None:
        data_specification = DependentElementSpec[NodeID | ResourceID | OpaqueID, DestinationType](
            type_map={
                DestinationType.node: NodeID,
                DestinationType.resource: ResourceID,
                DestinationType.opaque_id_type: OpaqueID,
            },
            length_type=UInt8,
            check_length=True,
        )

        with pytest.raises(TypeError, match=r'Cannot assign the same .*? to two different names'):
            class BadStructure(AnnotatedStructure):
                data: ContextVarDependentElement[NodeID | ResourceID | OpaqueID, DestinationType] = ContextVarDependentElement(control_var=destination_type, specification=data_specification)
                alias = data

        # The following errors need to be emulated as they won't happen under normal usage

        element = ContextVarDependentElement(control_var=destination_type, specification=data_specification)
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):
            element.__get__(Empty())
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):
            element.__set__(Empty(), OpaqueID())
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):
            element.from_wire(Empty(), b'')

        element.name = 'element'
        with pytest.raises(AttributeError):
            element.__get__(Empty())
        with pytest.raises(ValueError, match=r'Control context variable .*? is not set'):
            element.__set__(Empty(), OpaqueID())
        with pytest.raises(ValueError, match=r'Control context variable .*? is not set'):
            element.from_wire(Empty(), b'')

        class Test(AnnotatedStructure):
            data: ContextVarDependentElement[NodeID | ResourceID | OpaqueID, DestinationType] = ContextVarDependentElement(control_var=destination_type, specification=data_specification)

            @classmethod
            def new(cls) -> Self:
                # Bypass normal instance creation and return a bare-bone instance with no attributes set
                return super(Structure, cls).__new__(cls)

        assert isinstance(Test.data, ContextVarDependentElement)  # Accessing the element on the class returns the element instance
        repr(Test.data)  # Trigger element representation to test if it raises any exception

        struct = Test.new()
        with pytest.raises(AttributeError):
            _ = struct.data
        with pytest.raises(AttributeError, match=r'Attribute .*? of .*? object cannot be deleted'):
            del struct.data

        with pytest.raises(ValueError, match=r'Control context variable .*? is not set'):
            struct.data = OpaqueID()
        with pytest.raises(ValueError, match=r'Control context variable .*? is not set'):
            Test.data.from_wire(struct, b'')

        with pytest.raises(ValueError, match='Cannot find associated type for dependent element'), ContextSpec({destination_type: DestinationType.invalid}):
            Test(data=NodeID.generate())

        with pytest.raises(ValueError, match='Cannot find associated type for dependent element'), ContextSpec({destination_type: DestinationType.invalid}):
            Test.from_wire(b'\x05\x04test')

        with ContextSpec({destination_type: DestinationType.opaque_id_type}):
            with pytest.raises(TypeError, match=r'The value for the .*? field should be of type .*'):
                Test(data=NodeID.generate())

            with pytest.raises(ValueError, match=r'Insufficient data in buffer to get the length for the .*? element'):
                Test.from_wire(b'')

            with pytest.raises(ValueError, match=r'Insufficient data in buffer to get the .*? element'):
                Test.from_wire(b'\x04')

            value = Test(data=OpaqueID(b'test'))
            assert Test.from_wire(value.to_wire()) == value
            assert len(value.to_wire()) == value.wire_length()

            # Syntetic test to check that a dependent element can parse from both bytes-like or BytesIO
            Test.data.from_wire(value, BytesIO(b'\x05\x04val1'))
            assert value.data == b'val1'
            Test.data.from_wire(value, b'\x05\x04val2')
            assert value.data == b'val2'

        with pytest.raises(LookupError):
            destination_type.get()

    def test_context_field_dependent_element(self) -> None:
        data_specification = DependentElementSpec[NodeID | ResourceID | OpaqueID, DestinationType](
            type_map={
                DestinationType.node: NodeID,
                DestinationType.resource: ResourceID,
                DestinationType.opaque_id_type: OpaqueID,
            },
            length_type=UInt8,
            check_length=True,
        )

        with pytest.raises(TypeError, match=r'Cannot assign the same .*? to two different names'):
            class BadStructure(AnnotatedStructure):
                type: Element[DestinationType] = Element(DestinationType)
                data: ContextFieldDependentElement[NodeID | ResourceID | OpaqueID, DestinationType, DestinationType] = ContextFieldDependentElement(
                    context_field=type, context_query=lambda x: x, specification=data_specification  # noqa: COM812
                )
                alias = data

        # The following errors need to be emulated as they won't happen under normal usage

        element = ContextFieldDependentElement(context_field=Element(DestinationType), context_query=lambda x: x, specification=data_specification)
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):
            element.__get__(Empty())
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):
            element.__set__(Empty(), OpaqueID())
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):
            element.from_wire(Empty(), b'')

        element.name = 'element'
        with pytest.raises(AttributeError):
            element.__get__(Empty())
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):  # this time is from the context field not having a name set
            element.__set__(Empty(), OpaqueID())
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):  # this time is from the context field not having a name set
            element.from_wire(Empty(), b'')

        class Test(AnnotatedStructure):
            type: Element[DestinationType] = Element(DestinationType)
            data: ContextFieldDependentElement[NodeID | ResourceID | OpaqueID, DestinationType, DestinationType] = ContextFieldDependentElement(
                context_field=type, context_query=lambda x: x, specification=data_specification  # noqa: COM812
            )

            @classmethod
            def new(cls) -> Self:
                # Bypass normal instance creation and return a bare-bone instance with no attributes set
                return super(Structure, cls).__new__(cls)

        assert isinstance(Test.data, ContextFieldDependentElement)  # Accessing the element on the class returns the element instance
        repr(Test.data)  # Trigger element representation to test if it raises any exception

        struct = Test.new()
        with pytest.raises(AttributeError):
            _ = struct.data
        with pytest.raises(AttributeError, match=r'Attribute .*? of .*? object cannot be deleted'):
            del struct.data

        with pytest.raises(ValueError, match=r'The context providing element .*? is not set'):
            struct.data = OpaqueID()
        with pytest.raises(ValueError, match=r'The context providing element .*? is not set'):
            Test.data.from_wire(struct, b'')

        with pytest.raises(TypeError, match=r'The value for the .*? field should be of type .*'):
            Test(type=DestinationType.resource, data=NodeID.generate())

        with pytest.raises(ValueError, match='Cannot find associated type for dependent element'):
            Test(type=DestinationType.invalid, data=NodeID.generate())

        with pytest.raises(ValueError, match='Cannot find associated type for dependent element'):
            Test.from_wire(b'\x00\x05\x04test')

        with pytest.raises(ValueError, match=r'Insufficient data in buffer to get the length for the .*? element'):
            Test.from_wire(b'\x01')

        with pytest.raises(ValueError, match=r'Insufficient data in buffer to get the .*? element'):
            Test.from_wire(b'\x03\x04')

        value = Test(type=DestinationType.opaque_id_type, data=OpaqueID(b'test'))
        assert Test.from_wire(value.to_wire()) == value
        assert len(value.to_wire()) == value.wire_length()

        # Syntetic test to check that a dependent element can parse from both bytes-like or BytesIO
        Test.data.from_wire(value, BytesIO(b'\x05\x04val1'))
        assert value.data == b'val1'
        Test.data.from_wire(value, b'\x05\x04val2')
        assert value.data == b'val2'

    def test_field_dependent_element(self) -> None:
        data_specification = DependentElementSpec[NodeID | ResourceID | OpaqueID, DestinationType](
            type_map={
                DestinationType.node: NodeID,
                DestinationType.resource: ResourceID,
                DestinationType.opaque_id_type: OpaqueID,
            },
            length_type=UInt8,
            check_length=True,
        )

        with pytest.raises(TypeError, match=r'Cannot assign the same .*? to two different names'):
            class BadStructure(AnnotatedStructure):
                type: Element[DestinationType] = Element(DestinationType)
                data: FieldDependentElement[NodeID | ResourceID | OpaqueID, DestinationType] = FieldDependentElement(control_field=type, specification=data_specification)
                alias = data

        # The following errors need to be emulated as they won't happen under normal usage

        element = FieldDependentElement(control_field=Element(DestinationType), specification=data_specification)
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):
            element.__get__(Empty())
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):
            element.__set__(Empty(), OpaqueID())
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):
            element.from_wire(Empty(), b'')

        element.name = 'element'
        with pytest.raises(AttributeError):
            element.__get__(Empty())
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):  # this time is from the control field not having a name set
            element.__set__(Empty(), OpaqueID())
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):  # this time is from the control field not having a name set
            element.from_wire(Empty(), b'')

        class Test(AnnotatedStructure):
            type: Element[DestinationType] = Element(DestinationType)
            data: FieldDependentElement[NodeID | ResourceID | OpaqueID, DestinationType] = FieldDependentElement(control_field=type, specification=data_specification)

            @classmethod
            def new(cls) -> Self:
                # Bypass normal instance creation and return a bare-bone instance with no attributes set
                return super(Structure, cls).__new__(cls)

        assert isinstance(Test.data, FieldDependentElement)  # Accessing the element on the class returns the element instance
        repr(Test.data)  # Trigger element representation to test if it raises any exception

        struct = Test.new()
        with pytest.raises(AttributeError):
            _ = struct.data
        with pytest.raises(AttributeError, match=r'Attribute .*? of .*? object cannot be deleted'):
            del struct.data

        with pytest.raises(ValueError, match=r'Control element .*? is not set'):
            struct.data = OpaqueID()
        with pytest.raises(ValueError, match=r'Control element .*? is not set'):
            Test.data.from_wire(struct, b'')

        with pytest.raises(TypeError, match=r'The value for the .*? field should be of type .*'):
            Test(type=DestinationType.resource, data=NodeID.generate())

        with pytest.raises(ValueError, match='Cannot find associated type for dependent element'):
            Test(type=DestinationType.invalid, data=NodeID.generate())

        with pytest.raises(ValueError, match='Cannot find associated type for dependent element'):
            Test.from_wire(b'\x00\x05\x04test')

        with pytest.raises(ValueError, match=r'Insufficient data in buffer to get the length for the .*? element'):
            Test.from_wire(b'\x01')

        with pytest.raises(ValueError, match=r'Insufficient data in buffer to get the .*? element'):
            Test.from_wire(b'\x03\x04')

        value = Test(type=DestinationType.opaque_id_type, data=OpaqueID(b'test'))
        assert Test.from_wire(value.to_wire()) == value
        assert len(value.to_wire()) == value.wire_length()

        # Syntetic test to check that a dependent element can parse from both bytes-like or BytesIO
        Test.data.from_wire(value, BytesIO(b'\x05\x04val1'))
        assert value.data == b'val1'
        Test.data.from_wire(value, b'\x05\x04val2')
        assert value.data == b'val2'

    def test_list_element(self) -> None:
        with pytest.raises(TypeError, match=r'Cannot assign the same .*? to two different names'):
            class BadStructure(AnnotatedStructure):
                test: ListElement[UInt8] = ListElement(UInt8)
                alias = test

        # The following errors need to be emulated as they won't happen under normal usage

        element = ListElement(UInt8)
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):
            element.__get__(Empty())
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):
            element.__set__(Empty(), [])
        with pytest.raises(TypeError, match=r'Cannot use .*? instance without calling __set_name__ on it'):
            element.from_wire(Empty(), b'')

        class Test(AnnotatedStructure):
            elem: ListElement[NodeID] = ListElement(NodeID)

            @classmethod
            def new(cls) -> Self:
                # Bypass normal instance creation and return a bare-bone instance with no attributes set
                return super(Structure, cls).__new__(cls)

        assert isinstance(Test.elem, ListElement)  # Accessing the element on the class returns the element instance
        repr(Test.elem)  # Trigger element representation to test if it raises any exception

        struct = Test.new()
        with pytest.raises(AttributeError):
            _ = struct.elem
        with pytest.raises(AttributeError, match=r'Attribute .*? of .*? object cannot be deleted'):
            del struct.elem

        with pytest.raises(ValueError, match=r'Failed to read the .*? element from wire: .*'):
            Test.from_wire(b'123')

    def test_structure(self) -> None:
        class ArrayEntry(AnnotatedStructure):
            index: Element[int] = Element(int, default=0, adapter=UInt16Adapter)
            value: Element[str] = Element(str, adapter=String8Adapter)

        with pytest.raises(TypeError, match='Missing a required keyword argument'):
            ArrayEntry()               # pyright: ignore[reportCallIssue]
        with pytest.raises(TypeError, match='Got an unexpected keyword argument'):
            ArrayEntry(nonexistent=0)  # pyright: ignore[reportCallIssue]

        entry = ArrayEntry(value='test')

        assert entry == ArrayEntry(index=0, value='test')
        assert entry != 0

        class Target(AnnotatedStructure):
            _value_specification = DependentElementSpec[NodeID | ResourceID | OpaqueID, DestinationType](
                type_map={
                    DestinationType.node: NodeID,
                    DestinationType.resource: ResourceID,
                    DestinationType.opaque_id_type: OpaqueID,
                },
                length_type=UInt8,
            )

            data: ContextVarDependentElement[NodeID | ResourceID | OpaqueID, DestinationType] = ContextVarDependentElement(control_var=destination_type, specification=_value_specification)

        def set_context(value: DestinationType) -> None:
            destination_type.set(value)

        class Parent(AnnotatedStructure):
            type: Element[DestinationType] = Element(DestinationType, context_setter=set_context)
            target: Element[Target] = Element(Target)

        opaque_id_destination = ContextSpec({destination_type: DestinationType.opaque_id_type})

        # ContextStructure is an alternative to using ContextSpec directly as a context manager

        with pytest.raises(TypeError, match=r'The value for the .*? field should be of type .*'):
            ContextStructure(Target, opaque_id_destination)(data=NodeID.generate())

        target = ContextStructure(Target, opaque_id_destination)(data=OpaqueID(b'test'))
        parent = Parent(type=DestinationType.opaque_id_type, target=target)

        with opaque_id_destination:
            # instantiation within a ContextSpec context manager should be the same as using ContextStructure
            assert parent == Parent(type=DestinationType.opaque_id_type, target=Target(data=OpaqueID(b'test')))

        assert Parent.from_wire(parent.to_wire()) == parent
        assert len(parent.to_wire()) == parent.wire_length()

        with pytest.raises(ValueError, match=r'Failed to read the .*? element from wire'):
            Parent.from_wire(parent.to_wire()[:-1])

        repr(parent)  # Trigger element representation to test if it raises any exception

        with pytest.raises(LookupError):
            destination_type.get()


class TestKinds:

    def test_kinds(self) -> None:
        with pytest.raises(ValueError, match='Kinds with access control set to NODE_MULTIPLE must define max_node_multiple'):
            Kind(id=999, name='Test kind', data_model=DataModel.SINGLE, access_control=AccessControl.NODE_MULTIPLE, max_count=1, max_size=100)

        with pytest.raises(ValueError, match='The Kind id is already used by another Kind'):
            Kind(id=1, name='Repeat 1', data_model=DataModel.DICTIONARY, access_control=AccessControl.USER_NODE_MATCH, max_count=1, max_size=100)

        with pytest.raises(ValueError, match='The Kind name is already used by another Kind'):
            Kind(id=111, name='SIP-REGISTRATION', data_model=DataModel.DICTIONARY, access_control=AccessControl.USER_NODE_MATCH, max_count=1, max_size=100)

        with pytest.raises(KeyError):
            Kind.lookup(999)

        with pytest.raises(KeyError):
            Kind.lookup('non-existent')


class TestComponents:

    def test_ip_addresses(self) -> None:
        address_port_4 = IPAddressPort.from_address('127.0.0.1', 1234)
        address_port_6 = IPAddressPort.from_address('::1', 1234)

        assert address_port_4.type is AddressType.ipv4_address
        assert address_port_6.type is AddressType.ipv6_address

        assert IPAddressPort.from_wire(address_port_4.to_wire()) == address_port_4
        assert IPAddressPort.from_wire(address_port_6.to_wire()) == address_port_6
        assert len(address_port_4.to_wire()) == address_port_4.wire_length()
        assert len(address_port_6.to_wire()) == address_port_6.wire_length()

    def test_ice_candidate(self) -> None:
        host_candidate = ICECandidate(
            addr_port=IPAddressPort.from_address('10.0.0.1', 50000),
            foundation='dc3096e968eb2e8301ac2e232c348c70',
            priority=2130706431,
            type=CandidateType.host,
            related_address=Empty(),
        )

        assert ICECandidate.from_candidate(host_candidate.to_candidate()) == host_candidate
        assert ICECandidate.from_wire(host_candidate.to_wire()) == host_candidate
        assert len(host_candidate.to_wire()) == host_candidate.wire_length()

        srflx_candidate = ICECandidate(
            addr_port=IPAddressPort.from_address('1.2.3.4', 50000),
            foundation='dc3096e968eb2e8301ac2e232c348c70',
            priority=1694498815,
            type=CandidateType.srflx,
            related_address=IPAddressPort.from_address('10.0.0.1', 50001),
        )

        assert ICECandidate.from_candidate(srflx_candidate.to_candidate()) == srflx_candidate
        assert ICECandidate.from_wire(srflx_candidate.to_wire()) == srflx_candidate
        assert len(srflx_candidate.to_wire()) == srflx_candidate.wire_length()

    def test_routing_elements(self) -> None:
        # Destination

        with pytest.raises(ValueError, match='Insufficient data in buffer to extract'):
            Destination.from_wire(BytesIO(b''))

        destination = Destination.for_data(NodeID.generate())
        assert not destination.is_compact_id
        assert destination.type is DestinationType.node
        assert Destination.from_wire(destination.to_wire()) == destination
        assert len(destination.to_wire()) == destination.wire_length()

        destination = Destination.for_data(ResourceID.for_resource('user@domain.com'))
        assert not destination.is_compact_id
        assert destination.type is DestinationType.resource
        assert Destination.from_wire(destination.to_wire()) == destination
        assert len(destination.to_wire()) == destination.wire_length()

        destination = Destination.for_data(OpaqueID(b'opaque'))
        assert not destination.is_compact_id
        assert destination.type is DestinationType.opaque_id_type
        assert Destination.from_wire(destination.to_wire()) == destination
        assert len(destination.to_wire()) == destination.wire_length()

        destination = Destination.for_data(OpaqueID(b'\xf0\x04'))
        assert destination.is_compact_id
        assert destination.type is DestinationType.opaque_id_type
        assert Destination.from_wire(destination.to_wire()) == destination
        assert len(destination.to_wire()) == destination.wire_length() == 2
        assert destination.to_wire() == destination.data

        destination = Destination.for_data(b'user@domain.com')
        assert not destination.is_compact_id
        assert destination.type is DestinationType.resource
        assert Destination.from_wire(destination.to_wire()) == destination
        assert len(destination.to_wire()) == destination.wire_length()

        destination = Destination.for_data('user@domain.com')
        assert not destination.is_compact_id
        assert destination.type is DestinationType.resource
        assert Destination.from_wire(destination.to_wire()) == destination
        assert len(destination.to_wire()) == destination.wire_length()

        repr(destination)  # Trigger element representation to test if it raises any exception

        # ForwardingOption

        option = ForwardingOption(type=UInt8(0x07), flags=ForwardingFlags.RESPONSE_COPY, option=Opaque16(b'data'))
        assert ForwardingOption.from_wire(option.to_wire()) == option
        assert len(option.to_wire()) == option.wire_length()

        # MessageExtension

        extension = MessageExtension(type=UInt16(0x10), critical=False, extension=Opaque32(b'data'))
        assert MessageExtension.from_wire(extension.to_wire()) == extension
        assert len(extension.to_wire()) == extension.wire_length()

    def test_storage_elements(self) -> None:
        with pytest.raises(ValueError, match=r'Could not read the length of .*? from wire'):
            StoredData.from_wire(b'')

        with pytest.raises(ValueError, match=r'Could not read the length of .*? from wire'):
            StoredMetaData.from_wire(b'')

        with pytest.raises(ValueError, match=r'Insufficient data in buffer to read .*'):
            StoreKindData.from_wire(UInt32(100).to_wire() + UInt64().to_wire() + UInt32(5).to_wire())

        with pytest.raises(ValueError, match=r'Insufficient data in buffer to read .*'):
            StoredDataSpecifier.from_wire(UInt32(100).to_wire() + UInt64().to_wire() + UInt16(5).to_wire())

        with pytest.raises(ValueError, match=r'Insufficient data in buffer to read .*'):
            FetchKindResponse.from_wire(UInt32(100).to_wire() + UInt64().to_wire() + UInt32(5).to_wire())

        with pytest.raises(ValueError, match=r'Insufficient data in buffer to read .*'):
            StatKindResponse.from_wire(UInt32(100).to_wire() + UInt64().to_wire() + UInt32(5).to_wire())

        with pytest.raises(UnknownKindError) as excinfo:
            StoredDataSpecifier(kind_id=100, specifier=Empty())
        assert excinfo.value.args == (100,)


class TestMessages:

    resource: ClassVar[ResourceID] = ResourceID.for_resource('user@domain.com')

    signature: ClassVar[Signature] = Signature(
        algorithm=SignatureAndHashAlgorithm(hash=HashAlgorithm.none, signature=SignatureAlgorithm.anonymous),
        identity=SignerIdentity(type=SignerIdentityType.none, identity=Empty()),
        value=b'',
    )

    ice_candidates: ClassVar[Sequence[ICECandidate]] = [
        ICECandidate(
            addr_port=IPAddressPort.from_address('10.0.0.1', 50000),
            foundation='dc3096e968eb2e8301ac2e232c348c70',
            priority=2130706431,
            type=CandidateType.host,
            related_address=Empty(),
        ),
        ICECandidate(
            addr_port=IPAddressPort.from_address('1.2.3.4', 50000),
            foundation='dc3096e968eb2e8301ac2e232c348c70',
            priority=1694498815,
            type=CandidateType.srflx,
            related_address=IPAddressPort.from_address('10.0.0.1', 50001),
        ),
    ]

    def test_message(self) -> None:
        with pytest.raises(TypeError, match='When inheriting a message type with a non-zero code, the new type code must be different from 0'):
            class WrongMessage1(ProbeRequest):
                pass

        with pytest.raises(TypeError, match=r'Message code .*? is already used by .*'):
            class WrongMessage2(ProbeRequest, code=0x01):
                pass

        with pytest.raises(TypeError, match='Unknown message code'):
            Message[0]

        assert Message[ProbeRequest._code_] is ProbeRequest

    def test_probe(self) -> None:
        request = ProbeRequest(requested_info=[ProbeInformationType.responsible_set, ProbeInformationType.num_resources, ProbeInformationType.uptime])
        assert ProbeRequest.from_wire(request.to_wire()) == request
        assert len(request.to_wire()) == request.wire_length()

        response = ProbeResponse(
            probe_info=[
                ProbeInformation(type=ProbeInformationType.responsible_set, value=UInt32(100_000_000)),
                ProbeInformation(type=ProbeInformationType.num_resources, value=UInt32(100)),
                ProbeInformation(type=ProbeInformationType.uptime, value=UInt32(1000)),
            ],
        )
        assert ProbeResponse.from_wire(response.to_wire()) == response
        assert len(response.to_wire()) == response.wire_length()

        # Test that ProbeInformation of unknown type decodes to a generic opaque value
        assert ProbeInformation.from_wire(b'\x99\x04\x00\x00\x00\x00') == ProbeInformation(type=UInt8(0x99), value=Opaque8(bytes(4)))

    def test_attach(self) -> None:
        request = AttachRequest(username='test', password='pass', candidates=self.ice_candidates)
        assert AttachRequest.from_wire(request.to_wire()) == request
        assert len(request.to_wire()) == request.wire_length()

        response = AttachResponse(username='test', password='pass', candidates=self.ice_candidates)
        assert AttachResponse.from_wire(response.to_wire()) == response
        assert len(response.to_wire()) == response.wire_length()

    def test_store(self) -> None:
        with ContextSpec({data_model: SIPRegistration.data_model}):
            data = StoredData(storage_time=0, lifetime=3600, value=DictionaryEntry(key=self.resource, value=DataValue(exists=True, value=NodeID.generate())), signature=self.signature)
        sip_data = StoreKindData(kind_id=SIPRegistration.id, generation_counter=0, values=[data])

        with ContextSpec({data_model: CertificateByUser.data_model}):
            data = StoredData(storage_time=0, lifetime=3600, value=ArrayEntry(index=0, value=DataValue(exists=True, value=b'certificate')), signature=self.signature)
        user_cert_data = StoreKindData(kind_id=CertificateByUser.id, generation_counter=0, values=[data])

        request = StoreRequest(resource=self.resource, replica_number=0, kind_data=[sip_data, user_cert_data])
        wire_data = request.to_wire()
        assert StoreRequest.from_wire(wire_data) == request
        assert len(wire_data) == request.wire_length()

        # Simulate unknown kinds
        wire_data_rw = bytearray(wire_data)
        offset = request.resource.wire_length() + UInt8._size_ + UInt32._size_  # size(resource) + size(replica_number) + sizelen([kind_data])
        wire_data_rw[offset + 3] = 100
        values_len_offset = offset + UInt32._size_ + UInt64._size_              # offset + size(kind_id) + size(generation_counter)
        values_len = UInt32.from_wire(wire_data_rw[values_len_offset:])
        offset = values_len_offset + UInt32._size_ + values_len                 # values_len_offset + sizelen([values]) + len([values])
        wire_data_rw[offset + 3] = 101
        with pytest.raises(UnknownKindError) as excinfo:
            StoreRequest.from_wire(wire_data_rw)
        assert excinfo.value.args == (100, 101)

        kind_responses = [
            StoreKindResponse(kind_id=SIPRegistration.id, generation_counter=0, replicas=[NodeID.generate(), NodeID.generate()]),
            StoreKindResponse(kind_id=CertificateByUser.id, generation_counter=0, replicas=[NodeID.generate(), NodeID.generate()]),
        ]
        response = StoreResponse(kind_responses=kind_responses)
        wire_data = response.to_wire()
        assert StoreResponse.from_wire(wire_data) == response
        assert len(wire_data) == response.wire_length()

        with pytest.raises(LookupError):
            data_model.get()

    def test_fetch(self) -> None:
        request = FetchRequest(
            resource=self.resource,
            specifiers=[
                StoredDataSpecifier(kind_id=SIPRegistration.id, specifier=DictionaryKeyList()),
                StoredDataSpecifier(kind_id=CertificateByUser.id, specifier=ArrayRangeList()),
            ],
        )
        wire_data = request.to_wire()
        assert FetchRequest.from_wire(wire_data) == request
        assert len(wire_data) == request.wire_length()

        # Simulate unknown kinds
        wire_data_rw = bytearray(wire_data)
        offset = request.resource.wire_length() + UInt16._size_  # size(resource) + sizelen([specifiers])
        wire_data_rw[offset + 3] = 100
        length_offset = offset + UInt32._size_ + UInt64._size_   # offset + size(kind_id) + size(generation)
        length = UInt16.from_wire(wire_data_rw[length_offset:])
        offset = length_offset + UInt16._size_ + length          # values_len_offset + size(length) + len(specifier)
        wire_data_rw[offset + 3] = 101
        with pytest.raises(UnknownKindError) as excinfo:
            FetchRequest.from_wire(wire_data_rw)
        assert excinfo.value.args == (100, 101)

        # Response

        with ContextSpec({data_model: SIPRegistration.data_model}):
            sip_data = StoredData(storage_time=0, lifetime=3600, value=DictionaryEntry(key=self.resource, value=DataValue(exists=True, value=NodeID.generate())), signature=self.signature)

        with ContextSpec({data_model: CertificateByUser.data_model}):
            cert_data = StoredData(storage_time=0, lifetime=3600, value=ArrayEntry(index=0, value=DataValue(exists=True, value=b'certificate')), signature=self.signature)

        response = FetchResponse(
            kind_responses=[
                FetchKindResponse(kind_id=SIPRegistration.id, generation=0, values=[sip_data]),
                FetchKindResponse(kind_id=CertificateByUser.id, generation=0, values=[cert_data]),
            ],
        )
        wire_data = response.to_wire()
        assert FetchResponse.from_wire(wire_data) == response
        assert len(wire_data) == response.wire_length()

        # Simulate unknown kinds
        wire_data_rw = bytearray(wire_data)
        offset = UInt32._size_                                   # sizelen([kind_responses])
        wire_data_rw[offset + 3] = 100
        length_offset = offset + UInt32._size_ + UInt64._size_   # offset + size(kind_id) + size(generation)
        length = UInt32.from_wire(wire_data_rw[length_offset:])
        offset = length_offset + UInt32._size_ + length          # values_len_offset + sizelen([values]) + len(values)
        wire_data_rw[offset + 3] = 101
        with pytest.raises(UnknownKindError) as excinfo:
            FetchResponse.from_wire(wire_data_rw)
        assert excinfo.value.args == (100, 101)

        with pytest.raises(LookupError):
            data_model.get()

    def test_find(self) -> None:
        request = FindRequest(resource=self.resource, kinds=[UInt32(SIPRegistration.id), UInt32(0x99)])
        wire_data = request.to_wire()
        assert FindRequest.from_wire(wire_data) == request
        assert len(wire_data) == request.wire_length()

        response = FindResponse(
            results=[FindKindData(kind_id=SIPRegistration.id, closest=ResourceID.for_resource('test')), FindKindData(kind_id=CertificateByUser.id, closest=ResourceID(bytes(NodeID._size_)))]  # noqa: COM812
        )
        wire_data = response.to_wire()
        assert FindResponse.from_wire(wire_data) == response
        assert len(wire_data) == response.wire_length()

    def test_join(self) -> None:
        request = JoinRequest(node_id=NodeID.generate())
        assert JoinRequest.from_wire(request.to_wire()) == request
        assert len(request.to_wire()) == request.wire_length()

        response = JoinResponse()
        assert JoinResponse.from_wire(response.to_wire()) == response
        assert len(response.to_wire()) == response.wire_length()

    def test_leave(self) -> None:
        leave_data = ChordLeaveData(type=ChordLeaveType.from_successor, node_list=[NodeID.generate(), NodeID.generate()])

        request = LeaveRequest(node_id=NodeID.generate(), overlay_data=leave_data.to_wire())
        assert LeaveRequest.from_wire(request.to_wire()) == request
        assert len(request.to_wire()) == request.wire_length()

        assert ChordLeaveData.from_wire(request.overlay_data) == leave_data
        assert len(request.overlay_data) == leave_data.wire_length()

        response = LeaveResponse()
        assert LeaveResponse.from_wire(response.to_wire()) == response
        assert len(response.to_wire()) == response.wire_length()

    def test_update(self) -> None:
        request1 = UpdateRequest(uptime=1000, type=ChordUpdateType.peer_ready, data=Empty())
        request2 = UpdateRequest(uptime=1000, type=ChordUpdateType.neighbors, data=NodeNeighbors(predecessors=[NodeID.generate()], successors=[NodeID.generate()]))
        request3 = UpdateRequest(uptime=1000, type=ChordUpdateType.full, data=NodeNeighborsFingers(predecessors=[NodeID.generate()], successors=[NodeID.generate()], fingers=[NodeID.generate()]))

        for request in (request1, request2, request3):
            wire_data = request.to_wire()
            assert UpdateRequest.from_wire(wire_data) == request
            assert len(wire_data) == request.wire_length()

        response = UpdateResponse()
        assert UpdateResponse.from_wire(response.to_wire()) == response
        assert len(response.to_wire()) == response.wire_length()

    def test_route_query(self) -> None:
        request = RouteQueryRequest(send_update=False, destination=Destination.for_data(NodeID.generate()))
        assert RouteQueryRequest.from_wire(request.to_wire()) == request
        assert len(request.to_wire()) == request.wire_length()

        response = RouteQueryResponse(next_peer=NodeID.generate())
        assert RouteQueryResponse.from_wire(response.to_wire()) == response
        assert len(response.to_wire()) == response.wire_length()

    def test_ping(self) -> None:
        request = PingRequest()
        assert PingRequest.from_wire(request.to_wire()) == request
        assert len(request.to_wire()) == request.wire_length()

        response = PingResponse(id=1, time=1000)
        assert PingResponse.from_wire(response.to_wire()) == response
        assert len(response.to_wire()) == response.wire_length()

    def test_stat(self) -> None:
        request = StatRequest(
            resource=self.resource,
            specifiers=[
                StoredDataSpecifier(kind_id=SIPRegistration.id, specifier=DictionaryKeyList()),
                StoredDataSpecifier(kind_id=CertificateByUser.id, specifier=ArrayRangeList()),
            ],
        )
        wire_data = request.to_wire()
        assert StatRequest.from_wire(wire_data) == request
        assert len(wire_data) == request.wire_length()

        # Simulate unknown kinds
        wire_data_rw = bytearray(wire_data)
        offset = request.resource.wire_length() + UInt16._size_  # size(resource) + sizelen([specifiers])
        wire_data_rw[offset + 3] = 100
        length_offset = offset + UInt32._size_ + UInt64._size_   # offset + size(kind_id) + size(generation)
        length = UInt16.from_wire(wire_data_rw[length_offset:])
        offset = length_offset + UInt16._size_ + length          # values_len_offset + size(length) + len(specifier)
        wire_data_rw[offset + 3] = 101

        with pytest.raises(UnknownKindError) as excinfo:
            StatRequest.from_wire(wire_data_rw)
        assert excinfo.value.args == (100, 101)

        # Response

        with ContextSpec({data_model: SIPRegistration.data_model}):
            sip_metadata = StoredMetaData(
                storage_time=0, lifetime=3600, metadata=DictionaryEntryMeta(key=self.resource, value=DataValueMeta(exists=True, value_length=16, hash_algorithm=HashAlgorithm.none, hash_value=b''))  # noqa: COM812
            )

        with ContextSpec({data_model: CertificateByUser.data_model}):
            cert_metadata = StoredMetaData(
                storage_time=0, lifetime=3600, metadata=ArrayEntryMeta(index=0, value=DataValueMeta(exists=True, value_length=11, hash_algorithm=HashAlgorithm.none, hash_value=b''))  # noqa: COM812
            )

        response = StatResponse(
            kind_responses=[
                StatKindResponse(kind_id=SIPRegistration.id, generation=0, values=[sip_metadata]),
                StatKindResponse(kind_id=CertificateByUser.id, generation=0, values=[cert_metadata]),
            ],
        )
        wire_data = response.to_wire()
        assert StatResponse.from_wire(wire_data) == response
        assert len(wire_data) == response.wire_length()

        # Simulate unknown kinds
        wire_data_rw = bytearray(wire_data)
        offset = UInt32._size_                                   # sizelen([kind_responses])
        wire_data_rw[offset + 3] = 100
        length_offset = offset + UInt32._size_ + UInt64._size_   # offset + size(kind_id) + size(generation)
        length = UInt32.from_wire(wire_data_rw[length_offset:])
        offset = length_offset + UInt32._size_ + length          # values_len_offset + sizelen([values]) + len(values)
        wire_data_rw[offset + 3] = 101

        with pytest.raises(UnknownKindError) as excinfo:
            StatResponse.from_wire(wire_data_rw)
        assert excinfo.value.args == (100, 101)

        with pytest.raises(LookupError):
            data_model.get()

    def test_app_attach(self) -> None:
        request = AppAttachRequest(username='test', password='pass', application=5060, candidates=self.ice_candidates)
        assert AppAttachRequest.from_wire(request.to_wire()) == request
        assert len(request.to_wire()) == request.wire_length()

        response = AppAttachResponse(username='test', password='pass', application=5060, candidates=self.ice_candidates)
        assert AppAttachResponse.from_wire(response.to_wire()) == response
        assert len(response.to_wire()) == response.wire_length()

    def test_config_update(self) -> None:
        request = ConfigUpdateRequest(type=ConfigUpdateType.config, data=Opaque24(b'<xml/>'))
        assert ConfigUpdateRequest.from_wire(request.to_wire()) == request
        assert len(request.to_wire()) == request.wire_length()

        request = ConfigUpdateRequest(type=ConfigUpdateType.kind, data=KindDescriptionList([Opaque16(b'<xml/>')]))
        assert ConfigUpdateRequest.from_wire(request.to_wire()) == request
        assert len(request.to_wire()) == request.wire_length()

        response = ConfigUpdateResponse()
        assert ConfigUpdateResponse.from_wire(response.to_wire()) == response
        assert len(response.to_wire()) == response.wire_length()

    def test_error_response(self) -> None:
        response = ErrorResponse(code=ErrorCode.Forbidden, info=b'Not authorized to read data')
        assert ErrorResponse.from_wire(response.to_wire()) == response
        assert len(response.to_wire()) == response.wire_length()


class TestBlocks:

    configuration = Configuration(instance_name='test.com', sequence=17)  # pyright: ignore[reportCallIssue]

    def test_forwarding_header(self) -> None:
        header = ForwardingHeader.new(
            configuration=self.configuration,
            fragment=0xC000_0000,
            length=1000,
            transaction_id=new_transaction_id(),
            via_list=[],
            destination_list=[Destination.for_data('user@example.org')],
            options=[],
        )
        assert ForwardingHeader.from_wire(header.to_wire()) == header
        assert len(header.to_wire()) == header.wire_length()

        with pytest.raises(ValueError, match='Insufficient data in buffer to extract'):
            ForwardingHeader.from_wire(header.to_wire()[:-1])

        with pytest.raises(ValueError, match='Insufficient data in buffer to extract'):
            ForwardingHeader.from_wire(b'')

        with pytest.raises(ValueError, match=r'The buffer does not contain valid .*? data'):
            ForwardingHeader.from_wire(bytes(ForwardingHeader._preamble_.size))

    def test_message_contents(self) -> None:
        with pytest.raises(TypeError, match='Cannot use abstract message type'):
            MessageContents.for_message(Message())

        message = JoinRequest(node_id=NodeID.generate())
        content = MessageContents.for_message(message)
        wire_data = content.to_wire()
        read_content = MessageContents.from_wire(wire_data)
        read_message = Message[read_content.code].from_wire(read_content.body)
        assert len(wire_data) == content.wire_length()
        assert read_content == content
        assert read_message == message

    def test_signature_block(self) -> None:
        certificate_list = [GenericCertificate(type=CertificateType.X509, certificate=b'certificate')]
        signer_identity = SignerIdentity(type=SignerIdentityType.cert_hash, identity=CertificateHash(hash_algorithm=HashAlgorithm.sha256, certificate_hash=b'certificate-hash'))
        signature = Signature(algorithm=SignatureAndHashAlgorithm(hash=HashAlgorithm.sha256, signature=SignatureAlgorithm.rsa), identity=signer_identity, value=b'signature')
        security_block = SecurityBlock(certificates=certificate_list, signature=signature)
        assert SecurityBlock.from_wire(security_block.to_wire()) == security_block
        assert len(security_block.to_wire()) == security_block.wire_length()
        repr(signer_identity)  # Trigger element representation to test if it raises any exception

    def test_framed_messages(self) -> None:
        message = FramedMessage(type=FramedMessageType.ack, frame=AckFrame(sequence=1, received=1))
        assert FramedMessage.from_wire(message.to_wire()) == message
        assert len(message.to_wire()) == message.wire_length()

        message = FramedMessage(type=FramedMessageType.data, frame=DataFrame(sequence=1, message=b'test'))
        assert FramedMessage.from_wire(message.to_wire()) == message
        assert len(message.to_wire()) == message.wire_length()
