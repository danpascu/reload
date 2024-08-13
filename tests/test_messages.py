# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import pytest
from reload.configuration import Configuration
from reload.messages import (
    CertificateHash,
    Destination,
    Empty,
    ErrorResponse,
    ForwardingHeader,
    ForwardingOption,
    GenericCertificate,
    JoinRequest,
    Message,
    MessageContents,
    MessageExtension,
    SecurityBlock,
    Signature,
    SignatureAndHashAlgorithm,
    SignerIdentity,
)
from reload.messages.datamodel import (
    CertificateType,
    DataWireProtocol,
    DestinationType,
    Enum,
    ErrorCode,
    FixedSize,
    Flag,
    ForwardingFlags,
    HashAlgorithm,
    Integer,
    List,
    LiteralBytes,
    NodeID,
    Opaque,
    Opaque8,
    Opaque16,
    Opaque24,
    Opaque32,
    OpaqueID,
    ResourceID,
    SignatureAlgorithm,
    SignerIdentityType,
    UnsignedInteger,
    VariableLengthList,
    uint8,
    uint16,
    uint32,
    uint64,
    uint128,
)
from reload.messages.elements import AnnotatedStructure, Structure


class TestTypes:

    def test_types(self) -> None:
        assert issubclass(Integer, DataWireProtocol)
        assert issubclass(UnsignedInteger, DataWireProtocol)
        assert issubclass(Enum, DataWireProtocol)
        assert issubclass(Flag, DataWireProtocol)
        assert issubclass(Opaque, DataWireProtocol)
        assert issubclass(LiteralBytes, DataWireProtocol)
        assert issubclass(FixedSize, DataWireProtocol)
        assert issubclass(List, DataWireProtocol)
        assert issubclass(VariableLengthList, DataWireProtocol)
        assert issubclass(Structure, DataWireProtocol)
        assert issubclass(AnnotatedStructure, DataWireProtocol)
        assert issubclass(Destination, DataWireProtocol)
        assert issubclass(ForwardingOption, DataWireProtocol)
        assert issubclass(MessageExtension, DataWireProtocol)
        assert issubclass(SignerIdentity, DataWireProtocol)
        assert issubclass(ForwardingHeader, DataWireProtocol)


class TestUnsigned:

    def test_uint_creation(self) -> None:
        # abstract base class cannot be instantiated because it doesn't define its size in bits
        with pytest.raises(TypeError, match=r'Cannot instantiate abstract unsigned integer type .*'):
            UnsignedInteger()
        # unsigned integers support all the ways a python int can be instantiated
        assert uint8(42) == 42
        assert uint8('42') == 42
        assert uint8('0x42', base=16) == 0x42
        assert uint8() == 0
        # value must be >= 0
        with pytest.raises(ValueError, match=r'Value is out of range for unsigned .*'):
            uint8(-1)
        # value must be representable with the number of bits of the unsigned type
        with pytest.raises(ValueError, match=r'Value is out of range for unsigned .*'):
            uint8(2**8)
        with pytest.raises(ValueError, match=r'Value is out of range for unsigned .*'):
            uint16(2**16)
        with pytest.raises(ValueError, match=r'Value is out of range for unsigned .*'):
            uint32(2**32)
        with pytest.raises(ValueError, match=r'Value is out of range for unsigned .*'):
            uint64(2**64)
        with pytest.raises(ValueError, match=r'Value is out of range for unsigned .*'):
            uint128(2**128)

    def test_uint_encoding(self) -> None:
        assert uint8(42).to_wire() == b'*'
        assert uint16(12345).to_wire() == b'09'
        assert uint32(2 ** 32 - 2).to_wire() == b'\xff\xff\xff\xfe'
        assert uint64(2 ** 64 - 1).to_wire() == 8 * b'\xff'
        assert uint128(0).to_wire() == 16 * b'\x00'

    def test_uint_wire_length(self) -> None:
        assert uint8(42).wire_length() == 1
        assert uint16(12345).wire_length() == 2
        assert uint32(2).wire_length() == 4
        assert uint64(3).wire_length() == 8
        assert uint128(0).wire_length() == 16

    def test_uint_decoding(self) -> None:
        # insufficient data in buffer to extract uint from
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            uint8.from_wire(b'')
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            uint16.from_wire(b'\x00')
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            uint32.from_wire(b'\x00\x00\x00')
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            uint64.from_wire(b'\x00\x00\x00')
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            uint128.from_wire(b'\x00\x00\x00\x00')
        assert uint8.from_wire(b'*') == 42
        assert uint16.from_wire(b'\x124') == 4660
        assert uint32.from_wire(b'\x00\x00\x01\x02') == 258
        assert uint64.from_wire(uint64(12345).to_wire()) == 12345
        assert uint128.from_wire(uint128(42).to_wire()) == 42
        # excess bytes in buffer are ignored
        assert uint16.from_wire(b'\x01\x02\x03\x04') == 0x102


class TestEnum:

    def test_enum(self) -> None:
        assert DestinationType(1) is DestinationType.node
        assert DestinationType.node.to_wire() == b'\x01'
        assert DestinationType.node.wire_length() == 1
        assert ErrorCode.DataTooLarge.wire_length() == 2
        # encode to wire and back
        assert DestinationType.from_wire(DestinationType.node.to_wire()) is DestinationType.node
        # not enough data in buffer to extract Enum from
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            DestinationType.from_wire(b'')
        # value on wire doesn't match with Enum values
        with pytest.raises(ValueError, match=r'.*? is not a valid .*'):
            DestinationType.from_wire(b'\x99')


class TestFlag:

    def test_flag(self) -> None:
        flag = ForwardingFlags.RESPONSE_COPY
        assert ForwardingFlags(4) is flag
        assert flag.to_wire() == b'\x04'
        assert flag.wire_length() == 1
        assert ForwardingFlags.from_wire(flag.to_wire()) is flag
        # not enough data in buffer to extract Flag from
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            ForwardingFlags.from_wire(b'')
        # value on wire doesn't match with the Flag values -> converted to int
        assert isinstance(ForwardingFlags.from_wire(b'\x99'), int)


class TestOpaque:
    def test_opaque_creation(self) -> None:
        # abstract base class cannot be instantiated because it doesn't define its max size
        with pytest.raises(TypeError, match=r'Cannot instantiate abstract variable length bytes type .*'):
            Opaque()
        # opaque byte strings support all the ways a python bytes object can be instantiated
        assert Opaque8([1, 2, 3]) == b'\x01\x02\x03'
        assert Opaque8(b'abc') == b'abc'
        assert Opaque8('test', encoding='ascii') == b'test'
        assert Opaque8(3) == b'\x00\x00\x00'
        assert Opaque8() == b''
        # the size must be at most the max size defined by the type
        with pytest.raises(ValueError, match=r'.*? objects can have at most \d+ bytes'):
            Opaque8(2**8)
        with pytest.raises(ValueError, match=r'.*? objects can have at most \d+ bytes'):
            Opaque16(2**16)
        with pytest.raises(ValueError, match=r'.*? objects can have at most \d+ bytes'):
            Opaque24(2**24)

    def test_opaque_encoding(self) -> None:
        assert Opaque8().to_wire() == b'\x00'
        assert Opaque16(4).to_wire() == b'\x00\x04\x00\x00\x00\x00'
        assert Opaque24(b'foo').to_wire() == b'\x00\x00\x03foo'
        assert Opaque32(b'testing').to_wire() == b'\x00\x00\x00\x07testing'

    def test_opaque_wire_length(self) -> None:
        assert Opaque8().wire_length() == 1 + 0
        assert Opaque16(4).wire_length() == 2 + 4
        assert Opaque24(b'foo').wire_length() == 3 + 3
        assert Opaque32(b'testing').wire_length() == 4 + 7

    def test_opaque_decoding(self) -> None:
        assert Opaque8.from_wire(b'\x03foo') == b'foo'
        assert Opaque16.from_wire(b'\x00\x04test') == b'test'
        assert Opaque32.from_wire(b'\x00\x00\x00\x04test+padding') == b'test'
        # not enough data in buffer to extract opaque byte string from
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract the data length for .*'):
            Opaque8.from_wire(b'')
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract the data for .*'):
            Opaque8.from_wire(b'\x23abc')

    def test_ids(self) -> None:
        node_id = NodeID.generate()
        opaque_id = OpaqueID(b'test')
        resource_id = ResourceID.for_resource('user@example.com')
        assert node_id.wire_length() == NodeID._size_
        assert opaque_id.wire_length() == len(opaque_id) + 1
        assert resource_id.wire_length() == len(resource_id) + 1
        assert len(resource_id) == len(node_id)
        assert node_id.to_wire() == node_id
        assert NodeID.from_wire(node_id.to_wire()) == node_id
        assert OpaqueID.from_wire(opaque_id.to_wire()) == opaque_id
        assert ResourceID.from_wire(resource_id.to_wire()) == resource_id
        # not enough data in buffer to extract NodeID from
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            NodeID.from_wire(b'short')


class DestinationList(List[Destination]):
    pass


class ForwardingOptionList(List[ForwardingOption]):
    pass


class MessageExtensionList(VariableLengthList[MessageExtension], maxsize=2**32 - 1):
    pass


class NodeIDList(VariableLengthList[NodeID], maxsize=2**16 - 1):
    pass


class TestCompound:

    def test_list_types(self) -> None:
        # lists that do not encode their size on the wire
        destination1 = Destination(type=DestinationType.node, data=NodeID.generate())
        destination2 = Destination(type=DestinationType.node, data=NodeID.generate())
        target = Destination(type=DestinationType.resource, data=ResourceID.for_resource('user@example.org'))
        destination_list = DestinationList([destination1, destination2, target])
        assert destination_list.to_wire() == b''.join(item.to_wire() for item in destination_list)
        assert destination_list.wire_length() == sum(item.wire_length() for item in destination_list)
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            DestinationList.from_wire(destination_list.to_wire()[:-5])
        forwarding_options = ForwardingOptionList()
        assert forwarding_options.to_wire() == b''
        assert forwarding_options.wire_length() == 0
        # variable length lists
        message_extensions = MessageExtensionList()
        assert message_extensions.to_wire() == bytes(4)
        assert message_extensions.wire_length() == 4
        message_extensions.append(MessageExtension(type=uint16(9), critical=True, extension=Opaque32(b'test')))
        assert MessageExtensionList.from_wire(message_extensions.to_wire()) == message_extensions
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            MessageExtensionList.from_wire(message_extensions.to_wire()[:-1])
        node_list = NodeIDList([NodeID.generate(), NodeID.generate(), NodeID.generate()])
        assert node_list.to_wire() == b'\x000' + b''.join(node for node in node_list)
        assert node_list.wire_length() == len(node_list) * NodeID._size_ + NodeIDList._sizelen_
        assert NodeIDList.from_wire(node_list.to_wire()) == node_list
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            NodeIDList.from_wire(node_list.to_wire()[:-5])

    def test_destination(self) -> None:
        node_id = NodeID.generate()
        destination = Destination(type=DestinationType.node, data=node_id)
        assert destination.wire_length() == len(node_id) + DestinationType._size_ + uint8._size_
        assert destination.to_wire() == b'\x01\x10' + node_id
        assert Destination.from_wire(destination.to_wire()) == destination
        resource_id = ResourceID.for_resource('user@example.org')
        destination = Destination(type=DestinationType.resource, data=resource_id)
        assert destination.wire_length() == len(resource_id) + uint8._size_ + DestinationType._size_ + uint8._size_
        assert destination.to_wire() == b'\x02\x11\x10' + resource_id
        assert Destination.from_wire(destination.to_wire()) == destination
        opaque_id = OpaqueID(b'test')
        destination = Destination(type=DestinationType.opaque_id_type, data=opaque_id)
        assert destination.wire_length() == len(opaque_id) + uint8._size_ + DestinationType._size_ + uint8._size_
        assert destination.to_wire() == b'\x03\x05\x04' + opaque_id
        assert Destination.from_wire(destination.to_wire()) == destination
        opaque_id = OpaqueID(b'\xf7\x25')
        destination = Destination(type=DestinationType.opaque_id_type, data=opaque_id)
        assert destination.wire_length() == 2
        assert destination.to_wire() == opaque_id
        assert Destination.from_wire(destination.to_wire()) == destination
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            Destination.from_wire(b'\x01\x10short')
        with pytest.raises(ValueError, match=r'.*? is not a valid .*'):
            Destination.from_wire(b'\x79\xffinvalid-type.....')

    def test_forwarding_option(self) -> None:
        option = ForwardingOption(type=uint8(7), flags=ForwardingFlags.FORWARD_CRITICAL, option=Opaque16(b'test'))
        assert ForwardingOption.from_wire(b'\x07\x01\x00\x04test') == option
        assert ForwardingOption.from_wire(option.to_wire()) == option
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            ForwardingOption.from_wire(b'\xf0\xff')

    def test_message_extension(self) -> None:
        extension = MessageExtension(type=uint16(9), critical=True, extension=Opaque32(b'test'))
        assert MessageExtension.from_wire(b'\x00\x09\x01\x00\x00\x00\x04test') == extension
        assert MessageExtension.from_wire(extension.to_wire()) == extension
        with pytest.raises(ValueError, match=r'Insufficient data in buffer to extract .*'):
            MessageExtension.from_wire(b'\xf0\xff')

    def test_error_response(self) -> None:
        error_response = ErrorResponse(code=ErrorCode.Forbidden)
        assert error_response.wire_length() == ErrorCode._size_ + Opaque16._sizelen_
        assert error_response.to_wire() == b'\x00\x02\x00\x00'
        error_response.info = b'NodeID mismatch'
        assert error_response.wire_length() == ErrorCode._size_ + Opaque16._sizelen_ + len(error_response.info)
        assert error_response.to_wire() == b'\x00\x02\x00\x0fNodeID mismatch'
        assert ErrorResponse.from_wire(error_response.to_wire()) == error_response

    def test_empty_structure(self) -> None:
        empty = Empty()
        assert empty.wire_length() == 0
        assert empty.to_wire() == b''
        assert Empty.from_wire(empty.to_wire()) == empty

    def test_signer_identity(self) -> None:
        identity_cert = SignerIdentity(type=SignerIdentityType.cert_hash, identity=CertificateHash(hash_algorithm=HashAlgorithm.sha256, certificate_hash=b'cert-hash'))
        identity_none = SignerIdentity(type=SignerIdentityType.none, identity=Empty())
        assert SignerIdentity.from_wire(identity_cert.to_wire()) == identity_cert
        assert SignerIdentity.from_wire(identity_none.to_wire()) == identity_none


class TestBlocks:

    configuration = Configuration(instance_name='test.com', sequence=17)  # pyright: ignore[reportCallIssue]

    def test_forwarding_header(self) -> None:
        header = ForwardingHeader.new(
            configuration=self.configuration,
            fragment=0xc000_0000,
            length=1000,
            transaction_id=12345,
            via_list=[],
            destination_list=[Destination(type=DestinationType.resource, data=ResourceID.for_resource('user@example.org'))],
            options=[],
        )
        assert ForwardingHeader.from_wire(header.to_wire()) == header

    def test_message_contents(self) -> None:
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
