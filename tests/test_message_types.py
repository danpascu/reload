# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest

from reload.messages.types import *


class TestTypes(unittest.TestCase):

    # noinspection DuplicatedCode
    def test_types(self):
        self.assertTrue(issubclass(UnsignedInteger, Element))
        self.assertTrue(issubclass(Enum, Element))
        self.assertTrue(issubclass(Flag, Element))
        self.assertTrue(issubclass(Opaque, Element))
        self.assertTrue(issubclass(FixedBytes, Element))
        self.assertTrue(issubclass(FixedSize, Element))
        self.assertTrue(issubclass(List, Element))
        self.assertTrue(issubclass(VariableLengthList, Element))
        self.assertTrue(issubclass(SimpleStructure, Element))
        self.assertTrue(issubclass(Destination, Element))
        self.assertTrue(issubclass(ForwardingOption, Element))
        self.assertTrue(issubclass(UnknownForwardingOption, Element))
        self.assertTrue(issubclass(MessageExtension, Element))
        self.assertTrue(issubclass(UnknownMessageExtension, Element))
        self.assertTrue(issubclass(SignerIdentity, Element))
        self.assertTrue(issubclass(ForwardingHeader, Element))


class TestUnsigned(unittest.TestCase):

    def test_uint_creation(self):
        # abstract base class cannot be instantiated because it doesn't define its size in bits
        with self.assertRaises(TypeError):
            UnsignedInteger()
        # unsigned integers support all the ways a python int can be instantiated
        self.assertEqual(uint8(42), 42)
        self.assertEqual(uint8('42'), 42)
        self.assertEqual(uint8('0x42', base=16), 0x42)
        self.assertEqual(uint8(), 0)
        # value must be >= 0
        with self.assertRaises(ValueError):
            uint8(-1)
        # value must be representable with the number of bits of the unsigned type
        with self.assertRaises(ValueError):
            uint8(2**8)
        with self.assertRaises(ValueError):
            uint16(2**16)
        with self.assertRaises(ValueError):
            uint32(2**32)
        with self.assertRaises(ValueError):
            uint64(2**64)
        with self.assertRaises(ValueError):
            uint128(2**128)

    def test_uint_encoding(self):
        self.assertEqual(uint8(42).to_wire(), b'\x2a')
        self.assertEqual(uint16(12345).to_wire(), b'\x30\x39')
        self.assertEqual(uint32(2**32-2).to_wire(), b'\xff\xff\xff\xfe')
        self.assertEqual(uint64(2**64-1).to_wire(), 8 * b'\xff')
        self.assertEqual(uint128(0).to_wire(), 16 * b'\x00')

    def test_uint_wire_length(self):
        self.assertEqual(uint8(42).wire_length(), 1)
        self.assertEqual(uint16(12345).wire_length(), 2)
        self.assertEqual(uint32(2).wire_length(), 4)
        self.assertEqual(uint64(3).wire_length(), 8)
        self.assertEqual(uint128(0).wire_length(), 16)

    def test_uint_decoding(self):
        # insufficient data in buffer to extract uint from
        with self.assertRaises(ValueError):
            uint8.from_wire(b'')
        with self.assertRaises(ValueError):
            uint16.from_wire(b'\x00')
        with self.assertRaises(ValueError):
            uint32.from_wire(b'\x00\x00\x00')
        with self.assertRaises(ValueError):
            uint64.from_wire(b'\x00\x00\x00')
        with self.assertRaises(ValueError):
            uint128.from_wire(b'\x00\x00\x00\x00')
        self.assertEqual(uint8.from_wire(b'\x2a'), 42)
        self.assertEqual(uint16.from_wire(b'\x12\x34'), 0x1234)
        self.assertEqual(uint32.from_wire(b'\x00\x00\x01\x02'), 0x102)
        self.assertEqual(uint64.from_wire(uint64(12345).to_wire()), 12345)
        self.assertEqual(uint128.from_wire(uint128(42).to_wire()), 42)
        # excess bytes in buffer are ignored
        self.assertEqual(uint16.from_wire(b'\x01\x02\x03\x04'), 0x102)
        # an offset can be used
        self.assertEqual(uint16.from_wire(b'\x01\x02\x03\x04', offset=2), 0x304)
        # offset can't be negative
        with self.assertRaises(ValueError):
            uint16.from_wire(b'\x01\x02\x03\x04', offset=-1)


class TestEnum(unittest.TestCase):

    def test_enum(self):
        self.assertIs(DestinationType(1), DestinationType.node)
        self.assertEqual(DestinationType.node.to_wire(), b'\x01')
        self.assertEqual(DestinationType.node.wire_length(), 1)
        self.assertEqual(ErrorCode.DataTooLarge.wire_length(), 2)
        # encode to wire and back
        self.assertIs(DestinationType.from_wire(DestinationType.node.to_wire()), DestinationType.node)
        # not enough data in buffer to extract Enum from
        with self.assertRaises(ValueError):
            DestinationType.from_wire(b'')
        # value on wire doesn't match with Enum values
        with self.assertRaises(ValueError):
            DestinationType.from_wire(b'\x99')
        # an offset can be used
        self.assertEqual(DestinationType.from_wire(b'\xff\xfe\x01\x02\x03\x04', offset=2), DestinationType.node)
        # offset can't be negative
        with self.assertRaises(ValueError):
            DestinationType.from_wire(b'\x01\x02', offset=-1)


class TestFlag(unittest.TestCase):

    def test_flag(self):
        flag = ForwardingFlags.RESPONSE_COPY
        self.assertIs(ForwardingFlags(4), flag)
        self.assertEqual(flag.to_wire(), b'\x04')
        self.assertEqual(flag.wire_length(), 1)
        self.assertIs(ForwardingFlags.from_wire(flag.to_wire()), flag)
        # not enough data in buffer to extract Flag from
        with self.assertRaises(ValueError):
            ForwardingFlags.from_wire(b'')
        # value on wire doesn't match with the Flag values -> converted to int
        self.assertIsInstance(ForwardingFlags.from_wire(b'\x99'), int)
        # an offset can be used
        self.assertEqual(ForwardingFlags.from_wire(b'\xff\xfe\x01\x02\x03\x04', offset=5), flag)
        # offset can't be negative
        with self.assertRaises(ValueError):
            ForwardingFlags.from_wire(b'\x01\x02', offset=-1)


class TestOpaque(unittest.TestCase):
    def test_opaque_creation(self):
        # abstract base class cannot be instantiated because it doesn't define its max size
        with self.assertRaises(TypeError):
            Opaque()
        # opaque byte strings support all the ways a python bytes object can be instantiated
        self.assertEqual(Opaque8([1, 2, 3]), b'\x01\x02\x03')
        self.assertEqual(Opaque8(b'abc'), b'abc')
        self.assertEqual(Opaque8('test', encoding='ascii'), b'test')
        self.assertEqual(Opaque8(3), b'\x00\x00\x00')
        self.assertEqual(Opaque8(), b'')
        # the size must be at most the max size defined by the type
        with self.assertRaises(ValueError):
            Opaque8(2**8)
        with self.assertRaises(ValueError):
            Opaque16(2**16)
        with self.assertRaises(ValueError):
            Opaque24(2**24)

    def test_opaque_encoding(self):
        self.assertEqual(Opaque8().to_wire(), b'\x00')
        self.assertEqual(Opaque16(4).to_wire(), b'\x00\x04\x00\x00\x00\x00')
        self.assertEqual(Opaque24(b'foo').to_wire(), b'\x00\x00\x03foo')
        self.assertEqual(Opaque32(b'testing').to_wire(), b'\x00\x00\x00\x07testing')

    def test_opaque_wire_length(self):
        self.assertEqual(Opaque8().wire_length(), 1 + 0)
        self.assertEqual(Opaque16(4).wire_length(), 2 + 4)
        self.assertEqual(Opaque24(b'foo').wire_length(), 3 + 3)
        self.assertEqual(Opaque32(b'testing').wire_length(), 4 + 7)

    def test_opaque_decoding(self):
        self.assertEqual(Opaque8.from_wire(b'\x03foo'), b'foo')
        self.assertEqual(Opaque16.from_wire(b'\x00\x04test'), b'test')
        self.assertEqual(Opaque32.from_wire(b'\x00\x00\x00\x04test+padding'), b'test')
        # not enough data in buffer to extract opaque byte string from
        with self.assertRaises(ValueError):
            Opaque8.from_wire(b'\x23abc')
        # an offset can be used
        self.assertEqual(Opaque8.from_wire(b'\xff\xfe\x03foo', offset=2), b'foo')
        # offset can't be negative
        with self.assertRaises(ValueError):
            Opaque8.from_wire(b'\x04test', offset=-1)

    def test_ids(self):
        node_id = NodeID.generate()
        opaque_id = OpaqueID(b'test')
        resource_id = ResourceID.for_resource('user@example.com')
        self.assertEqual(node_id.wire_length(), NodeID.__size__)
        self.assertEqual(opaque_id.wire_length(), len(opaque_id) + 1)
        self.assertEqual(resource_id.wire_length(), len(resource_id) + 1)
        self.assertEqual(len(resource_id), len(node_id))
        self.assertEqual(node_id.to_wire(), node_id)
        self.assertEqual(NodeID.from_wire(node_id.to_wire()), node_id)
        self.assertEqual(OpaqueID.from_wire(opaque_id.to_wire()), opaque_id)
        self.assertEqual(ResourceID.from_wire(resource_id.to_wire()), resource_id)
        # not enough data in buffer to extract NodeID from
        with self.assertRaises(ValueError):
            NodeID.from_wire(b'short')
        # an offset can be used
        self.assertEqual(OpaqueID.from_wire(b'\xff\xfe\x03foo', offset=2), b'foo')
        # offset can't be negative
        with self.assertRaises(ValueError):
            OpaqueID.from_wire(b'\x04test', offset=-1)


class TestCompound(unittest.TestCase):

    def test_list_types(self):
        # lists that do not encode their size on the wire
        destination1 = Destination(DestinationType.node, NodeID.generate())
        destination2 = Destination(DestinationType.node, NodeID.generate())
        target = Destination(DestinationType.resource, ResourceID.for_resource('user@example.org'))
        destination_list = DestinationList([destination1, destination2, target])
        self.assertEqual(destination_list.to_wire(), b''.join(item.to_wire() for item in destination_list))
        self.assertEqual((destination_list.wire_length()), sum(item.wire_length() for item in destination_list))
        with self.assertRaises(ValueError):
            DestinationList.from_wire(destination_list.to_wire()[:-5])
        forwarding_options = ForwardingOptionList()
        self.assertEqual(forwarding_options.to_wire(), b'')
        self.assertEqual(forwarding_options.wire_length(), 0)
        # variable length lists
        message_extensions = MessageExtensionList()
        self.assertEqual(message_extensions.to_wire(), bytes(4))
        self.assertEqual(message_extensions.wire_length(), 4)
        message_extensions.append(UnknownMessageExtension(9, True, Opaque32(b'test')))
        self.assertEqual(MessageExtensionList.from_wire(message_extensions.to_wire()), message_extensions)
        with self.assertRaises(ValueError):
            self.assertEqual(MessageExtensionList.from_wire(message_extensions.to_wire()[:-1]), message_extensions)
        node_list = NodeIDList([NodeID.generate(), NodeID.generate(), NodeID.generate()])
        self.assertEqual(node_list.to_wire(), b'\x00\x30' + b''.join(node for node in node_list))
        self.assertEqual(node_list.wire_length(), len(node_list) * NodeID.__size__ + NodeIDList.__sizelen__)
        self.assertEqual(NodeIDList.from_wire(node_list.to_wire()), node_list)
        with self.assertRaises(ValueError):
            NodeIDList.from_wire(node_list.to_wire()[:-5])

    def test_destination(self):
        node_id = NodeID.generate()
        destination = Destination(DestinationType.node, node_id)
        self.assertEqual(destination.wire_length(), len(node_id) + DestinationType.__size__ + uint8.__size__)
        self.assertEqual(destination.to_wire(), b'\x01\x10' + node_id)
        self.assertEqual(Destination.from_wire(destination.to_wire()), destination)
        resource_id = ResourceID.for_resource('user@example.org')
        destination = Destination(DestinationType.resource, resource_id)
        self.assertEqual(destination.wire_length(), len(resource_id) + uint8.__size__ + DestinationType.__size__ + uint8.__size__)
        self.assertEqual(destination.to_wire(), b'\x02\x11\x10' + resource_id)
        self.assertEqual(Destination.from_wire(destination.to_wire()), destination)
        opaque_id = OpaqueID(b'test')
        destination = Destination(DestinationType.opaque_id_type, opaque_id)
        self.assertEqual(destination.wire_length(), len(opaque_id) + uint8.__size__ + DestinationType.__size__ + uint8.__size__)
        self.assertEqual(destination.to_wire(), b'\x03\x05\x04' + opaque_id)
        self.assertEqual(Destination.from_wire(destination.to_wire()), destination)
        opaque_id = OpaqueID(b'\xf7\x25')
        destination = Destination(DestinationType.opaque_id_type, opaque_id)
        self.assertEqual(destination.wire_length(), 2)
        self.assertEqual(destination.to_wire(), opaque_id)
        self.assertEqual(Destination.from_wire(destination.to_wire()), destination)
        with self.assertRaises(ValueError):
            Destination.from_wire(b'\x01\x10short')
        with self.assertRaises(ValueError):
            Destination.from_wire(b'\x79\xffinvalid-type.....')

    def test_forwarding_option(self):
        option = UnknownForwardingOption(7, ForwardingFlags.FORWARD_CRITICAL, Opaque16(b'test'))
        self.assertEqual(ForwardingOption.from_wire(b'\x07\x01\x00\x04test'), option)
        self.assertEqual(ForwardingOption.from_wire(option.to_wire()), option)
        with self.assertRaises(ValueError):
            ForwardingOption.from_wire(b'\xf0\xff')

    def test_message_extension(self):
        extension = UnknownMessageExtension(9, True, Opaque32(b'test'))
        self.assertEqual(MessageExtension.from_wire(b'\x09\x01\x00\x00\x00\x04test'), extension)
        self.assertEqual(MessageExtension.from_wire(extension.to_wire()), extension)
        with self.assertRaises(ValueError):
            MessageExtension.from_wire(b'\xf0\xff')

    def test_error_response(self):
        error_response = ErrorResponse(ErrorCode.Forbidden)
        self.assertEqual(error_response.wire_length(), ErrorCode.__size__ + Opaque16.__sizelen__)
        self.assertEqual(error_response.to_wire(), b'\x00\x02\x00\x00')
        error_response.info = b'NodeID mismatch'
        self.assertEqual(error_response.wire_length(), ErrorCode.__size__ + Opaque16.__sizelen__ + len(error_response.info))
        self.assertEqual(error_response.to_wire(), b'\x00\x02\x00\x0fNodeID mismatch')
        self.assertEqual(ErrorResponse.from_wire(error_response.to_wire()), error_response)

    def test_empty_structure(self):
        empty = Empty()
        self.assertEqual(empty.wire_length(), 0)
        self.assertEqual(empty.to_wire(), b'')
        self.assertEqual(Empty.from_wire(empty.to_wire()), empty)

    def test_signer_identity(self):
        identity_cert = SignerIdentity(SignerIdentityType.cert_hash, CertificateHash(HashAlgorithm.sha256, b'cert-hash'))
        identity_none = SignerIdentity(SignerIdentityType.none, Empty())
        self.assertEqual(SignerIdentity.from_wire(identity_cert.to_wire()), identity_cert)
        self.assertEqual(SignerIdentity.from_wire(identity_none.to_wire()), identity_none)


class TestBlocks(unittest.TestCase):

    class Configuration:
        overlay_id = 1
        sequence = 17
        initial_ttl = 100

    def test_forwarding_header(self):
        header = ForwardingHeader.new(
            self.Configuration,
            0xc000_0000,
            1000,
            12345,
            DestinationList(),
            DestinationList([Destination(DestinationType.resource, ResourceID.for_resource('user@example.org'))]),
            ForwardingOptionList(),
        )
        self.assertEqual(vars(ForwardingHeader.from_wire(header.to_wire())), vars(header))

    def test_message_contents(self):
        message = JoinRequest(NodeID.generate())
        content = MessageContents.for_message(message)
        wire_data = content.to_wire()
        read_content = MessageContents.from_wire(wire_data)
        read_message = Message[read_content.code].from_wire(read_content.body)
        self.assertEqual(len(wire_data), content.wire_length())
        self.assertEqual(read_content, content)
        self.assertEqual(read_message, message)

    def test_signature_block(self):
        certificate_list = GenericCertificateList([GenericCertificate(CertificateType.X509, b'certificate')])
        signer_identity = SignerIdentity(SignerIdentityType.cert_hash, CertificateHash(HashAlgorithm.sha256, b'certificate-hash'))
        signature = Signature(SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa), signer_identity, b'signature')
        security_block = SecurityBlock(certificate_list, signature)
        self.assertEqual(SecurityBlock.from_wire(security_block.to_wire()), security_block)


if __name__ == '__main__':
    unittest.main()
