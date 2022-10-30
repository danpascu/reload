# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import abc
import enum
import hashlib
import random
import struct

from collections.abc import Iterable
from typing import cast, TypeVar


__all__ = (
    # constants  # todo: expose this?
    'RELOAD_VERSION',

    # abstract types
    'Element',
    'UnsignedInteger',
    'Enum',
    'Flag',
    'FixedBytes',
    'FixedSize',
    'Opaque',
    'List',
    'VariableLengthList',
    'StructureField',
    'SimpleStructure',
    'Message',

    # unsigned integer types
    'uint8',
    'uint16',
    'uint32',
    'uint64',
    'uint128',

    # enumeration and flag types
    'AddressType',
    'DestinationType',
    'ForwardingOptionType',
    'ForwardingFlags',
    'MessageExtensionType',
    'ErrorCode',
    'CertificateType',
    'SignatureAlgorithm',
    'HashAlgorithm',
    'SignerIdentityType',
    'ChordLeaveType',

    # byte sequences
    'Opaque8',
    'Opaque16',
    'Opaque24',
    'Opaque32',
    'NodeID',
    'OpaqueID',
    'ResourceID',

    # composite types
    'Destination',
    'DestinationList',
    'ViaList',
    'ForwardingOption',
    'ForwardingOptionList',
    'UnknownForwardingOption',
    'MessageExtension',
    'MessageExtensionList',
    'UnknownMessageExtension',
    'GenericCertificate',
    'GenericCertificateList',
    'SignatureAndHashAlgorithm',
    'CertificateHash',
    'CertificateHashNodeID',
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
    'NodeIDList',
    'ChordLeaveData',

    # high level structures
    'ForwardingHeader',
    'MessageContents',
    'SecurityBlock',
)


RELOAD_VERSION = 10  # The version of the RELOAD protocol being implemented times 10 (currently 1.0)

RELO_TOKEN = b'\xd2ELO'  # 'RELO' with the high bit of the 1st character set to 1


# noinspection PyUnresolvedReferences
class Element(metaclass=abc.ABCMeta):
    """Abstract class that defines the interface for RELOAD message elements"""

    @classmethod
    @abc.abstractmethod
    def from_wire(cls, buffer: bytes, offset=0):
        raise NotImplementedError

    @abc.abstractmethod
    def to_wire(self):
        raise NotImplementedError

    @abc.abstractmethod
    def wire_length(self):
        raise NotImplementedError

    @classmethod
    def __subclasshook__(cls, subclass):
        if cls is Element and all(callable(getattr(subclass, method, None)) for method in cls.__abstractmethods__):
            return True
        return NotImplemented


T = TypeVar('T')


# helpers

def byte_length(number: int):
    """Return the number of bytes needed to represent the number"""
    return (number.bit_length() + 7) // 8


# Basic data types

# Numbers

class UnsignedInteger(int):
    __bits__ = None
    __size__ = None

    def __init_subclass__(cls, **kw):
        if (bits := kw.pop('bits', None)) is not None:
            cls.__bits__ = bits
            cls.__size__ = bits // 8
        super().__init_subclass__(**kw)

    def __new__(cls, *args, **kw):
        if cls.__bits__ is None:
            raise TypeError(f"Can't instantiate abstract unsigned integer type {cls.__name__} that does not define its bit length")
        value = super().__new__(cls, *args, **kw)
        if value < 0 or value.bit_length() > cls.__bits__:
            raise ValueError(f'value is out of range for unsigned {cls.__bits__}-bits: {value!r}')
        return value

    @classmethod
    def from_wire(cls, buffer: bytes, offset=0):
        if cls.__bits__ is None:
            raise TypeError(f"Can't instantiate abstract unsigned integer type {cls.__name__} that does not define its bit length")
        if offset < 0:
            raise ValueError('offset must be a positive integer')
        if len(buffer) < offset + cls.__size__:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__name__} from')
        return cls.from_bytes(buffer[offset:offset + cls.__size__], byteorder='big')

    def to_wire(self):
        return self.to_bytes(self.__size__, byteorder='big')

    def wire_length(self):
        return self.__size__


class Unsigned8(UnsignedInteger, bits=8):
    pass


class Unsigned16(UnsignedInteger, bits=16):
    pass


class Unsigned32(UnsignedInteger, bits=32):
    pass


class Unsigned64(UnsignedInteger, bits=64):
    pass


class Unsigned128(UnsignedInteger, bits=128):
    pass


uint8 = Unsigned8
uint16 = Unsigned16
uint32 = Unsigned32
uint64 = Unsigned64
uint128 = Unsigned128


# todo: bool cannot be subclassed. decide how to handle this (define an enum or use uint8 or just bool.to_bytes(1, 'big'))


# Enumeration and flag types

class EnumFlagWireProtocol:
    """Mixin class that provides the wire protocol for Enum and Flag types"""

    def __init_subclass__(cls, **kw):
        cls.__size__ = kw.pop('size', 1)
        super().__init_subclass__(**kw)

    @classmethod
    def from_wire(cls: enum.EnumMeta, buffer: bytes, offset=0):
        if offset < 0:
            raise ValueError('offset must be a positive integer')
        if len(buffer) < offset + cls.__size__:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__name__} from')
        return cls(int.from_bytes(buffer[offset:offset + cls.__size__], byteorder='big'))

    def to_wire(self: enum.IntEnum):
        return self.to_bytes(self.__size__, byteorder='big')

    def wire_length(self):
        return self.__size__


class Enum(EnumFlagWireProtocol, enum.IntEnum):
    pass


class Flag(EnumFlagWireProtocol, enum.IntFlag):
    pass


class AddressType(Enum):
    invalid = 0
    ipv4_address = 1
    ipv6_address = 2


class DestinationType(Enum):
    invalid = 0
    node = 1
    resource = 2
    opaque_id_type = 3


class ForwardingOptionType(Enum):
    invalid = 0


class ForwardingFlags(Flag):
    FORWARD_CRITICAL = 1
    DESTINATION_CRITICAL = 2
    RESPONSE_COPY = 4


class MessageExtensionType(Enum, size=2):
    invalid = 0


class ErrorCode(Enum, size=2):
    # 0x8000 .. 0xFFFE - Reserved

    invalid = 0
    unassigned = 1

    Forbidden = 2
    NotFound = 3
    RequestTimeout = 4
    GenerationCounterTooLow = 5
    IncompatibleWithOverlay = 6
    UnsupportedForwardingOption = 7
    DataTooLarge = 8
    DataTooOld = 9
    TTLExceeded = 10
    MessageTooLarge = 11
    UnknownKind = 12
    UnknownExtension = 13
    ResponseTooLarge = 14
    ConfigTooOld = 15
    ConfigTooNew = 16
    InProgress = 17
    ExpA = 18
    ExpB = 19
    InvalidMessage = 20


class CertificateType(Enum):
    X509 = 0
    # OpenPGP = 1  # not used by RELOAD


class SignatureAlgorithm(Enum):
    # https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16
    anonymous = 0
    rsa = 1
    dsa = 2
    ecdsa = 3
    ed25519 = 7
    ed448 = 8
    gostr34102012_256 = 64
    gostr34102012_512 = 65


class HashAlgorithm(Enum):
    # https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
    none = 0
    md5 = 1
    sha1 = 2
    sha224 = 3
    sha256 = 4
    sha384 = 5
    sha512 = 6
    Intrinsic = 8


class SignerIdentityType(Enum):
    invalid = 0
    cert_hash = 1
    cert_hash_node_id = 2
    none = 3


class ChordLeaveType(Enum):
    invalid = 0
    from_successor = 1
    from_predecessor = 2


# Byte strings

class FixedBytes(bytes):
    __instance__ = None

    def __init_subclass__(cls, **kw):
        if (value := kw.pop('value', None)) is not None:
            cls.__instance__ = super().__new__(cls, value)
        super().__init_subclass__(**kw)

    def __new__(cls, *args, **kw):
        return cls.__instance__

    @classmethod
    def from_wire(cls, buffer: bytes, offset=0):
        if offset < 0:
            raise ValueError('offset must be a positive integer')
        size = len(cls.__instance__)
        if len(buffer) < offset + size:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__name__} from')
        if buffer[offset:offset+size] != cls.__instance__:
            raise ValueError(f'Value on wire does not match {cls.__name__}')
        return cls.__instance__

    def to_wire(self):
        return self

    def wire_length(self):
        return len(self)


class FixedSize(bytes):
    """A fixed size bytes buffer"""

    __size__ = None

    def __init_subclass__(cls, **kw):
        if (size := kw.pop('size', None)) is not None:
            cls.__size__ = size
        super().__init_subclass__(**kw)

    def __new__(cls, *args, **kw):
        if cls.__size__ is None:
            raise TypeError(f"Can't instantiate fixed size bytes type {cls.__name__} that does not define its size")
        instance = super().__new__(cls, *args, **kw)
        if len(instance) != cls.__size__:
            raise ValueError(f'{cls.__name__} objects must have {cls.__size__} bytes')
        return instance

    @classmethod
    def from_wire(cls, buffer: bytes, offset=0):
        if cls.__size__ is None:
            raise TypeError(f"Can't instantiate fixed size bytes type {cls.__name__} that does not define its size")
        if offset < 0:
            raise ValueError('offset must be a positive integer')
        if len(buffer) < offset + cls.__size__:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__name__} from')
        return cls(buffer[offset:offset + cls.__size__])

    def to_wire(self):
        return self

    def wire_length(self):
        return self.__size__


class Opaque(bytes):
    """A bytes buffer of up to maxsize bytes, prefixed with its length"""

    __maxsize__ = None
    __sizelen__ = None

    def __init_subclass__(cls, **kw):
        if (maxsize := kw.pop('maxsize', None)) is not None:
            cls.__maxsize__ = maxsize
            cls.__sizelen__ = byte_length(maxsize)
        super().__init_subclass__(**kw)

    def __new__(cls, *args, **kw):
        if cls.__maxsize__ is None:
            raise TypeError(f"Can't instantiate variable length bytes type {cls.__name__} that does not define its max size")
        instance = super().__new__(cls, *args, **kw)
        if len(instance) > cls.__maxsize__:
            raise ValueError(f'{cls.__name__} objects can have at most {cls.__maxsize__} bytes')
        return instance

    @classmethod
    def from_wire(cls, buffer: bytes, offset=0):
        if cls.__maxsize__ is None:
            raise TypeError(f"Can't instantiate variable length bytes type {cls.__name__} that does not define its max size")
        if offset < 0:
            raise ValueError('offset must be a positive integer')
        buffer_length = len(buffer)
        data_start = offset + cls.__sizelen__
        if buffer_length < data_start:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__name__} from')
        data_size = int.from_bytes(buffer[offset:data_start], byteorder='big')
        if buffer_length < data_start + data_size:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__name__} from')
        return cls(buffer[data_start:data_start+data_size])

    def to_wire(self):
        return len(self).to_bytes(self.__sizelen__, byteorder='big') + self

    def wire_length(self):
        return self.__sizelen__ + len(self)


class Opaque8(Opaque, maxsize=2**8-1):
    pass


class Opaque16(Opaque, maxsize=2**16-1):
    pass


class Opaque24(Opaque, maxsize=2**24-1):
    pass


class Opaque32(Opaque, maxsize=2**32-1):
    pass


opaque8 = Opaque8
opaque16 = Opaque16
opaque24 = Opaque24
opaque32 = Opaque32


# Special values

# token = bytearray(b'RELO')
# token[0] |= 0b1000_0000

class ReloToken(FixedBytes, value=b'\xd2ELO'):  # todo: turn this into a constant (we do not use its from_wire/to_wire capabilities)
    pass


# IDs

class NodeID(FixedSize, size=16):
    def __repr__(self):
        return f'<{self.__class__.__name__}: {self.hex()}>'

    @property
    def value(self):
        return int.from_bytes(self, byteorder='big')

    @classmethod
    def generate(cls):
        return cls(random.randbytes(cls.__size__))


class OpaqueID(Opaque, maxsize=255):
    def __repr__(self):
        return f'<{self.__class__.__name__}: {self.hex()}>'

    @property
    def value(self):
        return int.from_bytes(self, byteorder='big')


class ResourceID(OpaqueID):
    @classmethod
    def for_resource(cls, resource: 'str | bytes'):
        if isinstance(resource, str):
            resource = resource.encode()
        return cls(hashlib.sha1(resource).digest()[:NodeID.__size__])


# Compound types

class List(list):
    __type__ = None

    def __init_subclass__(cls, **kw):
        if (item_type := kw.pop('item_type', None)) is not None:
            cls.__type__ = item_type
        super().__init_subclass__(**kw)

    def __new__(cls, iterable=(), /) -> T:
        if cls.__type__ is None:
            raise TypeError(f"Can't instantiate abstract list {cls.__name__} that does not define its item type")
        return super().__new__(cls, iterable)

    def __init__(self, iterable=(), /):
        self._validate(iterable)  # todo: decide if to validate or not
        super().__init__(iterable)

    def __repr__(self):
        return f'{self.__class__.__name__}({super().__repr__()})'

    def __add__(self, other, /):
        items = super().__add__(other)
        if not isinstance(other, self.__class__):
            self._validate(other)
        return self._new(items)

    def __getitem__(self, index, /):
        if isinstance(index, slice):
            return self._new(super().__getitem__(index))
        else:
            return super().__getitem__(index)

    def __iadd__(self, other, /):
        if not isinstance(other, self.__class__):
            self._validate(other)
        super().__iadd__(other)

    def __mul__(self, value, /):
        return self._new(super().__mul__(value))

    def __rmul__(self, value, /):
        return self._new(super().__rmul__(value))

    def __setitem__(self, index, value, /):
        if isinstance(index, slice):
            if not isinstance(value, self.__class__):
                self._validate(value)
        else:
            if not isinstance(value, self.__type__):
                raise TypeError(f'item must be of type {self.__type__.__qualname__}')
        super().__setitem__(index, value)

    @classmethod
    def _new(cls, iterable=(), /) -> T:
        """Create a new instance assuming that iterable has items of the correct type"""
        if cls.__type__ is None:
            raise TypeError(f"Can't instantiate abstract list {cls.__name__} that does not define its item type")
        instance = super().__new__(cls)
        super(List, instance).__init__(iterable)
        return instance

    def _validate(self, iterable, /):
        if not all(isinstance(item, self.__type__) for item in iterable):
            raise TypeError(f'items must be of type {self.__type__.__qualname__}')

    def append(self, item, /):
        if not isinstance(item, self.__type__):
            raise TypeError(f'item must be of type {self.__type__.__qualname__}')
        super().append(item)

    def copy(self) -> T:
        return self._new(super().copy())

    def extend(self, iterable, /):
        if not isinstance(iterable, self.__class__):
            self._validate(iterable)
        super().extend(iterable)

    def insert(self, index, item, /):
        if not isinstance(item, self.__type__):
            raise TypeError(f'item must be of type {self.__type__.__qualname__}')
        super().insert(index, item)

    # Element API

    @classmethod
    def from_wire(cls, buffer: bytes, offset=0) -> T:
        if cls.__type__ is None:
            raise TypeError(f"Can't instantiate abstract list {cls.__name__} that does not define its item type")
        buffer_length = len(buffer)
        position = offset
        items = []
        while position < buffer_length:
            item = cls.__type__.from_wire(buffer, position)
            items.append(item)
            position += item.wire_length()
        return cls._new(items)

    def to_wire(self):
        return b''.join(item.to_wire() for item in self)

    def wire_length(self):
        return sum(item.wire_length() for item in self)


class VariableLengthList(List):
    __maxsize__ = None
    __sizelen__ = None

    def __init_subclass__(cls, **kw):
        if (maxsize := kw.pop('maxsize', None)) is not None:
            cls.__maxsize__ = maxsize
            cls.__sizelen__ = byte_length(maxsize)
        super().__init_subclass__(**kw)

    def __new__(cls, iterable=(), /) -> T:
        if cls.__maxsize__ is None:
            raise TypeError(f"Can't instantiate variable length list {cls.__name__} that does not define its max size")
        return super().__new__(cls, iterable)

    @classmethod
    def from_wire(cls, buffer: bytes, offset=0) -> T:
        if cls.__maxsize__ is None:
            raise TypeError(f"Can't instantiate variable length list {cls.__name__} that does not define its max size")
        if offset < 0:
            raise ValueError('offset must be a positive integer')
        buffer_length = len(buffer)
        data_start = offset + cls.__sizelen__
        if data_start > buffer_length:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__name__} from')
        data_size = int.from_bytes(buffer[offset:data_start], byteorder='big')
        if data_start + data_size > buffer_length:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__name__} from')
        with memoryview(buffer)[data_start:data_start+data_size] as view:
            return super().from_wire(view)

    def to_wire(self):
        return super().wire_length().to_bytes(self.__sizelen__, byteorder='big') + super().to_wire()

    def wire_length(self):
        return self.__sizelen__ + super().wire_length()


class StructureField:
    # noinspection PyShadowingBuiltins
    def __init__(self, type, *, key_field=None, default=None):
        if key_field is None:
            if not issubclass(type, (Element, bool)):  # todo: deal with bool
                raise TypeError(f'Invalid type for {self.__class__.__name__}: must be an Element subclass.')
        else:
            if not isinstance(key_field, StructureField):
                raise TypeError('key_field must be an already defined StructureField from the same class')
            if not isinstance(type, dict):
                raise TypeError('When key_field is not None, type must be a mapping between values of the key_field and types')
            if not all(issubclass(cls, Element) for cls in type.values()):
                raise TypeError('The values from the type mapping must be Element subclasses')
        self.name = None
        self.type = type
        self.default = default
        self.key_field = key_field

    def __set_name__(self, owner, name):
        if not hasattr(owner, '__fields__'):
            owner.__fields__ = ()
        if self.name is None:
            self.name = name
            if self.key_field is not None and self.key_field not in owner.__fields__:
                raise ValueError(f'The key_field does not belong to the same owner as this {self.__class__.__name__}')
            owner.__fields__ += self,
        elif name != self.name:
            raise TypeError(f'cannot assign the same {self.__class__.__name__} to two different names: {self.name} and {name}')

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        if self.name is None:
            raise TypeError(f'cannot use {self.__class__.__name__} instance without calling __set_name__ on it.')
        return instance.__dict__[self.name]

    def __set__(self, instance, value):
        if self.key_field is None:
            field_type = self.type
        else:
            field_type = self.type[instance.__dict__[self.key_field.name]]
        if not isinstance(value, field_type):
            value = field_type(value)
        instance.__dict__[self.name] = value

    def __delete__(self, instance):
        raise AttributeError(f"Attribute '{self.name}' of '{instance.__class__.__name__}' object cannot be deleted")

    # def from_wire(self, instance, buffer: bytes, offset=0):
    #     pass
    #
    # def to_wire(self, instance):
    #     pass
    #
    # def wire_length(self, instance):
    #     pass

    # def __repr__(self):
    #     if self.key_field is None:
    #         return f'{self.__class__.__name__}(type={self.type.__name__})'
    #     else:
    #         type_repr = {str(key) if isinstance(key, Enum) else repr(key): value.__name__ for key, value in self.type.items()}
    #         return f'{self.__class__.__name__}(type={{{", ".join(": ".join(pair) for pair in type_repr.items())}}}, key_field={self.key_field.name})'


class SimpleStructure:
    __fields__ = ()

    def __init_subclass__(cls, **kw):
        if cls.__init__ is SimpleStructure.__init__ and cls.__fields__:
            def check_defaults():
                seen_default = False
                for field in cls.__fields__:
                    if field.default is not None:
                        seen_default = True
                    elif seen_default:
                        raise TypeError(f'non-default field {field.name!r} follows default field')

            def signature_generator():
                yield 'self'
                for field in cls.__fields__:
                    if field.default is not None:
                        yield f'{field.name}: {field.type.__name__} = {field.default}'
                    else:
                        yield f'{field.name}: {field.type.__name__}'

            def body_generator():
                for field in cls.__fields__:
                    yield f'    self.{field.name} = {field.name}\n'

            check_defaults()
            function_definition = f"def __init__({', '.join(signature_generator())}):\n{''.join(body_generator())}"
            namespace = {}
            exec(function_definition, globals(), namespace)
            cls.__init__ = namespace['__init__']
        super().__init_subclass__(**kw)

    def __init__(self, *args, **kw):
        pass

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return all(field.__get__(self) == field.__get__(other) for field in self.__fields__)
        return NotImplemented

    @classmethod
    def from_wire(cls, buffer: bytes, offset=0):
        if offset < 0:
            raise ValueError('offset must be a positive integer')
        args = []
        position = offset
        for field in cls.__fields__:
            value = field.type.from_wire(buffer, position)
            args.append(value)
            position += value.wire_length()
        return cls(*args)
        # return cls(*[field.type.from_wire(buffer, offset + field.offset) for field in cls.__fields__])

    def to_wire(self):
        return b''.join(field.__get__(self).to_wire() for field in self.__fields__)

    def wire_length(self):
        return sum(field.__get__(self).wire_length() for field in self.__fields__)


class Destination:
    type = StructureField(type=DestinationType)
    data = StructureField(type={DestinationType.node: NodeID, DestinationType.resource: ResourceID, DestinationType.opaque_id_type: OpaqueID}, key_field=type)

    # noinspection PyShadowingBuiltins
    def __init__(self, type: DestinationType, data: 'NodeID | ResourceID | OpaqueID'):
        self.type = type
        self.data = data

    def __repr__(self):
        return f'<{self.__class__.__name__}: {self.type.name} {self.data.hex()}>'

    def __eq__(self, other):
        if isinstance(other, Destination):
            return self.type is other.type and self.data == other.data
        return NotImplemented

    @classmethod
    def from_wire(cls, buffer: bytes, offset=0):
        if offset < 0:
            raise ValueError('offset must be a positive integer')
        if len(buffer) < offset + 2:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__name__} from')
        if buffer[0] & 0x80:
            return cls(DestinationType.opaque_id_type, buffer[0:2])
        else:
            destination_type = DestinationType.from_wire(buffer, offset)
            # length = uint8.from_wire(buffer, offset + 1)
            # length = buffer[offset+1]
            try:
                data_type = cls.data.type[destination_type]
            except KeyError:
                raise ValueError(f'Invalid {cls.__name__} type: {destination_type}')
            data = data_type.from_wire(buffer, offset + 2)
            return cls(destination_type, data)

    def to_wire(self):
        if self.type is DestinationType.opaque_id_type and len(self.data) == 2 and self.data[0] & 0x80:
            return bytes(self.data)
        else:
            return self.type.to_wire() + uint8(self.data.wire_length()).to_wire() + self.data.to_wire()

    def wire_length(self):
        if self.type is DestinationType.opaque_id_type and len(self.data) == 2 and self.data[0] & 0x80:
            return 2
        else:
            return self.data.wire_length() + 2


class DestinationList(List, item_type=Destination):
    pass


class ViaList(List, item_type=Destination):
    pass


class ForwardingOption:
    type = StructureField(type=ForwardingOptionType)
    flags = StructureField(type=ForwardingFlags)
    option = StructureField(type={}, key_field=type)  # currently there are no forwarding options defined in the RFC

    # noinspection PyShadowingBuiltins
    def __init__(self, type: ForwardingOptionType, flags: ForwardingFlags, option: Element):
        self.type = type
        self.flags = flags
        self.option = option

    def __repr__(self):
        return f'{self.__class__.__name__}(type={self.type!r}, flags={self.flags!r}, option={self.option!r})'

    def __eq__(self, other):
        if isinstance(other, ForwardingOption):
            return self.type is other.type and self.flags == other.flags and self.option == other.option
        return NotImplemented

    @classmethod
    def from_wire(cls, buffer: bytes, offset=0):
        if offset < 0:
            raise ValueError('offset must be a positive integer')
        if len(buffer) < offset + 4:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__name__} from')
        try:
            forwarding_option_type = ForwardingOptionType.from_wire(buffer, offset)
        except ValueError:
            return UnknownForwardingOption.from_wire(buffer, offset)
        else:
            flags = ForwardingFlags.from_wire(buffer, offset + 1)
            # length = uint16.from_wire(buffer, offset + 2)
            try:
                option_type = cls.option.type[forwarding_option_type]
            except KeyError:
                raise ValueError(f'Invalid {cls.__name__} type: {forwarding_option_type}')
            option = option_type.from_wire(buffer, offset + 4)
            return cls(forwarding_option_type, flags, option)

    def to_wire(self):
        return self.type.to_wire() + self.flags.to_wire() + uint16(self.option.wire_length()).to_wire() + self.option.to_wire()

    def wire_length(self):
        return self.option.wire_length() + 4


# noinspection PyShadowingBuiltins
class UnknownForwardingOption(ForwardingOption):
    """Instances of this represent forwarding options that are not understood"""

    type = StructureField(type=uint8)
    flags = StructureField(type=ForwardingFlags)
    option = StructureField(type=Opaque16)

    def __init__(self, type: int, flags: ForwardingFlags, option: bytes):
        super().__init__(cast(ForwardingOptionType, type), flags, cast(Element, option))

    def __eq__(self, other):
        if isinstance(other, UnknownForwardingOption):
            return self.type == other.type and self.flags == other.flags and self.option == other.option
        return NotImplemented

    @classmethod
    def from_wire(cls, buffer: bytes, offset=0):
        if offset < 0:
            raise ValueError('offset must be a positive integer')
        if len(buffer) < offset + 2:
            raise ValueError('Insufficient data in buffer to extract ForwardingOption from')
        type = uint8.from_wire(buffer, offset)
        flags = ForwardingFlags.from_wire(buffer, offset + 1)
        option = Opaque16.from_wire(buffer, offset + 2)
        return cls(type, flags, option)

    def to_wire(self):
        return self.type.to_wire() + self.flags.to_wire() + self.option.to_wire()

    def wire_length(self):
        return self.option.wire_length() + 2


class ForwardingOptionList(List, item_type=ForwardingOption):
    pass


class MessageExtension:
    type = StructureField(type=MessageExtensionType)
    critical = StructureField(type=bool)
    extension = StructureField(type={}, key_field=type)  # currently there are no message extensions defined in the RFC

    # noinspection PyShadowingBuiltins
    def __init__(self, type: MessageExtensionType, critical: bool, extension: Element):
        self.type = type
        self.critical = critical
        self.extension = extension

    def __repr__(self):
        return f'{self.__class__.__name__}(type={self.type!r}, critical={self.critical!r}, extension={self.extension!r})'

    def __eq__(self, other):
        if isinstance(other, MessageExtension):
            return self.type is other.type and self.critical == other.critical and self.extension == other.extension
        return NotImplemented

    @classmethod
    def from_wire(cls, buffer: bytes, offset=0):
        if offset < 0:
            raise ValueError('offset must be a positive integer')
        if len(buffer) < offset + 2:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__name__} from')
        try:
            message_extension_type = MessageExtensionType.from_wire(buffer, offset)
        except ValueError:
            return UnknownMessageExtension.from_wire(buffer, offset)
        else:
            critical = bool(buffer[offset+1])
            try:
                extension_type = cls.extension.type[message_extension_type]
            except KeyError:
                raise ValueError(f'Invalid {cls.__name__} type: {message_extension_type}')
            extension = extension_type.from_wire(buffer, offset + 2)
            return cls(message_extension_type, critical, extension)

    def to_wire(self):
        return self.type.to_wire() + self.critical.to_bytes(1, byteorder='big') + self.extension.to_wire()

    def wire_length(self):
        return self.extension.wire_length() + 2


# noinspection PyShadowingBuiltins
class UnknownMessageExtension(MessageExtension):
    """Instances of this represent message extensions that are not understood"""

    type = StructureField(type=uint8)
    critical = StructureField(type=bool)
    extension = StructureField(type=Opaque32)

    def __init__(self, type: int, critical: bool, extension: bytes):
        super().__init__(cast(MessageExtensionType, type), critical, cast(Element, extension))

    def __eq__(self, other):
        if isinstance(other, UnknownMessageExtension):
            return self.type == other.type and self.critical == other.critical and self.extension == other.extension
        return NotImplemented

    @classmethod
    def from_wire(cls, buffer: bytes, offset=0):
        if offset < 0:
            raise ValueError('offset must be a positive integer')
        if len(buffer) < offset + 2:
            raise ValueError('Insufficient data in buffer to extract MessageExtension from')
        type = uint8.from_wire(buffer, offset)
        critical = bool(buffer[offset+1])
        extension = Opaque32.from_wire(buffer, offset+2)
        return cls(type, critical, extension)


class MessageExtensionList(VariableLengthList, item_type=MessageExtension, maxsize=2**32-1):
    pass


class GenericCertificate(SimpleStructure):
    type = StructureField(type=CertificateType)
    certificate = StructureField(type=Opaque16)


class GenericCertificateList(VariableLengthList, item_type=GenericCertificate, maxsize=2**16-1):
    pass


class SignatureAndHashAlgorithm(SimpleStructure):
    hash = StructureField(type=HashAlgorithm)
    signature = StructureField(type=SignatureAlgorithm)


class CertificateHash(SimpleStructure):
    hash_algorithm = StructureField(type=HashAlgorithm)
    certificate_hash = StructureField(type=Opaque8)


class CertificateHashNodeID(SimpleStructure):  # todo: merge this with the one above, or give them different __init__ methods?
    hash_algorithm = StructureField(type=HashAlgorithm)
    certificate_node_id_hash = StructureField(type=Opaque8)  # todo: rename to certificate_hash?


class Empty(SimpleStructure):
    pass


class SignerIdentity:
    type = StructureField(type=SignerIdentityType)
    # length = StructureField(type=uint16)  # not exposed on the object
    identity = StructureField(
        type={
            SignerIdentityType.cert_hash: CertificateHash,
            SignerIdentityType.cert_hash_node_id: CertificateHashNodeID,
            SignerIdentityType.none: Empty
        }, key_field=type
    )

    # noinspection PyShadowingBuiltins
    def __init__(self, type: SignerIdentityType, identity: 'CertificateHash | CertificateHashNodeID | Empty'):
        self.type = type
        self.identity = identity

    def __repr__(self):
        return f'<{self.__class__.__name__}: {self.type.name} {self.identity!r}>'

    def __eq__(self, other):
        if isinstance(other, SignerIdentity):
            return self.type is other.type and self.identity == other.identity
        return NotImplemented

    @classmethod
    def from_wire(cls, buffer: bytes, offset=0):
        if offset < 0:
            raise ValueError('offset must be a positive integer')
        if len(buffer) < offset + 3:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__name__} from')
        identity_type = SignerIdentityType.from_wire(buffer, offset)
        # length = uint16.from_wire(buffer, offset + 1)
        try:
            identity_type_class = cls.identity.type[identity_type]
        except KeyError:
            raise ValueError(f'Invalid {cls.__name__} type: {identity_type}')
        identity = identity_type_class.from_wire(buffer, offset + 3)
        return cls(identity_type, identity)

    def to_wire(self):
        return self.type.to_wire() + uint16(self.identity.wire_length()).to_wire() + self.identity.to_wire()

    def wire_length(self):
        return self.identity.wire_length() + 3


class Signature(SimpleStructure):
    algorithm = StructureField(type=SignatureAndHashAlgorithm)
    identity = StructureField(type=SignerIdentity)
    value = StructureField(type=Opaque16)


# Requests and Responses

class Message(SimpleStructure):
    # message code 0 is invalid and should not be used anywhere
    # this should be overridden by subclasses
    __code__ = 0
    __registry__ = {}

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        if not isinstance(cls.__code__, int) or cls.__code__ < 0 or cls.__code__ > 0xffff:
            raise ValueError(f'invalid message code: {cls.__code__} (should be between 0 and 0xffff)')
        if cls.__code__ != 0 and cls.__registry__.setdefault(cls.__code__, cls) is not cls:
            raise TypeError(f'message code 0x{cls.__code__:x} is already used by {cls.__registry__[cls.__code__]}')

    def __class_getitem__(cls, item) -> 'Message':
        return cls.__registry__[item]


class JoinRequest(Message):
    __code__ = 0x0f

    joining_peer_id = StructureField(type=NodeID)
    overlay_data = StructureField(type=Opaque16, default=b'')


class JoinResponse(Message):
    __code__ = 0x10

    overlay_data = StructureField(type=Opaque16, default=b'')


class LeaveRequest(Message):
    __code__ = 0x11

    leaving_peer_id = StructureField(type=NodeID)
    overlay_data = StructureField(type=Opaque16)


class LeaveResponse(Message):
    __code__ = 0x12


class PingRequest(Message):
    __code__ = 0x17

    padding = StructureField(type=Opaque16, default=b'')


class PingResponse(Message):
    __code__ = 0x18

    id = StructureField(type=uint64)
    time = StructureField(type=uint64)


class ErrorResponse(Message):
    __code__ = 0xffff

    code = StructureField(type=ErrorCode)
    info = StructureField(type=Opaque16, default=b'')


# Extension support

class NodeIDList(VariableLengthList, item_type=NodeID, maxsize=2**16-1):
    pass


class ChordLeaveData(SimpleStructure):
    type = StructureField(type=ChordLeaveType)
    node_list = StructureField(type=NodeIDList)  # todo: name: node_list vs nodes


# High level structures

class ForwardingHeader:
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

    # __preamble__ = struct.Struct('!4s4sHBBIIQIHHH')
    __preamble__ = struct.Struct('!4sIHBBIIQIHHH')

    # relo_token = StructureField(type=ReloToken)            # not exposed on the object
    overlay = StructureField(type=uint32)
    configuration_sequence = StructureField(type=uint16)
    version = StructureField(type=uint8)
    ttl = StructureField(type=uint8)
    fragment = StructureField(type=uint32)
    length = StructureField(type=uint32)
    transaction_id = StructureField(type=uint64)
    max_response_length = StructureField(type=uint32)
    # via_list_length = StructureField(type=uint16)          # not exposed on the object
    # destination_list_length = StructureField(type=uint16)  # not exposed on the object
    # options_length = StructureField(type=uint16)           # not exposed on the object
    via_list = StructureField(type=DestinationList)
    destination_list = StructureField(type=DestinationList)
    options = StructureField(type=ForwardingOptionList)

    def __init__(self,
                 overlay: int,
                 configuration_sequence: int,
                 version: int,
                 ttl: int,
                 fragment: int,
                 length: int,
                 transaction_id: int,
                 via_list: Iterable,
                 destination_list: Iterable,
                 options: Iterable = (),
                 max_response_length: int = 0
                 ):
        self.overlay = overlay  # todo: rename this to overlay_id?
        self.configuration_sequence = configuration_sequence
        self.version = version
        self.ttl = ttl
        self.fragment = fragment
        self.length = length
        self.transaction_id = transaction_id
        self.max_response_length = max_response_length
        self.via_list = cast(DestinationList, via_list)
        self.destination_list = cast(DestinationList, destination_list)
        self.options = cast(ForwardingOptionList, options)

    @classmethod
    def new(cls,
            configuration,
            fragment: int,
            length: int,
            transaction_id: int,
            via_list: Iterable,
            destination_list: Iterable,
            options: Iterable = (),
            max_response_length: int = 0
            ):
        return cls(
            configuration.overlay_id, configuration.sequence, RELOAD_VERSION, configuration.initial_ttl,
            fragment, length, transaction_id, via_list, destination_list, options, max_response_length
        )

    @classmethod
    def from_wire(cls, buffer: bytes, offset=0):
        if offset < 0:
            raise ValueError('offset must be a positive integer')
        try:
            relo_token, *args, max_response_length, via_length, destination_length, options_length = cls.__preamble__.unpack_from(buffer, offset)
        except struct.error as e:
            raise ValueError(f'Cannot read {cls.__name__} from buffer: {e!s}')
        if relo_token != ReloToken():
            raise ValueError(f'The buffer does not contain valid {cls.__name__} data')
        with memoryview(buffer) as view:
            via_start = offset + cls.__preamble__.size
            with view[via_start:via_start+via_length] as subview:
                via_list = DestinationList.from_wire(subview)
            destination_start = via_start + via_length
            with view[destination_start:destination_start+destination_length] as subview:
                destination_list = DestinationList.from_wire(subview)
            options_start = destination_start + destination_length
            with view[options_start:options_start+options_length] as subview:
                options = ForwardingOptionList.from_wire(subview)
        return cls(*args, via_list=via_list, destination_list=destination_list, options=options, max_response_length=max_response_length)

    def to_wire(self):
        preamble = self.__preamble__.pack(
            ReloToken(),
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
            self.options.wire_length()
        )
        return preamble + self.via_list.to_wire() + self.destination_list.to_wire() + self.options.to_wire()

    def wire_length(self):
        return self.__preamble__.size + self.via_list.wire_length() + self.destination_list.wire_length() + self.options.wire_length()


class MessageContents(SimpleStructure):
    code = StructureField(type=uint16)
    body = StructureField(type=Opaque32)
    extensions = StructureField(type=MessageExtensionList, default=())

    @classmethod
    def for_message(cls, message, extensions: MessageExtensionList = ()):
        if not isinstance(message, Message) or message.__code__ == 0:
            raise TypeError(f'message should be a non-abstract Message instance')
        return cls(message.__code__, message.to_wire(), extensions)


class SecurityBlock(SimpleStructure):
    certificates = StructureField(type=GenericCertificateList)
    signature = StructureField(type=Signature)
