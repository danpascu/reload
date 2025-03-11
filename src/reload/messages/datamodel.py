# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import enum
import hashlib
from collections.abc import Buffer, Iterable, MutableMapping
from io import BytesIO
from ipaddress import IPv4Address, IPv6Address
from secrets import token_bytes as secure_random_bytes
from types import GenericAlias, NotImplementedType, UnionType, new_class
from typing import Any, ClassVar, Protocol, Self, SupportsBytes, SupportsIndex, SupportsInt, TypeVar, overload, runtime_checkable

__all__ = (  # noqa: RUF022
    # Protocols and types

    'WireData',
    'DataWireProtocol',
    'DataWireAdapter',
    'SizedDataWireProtocol',

    # Adapters and the adapter registry

    'AdapterRegistry',

    'BooleanAdapter',

    'IntegerAdapter',
    'UnsignedIntegerAdapter',

    'Int8Adapter',
    'Int16Adapter',
    'Int32Adapter',
    'Int64Adapter',
    'Int128Adapter',

    'UInt8Adapter',
    'UInt16Adapter',
    'UInt32Adapter',
    'UInt64Adapter',
    'UInt128Adapter',

    'OpaqueAdapter',
    'StringAdapter',
    'LiteralBytesAdapter',
    'LiteralStringAdapter',

    'Opaque8Adapter',
    'Opaque16Adapter',
    'Opaque24Adapter',
    'Opaque32Adapter',

    'String8Adapter',
    'String16Adapter',
    'String24Adapter',
    'String32Adapter',

    'IPv4AddressAdapter',
    'IPv6AddressAdapter',

    'CompositeAdapter',

    # Abstract types

    'Integer',
    'UnsignedInteger',

    'Enum',
    'Flag',

    'LiteralBytes',
    'FixedSize',
    'Opaque',

    'List',
    'VariableLengthList',
    'make_list_type',
    'make_variable_length_list_type',

    # Concrete types

    'Int8',
    'Int16',
    'Int32',
    'Int64',
    'Int128',

    'UInt8',
    'UInt16',
    'UInt32',
    'UInt64',
    'UInt128',

    'int8',
    'int16',
    'int32',
    'int64',
    'int128',

    'uint8',
    'uint16',
    'uint32',
    'uint64',
    'uint128',

    'NoLength',

    'AddressType',
    'CandidateType',
    'CertificateType',
    'ChordLeaveType',
    'ChordUpdateType',
    'ConfigUpdateType',
    'DestinationType',
    'ErrorCode',
    'ForwardingFlags',
    'ForwardingOptionType',
    'FramedMessageType',
    'HashAlgorithm',
    'MessageExtensionType',
    'OverlayLinkType',
    'ProbeInformationType',
    'SignatureAlgorithm',
    'SignerIdentityType',

    'Opaque8',
    'Opaque16',
    'Opaque24',
    'Opaque32',

    'RELOToken',
    'NodeID',
    'OpaqueID',
    'ResourceID',
)


type WireData = bytes | bytearray | memoryview | BytesIO


# Protocols

@runtime_checkable
class DataWireProtocol(Protocol):
    """The wire protocol for RELOAD message data elements"""

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self: ...

    def to_wire(self) -> bytes: ...

    def wire_length(self) -> int: ...


@runtime_checkable
class DataWireAdapter[T](Protocol):
    """Wire protocol adapter for a RELOAD message data element of type T"""

    _abstract_: ClassVar[bool] = True

    @staticmethod
    def from_wire(buffer: WireData) -> T: ...

    @staticmethod
    def to_wire(value: T, /) -> bytes: ...

    @staticmethod
    def wire_length(value: T, /) -> int: ...

    @staticmethod
    def validate(value: T, /) -> T: ...


class SizedDataWireProtocol(DataWireProtocol, Protocol):
    _size_: ClassVar[int] = NotImplemented


class AdapterRegistry[T]:
    _adapters: ClassVar[MutableMapping[type, type[DataWireAdapter]]] = {}

    @classmethod
    def associate(cls, data_type: type[T], adapter: type[DataWireAdapter[T]]) -> None:
        if issubclass(data_type, DataWireProtocol):
            raise TypeError('Adapters for types that already implement DataWireProtocol must be explicitly provided with the element descriptors.')
        cls._adapters[data_type] = adapter

    @classmethod
    def get_adapter(cls, data_type: type[T]) -> type[DataWireAdapter[T]] | None:
        return cls._adapters.get(data_type, None)


# Helpers

def byte_length(number: int) -> int:
    """Return the number of bytes needed to represent the number"""
    return (number.bit_length() + 7) // 8


# Adapters

class BooleanAdapter:
    _abstract_: ClassVar[bool] = False

    @staticmethod
    def from_wire(buffer: WireData) -> bool:
        if isinstance(buffer, BytesIO):
            buffer = buffer.read(1)
        if not buffer:
            raise ValueError('Insufficient data in buffer to extract boolean value')
        match buffer[0]:
            case 0:
                return False
            case 1:
                return True
            case value:
                raise ValueError(f'Invalid boolean value: {value!r}')

    @staticmethod
    def to_wire(value: bool, /) -> bytes:  # noqa: FBT001
        return value.to_bytes(1)

    @staticmethod
    def wire_length(_: bool, /) -> int:  # noqa: FBT001
        return 1

    @staticmethod
    def validate(value: bool) -> bool:  # noqa: FBT001
        return value


AdapterRegistry.associate(bool, BooleanAdapter)


class IntegerAdapter:
    _abstract_: ClassVar[bool] = True
    _bits_: ClassVar[int] = NotImplemented
    _size_: ClassVar[int] = NotImplemented
    _mean_: ClassVar[int] = NotImplemented

    def __init_subclass__(cls, *, bits: int = NotImplemented, **kw: object) -> None:
        if bits is not NotImplemented:
            cls._bits_ = bits
            cls._size_ = bits // 8
            cls._mean_ = 1 << (bits - 1)  # The midpoint of the values representable with bits
            cls._abstract_ = False
        super().__init_subclass__(**kw)

    @classmethod
    def from_wire(cls, buffer: WireData) -> int:
        if isinstance(buffer, BytesIO):
            data = buffer.read(cls._size_)
        else:
            data = buffer[:cls._size_]
        if len(data) < cls._size_:
            raise ValueError(f'Insufficient data in buffer to extract a {cls._bits_}-bit integer')
        return int.from_bytes(data, byteorder='big', signed=True)

    @classmethod
    def to_wire(cls, value: int, /) -> bytes:
        return value.to_bytes(cls._size_, byteorder='big', signed=True)

    @classmethod
    def wire_length(cls, _: int, /) -> int:
        return cls._size_

    @classmethod
    def validate(cls, value: int, /) -> int:
        shifted_value = value + cls._mean_
        if shifted_value < 0 or shifted_value.bit_length() > cls._bits_:
            raise ValueError(f'Value is out of range for {cls._bits_}-bits integer: {value!r}')
        return value


class UnsignedIntegerAdapter(IntegerAdapter):
    @classmethod
    def from_wire(cls, buffer: WireData) -> int:
        if isinstance(buffer, BytesIO):
            data = buffer.read(cls._size_)
        else:
            data = buffer[:cls._size_]
        if len(data) < cls._size_:
            raise ValueError(f'Insufficient data in buffer to extract an unsigned {cls._bits_}-bit integer')
        return int.from_bytes(data, byteorder='big')

    @classmethod
    def to_wire(cls, value: int, /) -> bytes:
        return value.to_bytes(cls._size_, byteorder='big')

    @classmethod
    def wire_length(cls, _: int, /) -> int:
        return cls._size_

    @classmethod
    def validate(cls, value: int, /) -> int:
        if value < 0 or value.bit_length() > cls._bits_:
            raise ValueError(f'Value is out of range for unsigned {cls._bits_}-bits integer: {value!r}')
        return value


class Int8Adapter(IntegerAdapter, bits=8):
    pass


class Int16Adapter(IntegerAdapter, bits=16):
    pass


class Int32Adapter(IntegerAdapter, bits=32):
    pass


class Int64Adapter(IntegerAdapter, bits=64):
    pass


class Int128Adapter(IntegerAdapter, bits=128):
    pass


class UInt8Adapter(UnsignedIntegerAdapter, bits=8):
    pass


class UInt16Adapter(UnsignedIntegerAdapter, bits=16):
    pass


class UInt32Adapter(UnsignedIntegerAdapter, bits=32):
    pass


class UInt64Adapter(UnsignedIntegerAdapter, bits=64):
    pass


class UInt128Adapter(UnsignedIntegerAdapter, bits=128):
    pass


class OpaqueAdapter:
    """Adapter for a bytes buffer of up to maxsize bytes, prefixed with its length"""

    _abstract_: ClassVar[bool] = True
    _maxsize_: ClassVar[int] = NotImplemented
    _sizelen_: ClassVar[int] = NotImplemented

    def __init_subclass__(cls, *, maxsize: int = NotImplemented, **kw: object) -> None:
        if maxsize is not NotImplemented:
            cls._maxsize_ = maxsize
            cls._sizelen_ = byte_length(maxsize)
            cls._abstract_ = False
        super().__init_subclass__(**kw)

    @classmethod
    def from_wire(cls, buffer: WireData) -> bytes:
        if not isinstance(buffer, BytesIO):
            buffer = BytesIO(buffer)
        length_data = buffer.read(cls._sizelen_)
        if len(length_data) < cls._sizelen_:
            raise ValueError('Insufficient data in buffer to extract the opaque bytes length')
        data_length = int.from_bytes(length_data, byteorder='big')
        if data_length > cls._maxsize_:
            raise ValueError(f'Data length is too big for opaque bytes ({data_length} > {cls._maxsize_})')
        opaque_data = buffer.read(data_length)
        if len(opaque_data) < data_length:
            raise ValueError('Insufficient data in buffer to extract the opaque bytes')
        return opaque_data

    @classmethod
    def to_wire(cls, value: bytes, /) -> bytes:
        return len(value).to_bytes(cls._sizelen_, byteorder='big') + value

    @classmethod
    def wire_length(cls, value: bytes, /) -> int:
        return cls._sizelen_ + len(value)

    @classmethod
    def validate(cls, value: bytes, /) -> bytes:
        if len(value) > cls._maxsize_:
            raise ValueError(f'Value is too long for opaque bytes (max length is {cls._maxsize_}, value has {len(value)} bytes)')
        return value


class StringAdapter:
    """Represent strings as UTF-8 encoded length prefixed bytes limited to maxsize"""

    _abstract_: ClassVar[bool] = True
    _maxsize_: ClassVar[int] = NotImplemented
    _sizelen_: ClassVar[int] = NotImplemented

    def __init_subclass__(cls, *, maxsize: int = NotImplemented, **kw: object) -> None:
        if maxsize is not NotImplemented:
            cls._maxsize_ = maxsize
            cls._sizelen_ = byte_length(maxsize)
            cls._abstract_ = False
        super().__init_subclass__(**kw)

    @classmethod
    def from_wire(cls, buffer: WireData) -> str:
        if not isinstance(buffer, BytesIO):
            buffer = BytesIO(buffer)
        length_data = buffer.read(cls._sizelen_)
        if len(length_data) < cls._sizelen_:
            raise ValueError('Insufficient data in buffer to extract the length of the string')
        data_length = int.from_bytes(length_data, byteorder='big')
        if data_length > cls._maxsize_:
            raise ValueError(f'Data length is too big for the string ({data_length} > {cls._maxsize_})')
        opaque_data = buffer.read(data_length)
        if len(opaque_data) < data_length:
            raise ValueError('Insufficient data in buffer to extract the bytes representation of the string')
        try:
            return opaque_data.decode()
        except UnicodeDecodeError as exc:
            raise ValueError(f'Cannot decode bytes to string: {exc}') from exc

    @classmethod
    def to_wire(cls, value: str, /) -> bytes:
        data = value.encode()
        return len(data).to_bytes(cls._sizelen_, byteorder='big') + data

    @classmethod
    def wire_length(cls, value: str, /) -> int:
        return cls._sizelen_ + len(value.encode())

    @classmethod
    def validate(cls, value: str, /) -> str:
        data = value.encode()
        if len(data) > cls._maxsize_:
            raise ValueError(f'Value is too long for string (max length is {cls._maxsize_}, value has {len(data)} bytes)')
        return value


class LiteralBytesAdapter:
    """Adapter for a literal bytes value with or without a length prefix"""

    _abstract_: ClassVar[bool] = True
    _static_value_: ClassVar[bytes] = NotImplemented
    _wire_content_: ClassVar[bytes] = NotImplemented

    def __init_subclass__(cls, *, value: bytes, maxsize: int = NotImplemented, **kw: object) -> None:
        cls._static_value_ = value
        if maxsize is not NotImplemented:
            value_length = len(value)
            if value_length > maxsize:
                raise TypeError('The literal value has more than maxsize bytes')
            cls._wire_content_ = value_length.to_bytes(byte_length(maxsize), byteorder='big') + value
        else:
            cls._wire_content_ = value
        cls._abstract_ = False
        super().__init_subclass__(**kw)

    @classmethod
    def from_wire(cls, buffer: WireData) -> bytes:
        wire_length = len(cls._wire_content_)
        if isinstance(buffer, BytesIO):
            data = buffer.read(wire_length)
        else:
            data = buffer[:wire_length]
        if len(data) < wire_length:
            raise ValueError(f'Insufficient data in buffer to extract literal bytes {cls._static_value_!r}')
        if data != cls._wire_content_:
            raise ValueError(f'Value on wire does not match literal bytes {cls._static_value_!r} (wire content {data!r} != {cls._wire_content_!r})')
        return cls._static_value_

    @classmethod
    def to_wire(cls, _: bytes, /) -> bytes:
        return cls._wire_content_

    @classmethod
    def wire_length(cls, _: bytes, /) -> int:
        return len(cls._wire_content_)

    @classmethod
    def validate(cls, value: bytes, /) -> bytes:
        if value != cls._static_value_:
            raise ValueError(f'Invalid literal bytes value (expected {cls._static_value_!r}, got {value!r})')
        return value


class LiteralStringAdapter:
    """Adapter for a literal string value with or without a length prefix"""

    _abstract_: ClassVar[bool] = True
    _static_value_: ClassVar[str] = NotImplemented
    _wire_content_: ClassVar[bytes] = NotImplemented

    def __init_subclass__(cls, *, value: str, maxsize: int = NotImplemented, **kw: object) -> None:
        cls._static_value_ = value
        bytes_value = value.encode()
        if maxsize is not NotImplemented:
            bytes_length = len(bytes_value)
            if bytes_length > maxsize:
                raise TypeError('The literal value has more than maxsize bytes')
            cls._wire_content_ = bytes_length.to_bytes(byte_length(maxsize), byteorder='big') + bytes_value
        else:
            cls._wire_content_ = bytes_value
        cls._abstract_ = False
        super().__init_subclass__(**kw)

    @classmethod
    def from_wire(cls, buffer: WireData) -> str:
        wire_length = len(cls._wire_content_)
        if isinstance(buffer, BytesIO):
            data = buffer.read(wire_length)
        else:
            data = buffer[:wire_length]
        if len(data) < wire_length:
            raise ValueError(f'Insufficient data in buffer to extract literal string {cls._static_value_!r}')
        if data != cls._wire_content_:
            raise ValueError(f'Value on wire does not match literal string {cls._static_value_!r} (wire content {data!r} != {cls._wire_content_!r})')
        return cls._static_value_

    @classmethod
    def to_wire(cls, _: str, /) -> bytes:
        return cls._wire_content_

    @classmethod
    def wire_length(cls, _: str, /) -> int:
        return len(cls._wire_content_)

    @classmethod
    def validate(cls, value: str, /) -> str:
        if value != cls._static_value_:
            raise ValueError(f'Invalid literal string value (expected {cls._static_value_!r}, got {value!r})')
        return value


class Opaque8Adapter(OpaqueAdapter, maxsize=2**8 - 1):
    pass


class Opaque16Adapter(OpaqueAdapter, maxsize=2**16 - 1):
    pass


class Opaque24Adapter(OpaqueAdapter, maxsize=2**24 - 1):
    pass


class Opaque32Adapter(OpaqueAdapter, maxsize=2**32 - 1):
    pass


class String8Adapter(StringAdapter, maxsize=2**8 - 1):
    pass


class String16Adapter(StringAdapter, maxsize=2**16 - 1):
    pass


class String24Adapter(StringAdapter, maxsize=2**24 - 1):
    pass


class String32Adapter(StringAdapter, maxsize=2**32 - 1):
    pass


class IPv4AddressAdapter:
    _abstract_: ClassVar[bool] = False
    _size_ = UInt32Adapter._size_

    @classmethod
    def from_wire(cls, buffer: WireData) -> IPv4Address:
        if isinstance(buffer, BytesIO):
            data = buffer.read(cls._size_)
        else:
            data = buffer[:cls._size_]
        if len(data) < cls._size_:
            raise ValueError('Insufficient data in buffer to extract an IPv4Address')
        return IPv4Address(data)

    @classmethod
    def to_wire(cls, value: IPv4Address, /) -> bytes:
        return value.packed

    @classmethod
    def wire_length(cls, _: IPv4Address, /) -> int:
        return cls._size_

    @classmethod
    def validate(cls, value: IPv4Address, /) -> IPv4Address:
        return value


class IPv6AddressAdapter:
    _abstract_: ClassVar[bool] = False
    _size_ = UInt128Adapter._size_

    @classmethod
    def from_wire(cls, buffer: WireData) -> IPv6Address:
        if isinstance(buffer, BytesIO):
            data = buffer.read(cls._size_)
        else:
            data = buffer[:cls._size_]
        if len(data) < cls._size_:
            raise ValueError('Insufficient data in buffer to extract an IPv6Address')
        return IPv6Address(data)

    @classmethod
    def to_wire(cls, value: IPv6Address, /) -> bytes:
        return value.packed

    @classmethod
    def wire_length(cls, _: IPv6Address, /) -> int:
        return cls._size_

    @classmethod
    def validate(cls, value: IPv6Address, /) -> IPv6Address:
        return value


class CompositeAdapter[T: SizedDataWireProtocol]:
    _abstract_: ClassVar[bool] = True
    _types_: tuple[type[T], ...] = NotImplemented

    def __init_subclass__(cls, **kw: object) -> None:
        for base in getattr(cls, '__orig_bases__', ()):
            if hasattr(base, '__origin__') and issubclass(base.__origin__, CompositeAdapter):
                match base.__args__[0]:
                    case TypeVar():
                        pass  # new type is still generic
                    case UnionType() as union_type:
                        types: tuple[type[T], ...] = union_type.__args__
                        sizes = {t._size_ for t in types}
                        if NotImplemented in sizes:
                            raise TypeError('All type members must have defined their byte size')
                        if len(sizes) != 1:
                            raise TypeError('All types must have the same byte size')
                        cls._types_ = types
                        cls._abstract_ = False
                    case _:
                        raise TypeError(f'The {cls.__qualname__!r} type can only be parameterized with a union of types or a type variable')
        super().__init_subclass__(**kw)

    @classmethod
    def from_wire(cls, buffer: WireData) -> T:
        size = cls._types_[0]._size_  # all types are of equal size
        if isinstance(buffer, BytesIO):
            data = buffer.read(size)
        else:
            data = buffer[:size]
        if len(data) < size:
            raise ValueError(f'Insufficient data in buffer to extract {' | '.join(_type.__qualname__ for _type in cls._types_)!r}')
        last_error = None
        for item_type in cls._types_:
            try:
                return item_type.from_wire(data)
            except ValueError as exc:
                last_error = exc
        assert last_error is not None  # noqa: S101 (used by type checkers)
        raise last_error from None

    @classmethod
    def to_wire(cls, value: T, /) -> bytes:
        return value.to_wire()

    @classmethod
    def wire_length(cls, value: T, /) -> int:
        return value.wire_length()

    @classmethod
    def validate(cls, value: T, /) -> T:
        return value


# Data types

type ConvertibleToInt = str | Buffer | SupportsInt | SupportsIndex


# Numeric types

class Integer(int):
    _bits_: ClassVar[int] = NotImplemented
    _size_: ClassVar[int] = NotImplemented
    _mean_: ClassVar[int] = NotImplemented

    def __init_subclass__(cls, *, bits: int = NotImplemented, **kw: object) -> None:
        if bits is not NotImplemented:
            cls._bits_ = bits
            cls._size_ = bits // 8
            cls._mean_ = 1 << (bits - 1)  # The midpoint of the values representable with bits
        super().__init_subclass__(**kw)

    @overload
    def __new__(cls, x: ConvertibleToInt = ..., /) -> Self: ...

    @overload
    def __new__(cls, x: str | Buffer, /, base: SupportsIndex) -> Self: ...

    def __new__(cls, *args, **kw) -> Self:
        if cls._bits_ is NotImplemented:
            raise TypeError(f'Cannot instantiate abstract integer type {cls.__qualname__!r} that does not define its bit length')
        value = super().__new__(cls, *args, **kw)
        shifted_value = value + cls._mean_
        if shifted_value < 0 or shifted_value.bit_length() > cls._bits_:
            raise ValueError(f'Value is out of range for {cls._bits_}-bits integer: {value!r}')
        return value

    def __repr__(self) -> str:
        return f'{self.__class__.__qualname__}({super().__repr__()})'

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if cls._size_ is NotImplemented:
            raise TypeError(f'Cannot instantiate abstract integer type {cls.__qualname__!r} that does not define its bit length')
        if isinstance(buffer, BytesIO):
            data = buffer.read(cls._size_)
        else:
            data = buffer[:cls._size_]
        if len(data) < cls._size_:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__qualname__!r}')
        return cls.from_bytes(data, byteorder='big', signed=True)

    def to_wire(self) -> bytes:
        return self.to_bytes(self._size_, byteorder='big', signed=True)

    def wire_length(self) -> int:
        return self._size_


class UnsignedInteger(int):
    _bits_: ClassVar[int] = NotImplemented
    _size_: ClassVar[int] = NotImplemented

    def __init_subclass__(cls, *, bits: int = NotImplemented, **kw: object) -> None:
        if bits is not NotImplemented:
            cls._bits_ = bits
            cls._size_ = bits // 8
        super().__init_subclass__(**kw)

    @overload
    def __new__(cls, x: ConvertibleToInt = ..., /) -> Self: ...

    @overload
    def __new__(cls, x: str | Buffer, /, base: SupportsIndex) -> Self: ...

    def __new__(cls, *args, **kw) -> Self:
        if cls._bits_ is NotImplemented:
            raise TypeError(f'Cannot instantiate abstract unsigned integer type {cls.__qualname__!r} that does not define its bit length')
        value = super().__new__(cls, *args, **kw)
        if value < 0 or value.bit_length() > cls._bits_:
            raise ValueError(f'Value is out of range for unsigned {cls._bits_}-bits integer: {value!r}')
        return value

    def __repr__(self) -> str:
        return f'{self.__class__.__qualname__}({super().__repr__()})'

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if cls._size_ is NotImplemented:
            raise TypeError(f'Cannot instantiate abstract unsigned integer type {cls.__qualname__!r} that does not define its bit length')
        if isinstance(buffer, BytesIO):
            data = buffer.read(cls._size_)
        else:
            data = buffer[:cls._size_]
        if len(data) < cls._size_:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__qualname__!r}')
        return cls.from_bytes(data, byteorder='big')

    def to_wire(self) -> bytes:
        return self.to_bytes(self._size_, byteorder='big')

    def wire_length(self) -> int:
        return self._size_


class Int8(Integer, bits=8):
    pass


class Int16(Integer, bits=16):
    pass


class Int32(Integer, bits=32):
    pass


class Int64(Integer, bits=64):
    pass


class Int128(Integer, bits=128):
    pass


class UInt8(UnsignedInteger, bits=8):
    pass


class UInt16(UnsignedInteger, bits=16):
    pass


class UInt32(UnsignedInteger, bits=32):
    pass


class UInt64(UnsignedInteger, bits=64):
    pass


class UInt128(UnsignedInteger, bits=128):
    pass


int8 = Int8
int16 = Int16
int32 = Int32
int64 = Int64
int128 = Int128

uint8 = UInt8
uint16 = UInt16
uint32 = UInt32
uint64 = UInt64
uint128 = UInt128


class NoLength(UnsignedInteger, bits=0):
    """Special type for LinkedElements that do not have a length prefix"""

    @overload
    def __new__(cls, x: ConvertibleToInt = ..., /) -> Self: ...

    @overload
    def __new__(cls, x: str | Buffer, /, base: SupportsIndex) -> Self: ...

    def __new__(cls, *_args, **_kw) -> Self:
        return super(UnsignedInteger, cls).__new__(cls)

    def __repr__(self) -> str:
        return f'{self.__class__.__qualname__}()'


# Enumeration and flag types

class Enum(enum.IntEnum):
    _size_: ClassVar[int]

    def __init_subclass__(cls, *, size: int = 1, **kw: object) -> None:
        cls._size_ = size
        super().__init_subclass__(**kw)

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if isinstance(buffer, BytesIO):
            data = buffer.read(cls._size_)
        else:
            data = buffer[:cls._size_]
        if len(data) < cls._size_:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__qualname__!r}')
        return cls(int.from_bytes(data, byteorder='big'))

    def to_wire(self) -> bytes:
        return self.to_bytes(self._size_, byteorder='big')

    def wire_length(self) -> int:
        return self._size_


class Flag(enum.IntFlag):
    _size_: ClassVar[int]

    def __init_subclass__(cls, *, size: int = 1, **kw: object) -> None:
        cls._size_ = size
        super().__init_subclass__(**kw)

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if isinstance(buffer, BytesIO):
            data = buffer.read(cls._size_)
        else:
            data = buffer[:cls._size_]
        if len(data) < cls._size_:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__qualname__!r}')
        return cls(int.from_bytes(data, byteorder='big'))

    def to_wire(self) -> bytes:
        return self.to_bytes(self._size_, byteorder='big')

    def wire_length(self) -> int:
        return self._size_


class AddressType(Enum):
    invalid = 0
    ipv4_address = 1
    ipv6_address = 2


class CandidateType(Enum):
    invalid = 0
    host = 1
    srflx = 2
    relay = 4


class CertificateType(Enum):
    X509 = 0
    # OpenPGP = 1  # not used by RELOAD  # noqa: ERA001


class ChordLeaveType(Enum):
    invalid = 0
    from_successor = 1
    from_predecessor = 2


class ChordUpdateType(Enum):
    invalid = 0
    peer_ready = 1
    neighbors = 2
    full = 3


class ConfigUpdateType(Enum):
    invalid = 0
    config = 1
    kind = 2


class DestinationType(Enum):
    invalid = 0
    node = 1
    resource = 2
    opaque_id_type = 3


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


class ForwardingFlags(Flag):
    FORWARD_CRITICAL = 1
    DESTINATION_CRITICAL = 2
    RESPONSE_COPY = 4


class ForwardingOptionType(Enum):
    invalid = 0


class FramedMessageType(Enum):
    data = 128
    ack = 129


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


class MessageExtensionType(Enum, size=2):
    invalid = 0


class OverlayLinkType(Enum):
    invalid = 0
    DTLS_UDP_SR = 1
    DTLS_UDP_SR_NO_ICE = 3
    TLS_TCP_FH_NO_ICE = 4


class ProbeInformationType(Enum):
    invalid = 0
    responsible_set = 1
    num_resources = 2
    uptime = 3


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


class SignerIdentityType(Enum):
    invalid = 0
    cert_hash = 1
    cert_hash_node_id = 2
    none = 3


# Byte strings

class LiteralBytes(bytes):
    _instance_: ClassVar[Self] = NotImplemented

    def __init_subclass__(cls, *, value: bytes | bytearray | memoryview = NotImplemented, **kw: object) -> None:
        if value is not NotImplemented:
            cls._instance_ = super().__new__(cls, value)
        super().__init_subclass__(**kw)

    def __new__(cls) -> Self:
        if cls._instance_ is NotImplemented:
            raise TypeError(f'Cannot instantiate abstract literal bytes type {cls.__qualname__!r} that does not define its value')
        return cls._instance_

    def __repr__(self) -> str:
        return f'{self.__class__.__qualname__}()'

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if cls._instance_ is NotImplemented:
            raise TypeError(f'Cannot instantiate abstract literal bytes type {cls.__qualname__!r} that does not define its value')
        size = len(cls._instance_)
        if isinstance(buffer, BytesIO):
            data = buffer.read(size)
        else:
            data = buffer[:size]
        if len(data) < size:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__qualname__!r}')
        if data != cls._instance_:
            raise ValueError(f'Value on wire does not match {cls.__qualname__!r}')
        return cls._instance_

    def to_wire(self) -> bytes:
        return bytes(self)

    def wire_length(self) -> int:
        return len(self)


class FixedSize(bytes):
    """A fixed size bytes buffer"""

    _size_: ClassVar[int] = NotImplemented

    def __init_subclass__(cls, *, size: int = NotImplemented, **kw: object) -> None:
        if size is not NotImplemented:
            cls._size_ = size
        super().__init_subclass__(**kw)

    @overload
    def __new__(cls) -> Self: ...

    @overload
    def __new__(cls, o: Iterable[SupportsIndex] | SupportsIndex | SupportsBytes | Buffer, /) -> Self: ...

    @overload
    def __new__(cls, string: str, /, encoding: str, errors: str = ...) -> Self: ...

    def __new__(cls, *args, **kw):
        if cls._size_ is NotImplemented:
            raise TypeError(f'Cannot instantiate fixed size bytes type {cls.__qualname__!r} that does not define its size')
        instance = super().__new__(cls, *args, **kw)
        if len(instance) != cls._size_:
            raise ValueError(f'{cls.__qualname__!r} objects must have {cls._size_} bytes')
        return instance

    def __repr__(self) -> str:
        return f'{self.__class__.__qualname__}({super().__repr__()})'

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if cls._size_ is NotImplemented:
            raise TypeError(f'Cannot instantiate fixed size bytes type {cls.__qualname__!r} that does not define its size')
        if isinstance(buffer, BytesIO):
            data = buffer.read(cls._size_)
        else:
            data = buffer[:cls._size_]
        if len(data) < cls._size_:
            raise ValueError(f'Insufficient data in buffer to extract {cls.__qualname__!r}')
        return cls(data)

    def to_wire(self) -> bytes:
        return bytes(self)

    def wire_length(self) -> int:
        return self._size_


class Opaque(bytes):
    """A bytes buffer of up to maxsize bytes, prefixed with its length"""

    _maxsize_: ClassVar[int] = NotImplemented
    _sizelen_: ClassVar[int] = NotImplemented

    def __init_subclass__(cls, *, maxsize: int = NotImplemented, **kw: object) -> None:
        if maxsize is not NotImplemented:
            cls._maxsize_ = maxsize
            cls._sizelen_ = byte_length(maxsize)
        super().__init_subclass__(**kw)

    @overload
    def __new__(cls) -> Self: ...

    @overload
    def __new__(cls, o: Iterable[SupportsIndex] | SupportsIndex | SupportsBytes | Buffer, /) -> Self: ...

    @overload
    def __new__(cls, string: str, /, encoding: str, errors: str = ...) -> Self: ...

    def __new__(cls, *args, **kw):
        if cls._maxsize_ is NotImplemented:
            raise TypeError(f'Cannot instantiate abstract variable length bytes type {cls.__qualname__!r} that does not define its max size')
        instance = super().__new__(cls, *args, **kw)
        if len(instance) > cls._maxsize_:
            raise ValueError(f'{cls.__qualname__!r} objects can have at most {cls._maxsize_} bytes')
        return instance

    def __repr__(self) -> str:
        return f'{self.__class__.__qualname__}({super().__repr__() if self else ''})'

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if cls._sizelen_ is NotImplemented:
            raise TypeError(f'Cannot instantiate abstract variable length bytes type {cls.__qualname__!r} that does not define its max size')
        if not isinstance(buffer, BytesIO):
            buffer = BytesIO(buffer)
        length_data = buffer.read(cls._sizelen_)
        if len(length_data) < cls._sizelen_:
            raise ValueError(f'Insufficient data in buffer to extract the data length for {cls.__qualname__!r}')
        data_length = int.from_bytes(length_data, byteorder='big')
        if data_length > cls._maxsize_:
            raise ValueError(f'Data length is too big for {cls.__qualname__!r} ({data_length} > {cls._maxsize_})')
        opaque_data = buffer.read(data_length)
        if len(opaque_data) < data_length:
            raise ValueError(f'Insufficient data in buffer to extract the data for {cls.__qualname__!r}')
        return cls(opaque_data)

    def to_wire(self) -> bytes:
        return len(self).to_bytes(self._sizelen_, byteorder='big') + self

    def wire_length(self) -> int:
        return self._sizelen_ + len(self)


class Opaque8(Opaque, maxsize=2**8 - 1):
    pass


class Opaque16(Opaque, maxsize=2**16 - 1):
    pass


class Opaque24(Opaque, maxsize=2**24 - 1):
    pass


class Opaque32(Opaque, maxsize=2**32 - 1):
    pass


opaque8 = Opaque8
opaque16 = Opaque16
opaque24 = Opaque24
opaque32 = Opaque32


# Special values

class RELOToken(LiteralBytes, value=b'\xd2ELO'):
    pass


# IDs

class NodeID(FixedSize, size=16):
    def __repr__(self) -> str:
        return f'<{self.__class__.__qualname__}: {self.hex()}>'

    @property
    def value(self) -> int:
        return int.from_bytes(self, byteorder='big')

    @classmethod
    def generate(cls) -> Self:
        return cls(secure_random_bytes(cls._size_))


class OpaqueID(Opaque, maxsize=255):
    def __repr__(self) -> str:
        return f'<{self.__class__.__qualname__}: {self.hex()}>'

    @property
    def value(self) -> int:
        return int.from_bytes(self, byteorder='big')


class ResourceID(OpaqueID):
    @classmethod
    def for_resource(cls, resource: str | bytes | bytearray | memoryview) -> Self:
        if isinstance(resource, str):
            resource = resource.encode()
        return cls(hashlib.sha1(resource, usedforsecurity=False).digest()[:NodeID._size_])


# List types

class List[T: DataWireProtocol](list[T]):
    _type_: type[T] = NotImplementedType

    def __init_subclass__(cls, *, custom_repr: bool = True, **kw: object) -> None:
        if not custom_repr:
            cls.__repr__ = list.__repr__  # type: ignore[method-assign]
        for base in getattr(cls, '__orig_bases__', ()):
            if isinstance(base, GenericAlias) and isinstance(base.__origin__, type) and issubclass(base.__origin__, List):
                match base.__args__[0]:
                    case TypeVar():
                        pass  # new type is still generic
                    case type() as list_type:
                        cls._type_ = list_type
                    case _:
                        raise TypeError(f'The {cls.__qualname__!r} type can only be parameterized with a single base type or a type variable')
        super().__init_subclass__(**kw)

    def __init__(self, iterable: Iterable[T] = (), /) -> None:
        if self._type_ is NotImplementedType:
            raise TypeError(f'Cannot instantiate abstract list {self.__class__.__qualname__!r} that does not define its item type')
        super().__init__(iterable)

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({super().__repr__()})'

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if cls._type_ is NotImplementedType:
            raise TypeError(f'Cannot instantiate abstract list {cls.__qualname__!r} that does not define its item type')
        if not isinstance(buffer, BytesIO):
            buffer = BytesIO(buffer)
        buffer_length = len(buffer.getvalue())
        items = []
        while buffer.tell() < buffer_length:
            item = cls._type_.from_wire(buffer)
            items.append(item)
        return cls(items)

    def to_wire(self) -> bytes:
        return b''.join(item.to_wire() for item in self)

    def wire_length(self) -> int:
        return sum(item.wire_length() for item in self)


class VariableLengthList[T: DataWireProtocol](List[T]):
    _maxsize_: ClassVar[int] = NotImplemented
    _sizelen_: ClassVar[int] = NotImplemented

    def __init_subclass__(cls, *, maxsize: int = NotImplemented, **kw: Any) -> None:  # noqa: ANN401
        if maxsize is not NotImplemented:
            cls._maxsize_ = maxsize
            cls._sizelen_ = byte_length(maxsize)
        super().__init_subclass__(**kw)

    def __init__(self, iterable: Iterable[T] = (), /) -> None:
        if self._sizelen_ is NotImplemented:
            raise TypeError(f'Cannot instantiate abstract variable length list {self.__class__.__qualname__!r} that does not define its max size')
        super().__init__(iterable)

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if cls._sizelen_ is NotImplemented:
            raise TypeError(f'Cannot instantiate abstract variable length list {cls.__qualname__!r} that does not define its max size')
        if not isinstance(buffer, BytesIO):
            buffer = BytesIO(buffer)
        size_data = buffer.read(cls._sizelen_)
        if len(size_data) < cls._sizelen_:
            raise ValueError(f'Insufficient data in buffer to extract list length for {cls.__qualname__!r}')
        data_size = int.from_bytes(size_data, byteorder='big')
        list_data = buffer.read(data_size)
        if len(list_data) < data_size:
            raise ValueError(f'Insufficient data in buffer to extract list values for {cls.__qualname__!r}')
        return super().from_wire(list_data)

    def to_wire(self) -> bytes:
        return super().wire_length().to_bytes(self._sizelen_, byteorder='big') + super().to_wire()

    def wire_length(self) -> int:
        return self._sizelen_ + super().wire_length()


def make_list_type[T: DataWireProtocol](item_type: type[T], *, custom_repr: bool = True) -> type[List[T]]:
    return new_class(f'{item_type.__name__}List', (List[item_type],), kwds={'custom_repr': custom_repr})  # type: ignore[valid-type]


def make_variable_length_list_type[T: DataWireProtocol](item_type: type[T], /, *, maxsize: int, custom_repr: bool = True) -> type[VariableLengthList[T]]:
    return new_class(f'{item_type.__name__}List', (VariableLengthList[item_type],), kwds={'maxsize': maxsize, 'custom_repr': custom_repr})  # type: ignore[valid-type]
