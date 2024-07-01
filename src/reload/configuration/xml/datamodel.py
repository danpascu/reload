# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from binascii import a2b_base64 as base64decode
from binascii import a2b_hex as hexdecode
from binascii import b2a_base64 as base64encode
from binascii import b2a_hex as hexencode
from collections.abc import MutableMapping
from datetime import UTC, datetime
from math import inf
from typing import ClassVar, Protocol, Self, runtime_checkable

__all__ = (  # noqa: RUF022
    'DataConverter',
    'DataAdapter',
    'AdapterRegistry',

    'Base64BinaryAdapter',
    'HexBinaryAdapter',

    'BooleanAdapter',
    'DatetimeAdapter',

    'IntegerAdapter',
    'PositiveIntegerAdapter',
    'NegativeIntegerAdapter',
    'NonNegativeIntegerAdapter',
    'NonPositiveIntegerAdapter',
    'ByteAdapter',
    'ShortAdapter',
    'IntAdapter',
    'LongAdapter',
    'UnsignedByteAdapter',
    'UnsignedShortAdapter',
    'UnsignedIntAdapter',
    'UnsignedLongAdapter',
    'Int8Adapter',
    'Int16Adapter',
    'Int32Adapter',
    'Int64Adapter',
    'UInt8Adapter',
    'UInt16Adapter',
    'UInt32Adapter',
    'UInt64Adapter',
)


@runtime_checkable
class DataConverter(Protocol):
    """A protocol that describes how a data type converts between itself and XML"""

    @classmethod
    def xml_parse(cls, value: str) -> Self:
        """Parse XML into the data type"""
        ...

    def xml_build(self: Self) -> str:
        """Build XML from the data type"""
        ...


@runtime_checkable
class DataAdapter[T](Protocol):
    """A protocol that describes an external adapter between a data type T and XML"""

    @staticmethod
    def xml_parse(value: str, /) -> T:
        """Parse XML into the data type"""
        ...

    @staticmethod
    def xml_build(value: T, /) -> str:
        """Build XML from the data type"""
        ...


class AdapterRegistry[T]:
    _adapters: ClassVar[MutableMapping[type, type[DataAdapter]]] = {}

    @classmethod
    def associate(cls, data_type: type[T], adapter: type[DataAdapter[T]]) -> None:
        if issubclass(data_type, DataConverter):
            raise TypeError('Adapters for types that already support the DataConverter protocol must be explicitly provided with the attribute/element descriptors.')
        cls._adapters[data_type] = adapter

    @classmethod
    def get_adapter(cls, data_type: type[T]) -> type[DataAdapter[T]] | None:
        return cls._adapters.get(data_type, None)


class Base64BinaryAdapter:
    @staticmethod
    def xml_parse(value: str) -> bytes:
        return base64decode(value)

    @staticmethod
    def xml_build(value: bytes) -> str:
        return base64encode(value, newline=False).decode('ascii')


class HexBinaryAdapter:
    @staticmethod
    def xml_parse(value: str) -> bytes:
        return hexdecode(value)

    @staticmethod
    def xml_build(value: bytes) -> str:
        return hexencode(value).decode('ascii')


class BooleanAdapter:
    @staticmethod
    def xml_parse(value: str) -> bool:
        match value.strip():
            case 'true' | '1':
                return True
            case 'false' | '0':
                return False
            case _:
                raise ValueError(f'Invalid boolean value: {value!r}')

    @staticmethod
    def xml_build(value: bool) -> str:  # noqa: FBT001
        return 'true' if value else 'false'


class DatetimeAdapter:
    @staticmethod
    def xml_parse(value: str) -> datetime:
        return datetime.fromisoformat(value).astimezone(UTC)

    @staticmethod
    def xml_build(value: datetime) -> str:
        return value.astimezone(UTC).isoformat()


AdapterRegistry.associate(bool, BooleanAdapter)
AdapterRegistry.associate(bytes, Base64BinaryAdapter)
AdapterRegistry.associate(datetime, DatetimeAdapter)


class IntegerAdapter:
    def __init_subclass__(cls, *, min_value: int | None = None, max_value: int | None = None, name: str = 'integer', bits: int | None = None, unsigned: bool = False, **kw: object) -> None:
        super().__init_subclass__(**kw)

        # Subclasses should specify either min_value/max_value/name or bits/unsigned.
        # When bits is specified it overwrites the name and boundaries with computed values.

        lower_bound: int | float
        upper_bound: int | float

        if bits is not None:
            if bits <= 0:
                raise ValueError('when specified, bits must be a positive integer')
            name = f'{"unsigned" if unsigned else "signed"} {bits}-bit integer'
            offset: int = 0 if unsigned else 2 ** (bits - 1)
            lower_bound = 0 - offset
            upper_bound = 2**bits - 1 - offset
        else:
            lower_bound = min_value if min_value is not None else -inf
            upper_bound = max_value if max_value is not None else +inf

        def xml_parse(value: str) -> int:
            number = int(value)
            if lower_bound <= number <= upper_bound:
                return number
            raise ValueError(f"invalid value '{value}' for {name}")

        def xml_build(value: int) -> str:
            if lower_bound <= value <= upper_bound:
                return str(value)
            raise ValueError(f"invalid value '{value}' for {name}")

        cls.xml_parse = staticmethod(xml_parse)  # type: ignore[method-assign]
        cls.xml_build = staticmethod(xml_build)  # type: ignore[method-assign]

    @staticmethod
    def xml_parse(value: str) -> int:
        return int(value)

    @staticmethod
    def xml_build(value: int) -> str:
        return str(value)


class PositiveIntegerAdapter(IntegerAdapter, min_value=+1, name='positive integer'):
    pass


class NegativeIntegerAdapter(IntegerAdapter, max_value=-1, name='negative integer'):
    pass


class NonNegativeIntegerAdapter(IntegerAdapter, min_value=0, name='non-negative integer'):
    pass


class NonPositiveIntegerAdapter(IntegerAdapter, max_value=0, name='non-positive integer'):
    pass


class ByteAdapter(IntegerAdapter, bits=8):
    pass


class ShortAdapter(IntegerAdapter, bits=16):
    pass


class IntAdapter(IntegerAdapter, bits=32):
    pass


class LongAdapter(IntegerAdapter, bits=64):
    pass


class UnsignedByteAdapter(IntegerAdapter, bits=8, unsigned=True):
    pass


class UnsignedShortAdapter(IntegerAdapter, bits=16, unsigned=True):
    pass


class UnsignedIntAdapter(IntegerAdapter, bits=32, unsigned=True):
    pass


class UnsignedLongAdapter(IntegerAdapter, bits=64, unsigned=True):
    pass


# Alternative definitions with more descriptive names

class Int8Adapter(IntegerAdapter, bits=8):
    pass


class Int16Adapter(IntegerAdapter, bits=16):
    pass


class Int32Adapter(IntegerAdapter, bits=32):
    pass


class Int64Adapter(IntegerAdapter, bits=64):
    pass


class UInt8Adapter(IntegerAdapter, bits=8, unsigned=True):
    pass


class UInt16Adapter(IntegerAdapter, bits=16, unsigned=True):
    pass


class UInt32Adapter(IntegerAdapter, bits=32, unsigned=True):
    pass


class UInt64Adapter(IntegerAdapter, bits=64, unsigned=True):
    pass
