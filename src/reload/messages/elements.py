# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from functools import reduce
from inspect import Parameter, Signature
from io import BytesIO
from itertools import chain
from operator import or_
from types import NoneType, UnionType, new_class
from typing import ClassVar, Self, cast, dataclass_transform, overload

from .datamodel import AdapterRegistry, DataWireAdapter, DataWireProtocol, List, NoLength, Opaque, UnsignedInteger, WireData, make_list_type, make_variable_length_list_type

__all__ = 'AnnotatedStructure', 'Structure', 'Element', 'LinkedElement', 'LinkedElementSpecification', 'ListElement'  # noqa: RUF022


class Structure:  # noqa: PLW1641
    __signature__: ClassVar[Signature] = Signature()

    _fields_: ClassVar[dict[str, 'FieldDescriptor']] = {}

    _all_arguments: ClassVar[frozenset[str]]
    _mandatory_arguments: ClassVar[frozenset[str]]
    _default_arguments: ClassVar[dict[str, object]]

    def __new__(cls, **kw: object) -> Self:
        if not cls._all_arguments.issuperset(kw):
            raise TypeError(f'Got an unexpected keyword argument {next(iter(set(kw) - cls._all_arguments))!r}')
        if not cls._mandatory_arguments.issubset(kw):
            raise TypeError(f'Missing a required keyword argument {next(iter(cls._mandatory_arguments - set(kw)))!r}')
        return super().__new__(cls)

    def __init__(self, **kw: object) -> None:
        # Fields need to be set in the order they were defined (there may be
        # linked elements that depend on previous elements), but **kw can be
        # provided in any order.
        kw = self._default_arguments | kw
        for name in self._fields_:
            setattr(self, name, kw[name])

    def __init_subclass__(cls, **kw: object) -> None:
        super().__init_subclass__(**kw)

        # all the fields on this element (both inherited and locally defined)
        fields = cls._fields_ | {name: value for name, value in cls.__dict__.items() if isinstance(value, FieldDescriptor)}

        cls._fields_ = fields

        cls.__signature__ = Signature(parameters=[descriptor.signature_parameter for descriptor in fields.values()])
        cls._all_arguments = frozenset(cls.__signature__.parameters)
        cls._mandatory_arguments = frozenset(p.name for p in cls.__signature__.parameters.values() if p.default is Parameter.empty)
        cls._default_arguments = {p.name: p.default for p in cls.__signature__.parameters.values() if p.default is not Parameter.empty}

    def __repr__(self) -> str:
        return f'{self.__class__.__qualname__}({', '.join(f'{name}={_reprproxy(getattr(self, name))!r}' for name in self._fields_)})'

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Structure):
            return all(getattr(self, name) == getattr(other, name) for name in self._fields_)
        return NotImplemented

    @classmethod
    def from_wire(cls, buffer: WireData) -> Self:
        if not isinstance(buffer, BytesIO):
            buffer = BytesIO(buffer)
        instance = super().__new__(cls)
        for field in cls._fields_.values():
            field.from_wire(instance, buffer)
        return instance

    def to_wire(self) -> bytes:
        return b''.join(field.to_wire(self) for field in self._fields_.values())

    def wire_length(self) -> int:
        return sum(field.wire_length(self) for field in self._fields_.values())


type DataWireAdapterType[T] = type[DataWireAdapter[T]]


# Field descriptor specifications

class FieldDescriptor(ABC):
    name: str | None

    @property
    @abstractmethod
    def signature_parameter(self) -> Parameter: ...

    @abstractmethod
    def from_wire(self, instance: Structure, buffer: WireData) -> None: ...

    @abstractmethod
    def to_wire(self, instance: Structure) -> bytes: ...

    @abstractmethod
    def wire_length(self, instance: Structure) -> int: ...


class ElementDescriptor[T](FieldDescriptor):
    name: str | None
    type: type[T] | UnionType
    default: T
    adapter: DataWireAdapterType[T]

    @property
    def signature_parameter(self) -> Parameter:
        assert self.name is not None  # noqa: S101 (used by type checkers)
        kwds = {} if self.default is NotImplemented else {'default': self.default}
        return Parameter(name=self.name, kind=Parameter.KEYWORD_ONLY, annotation=self.type, **kwds)


class LinkedElementDescriptor[T, U](FieldDescriptor):
    name: str | None
    linked_field: ElementDescriptor[U]
    type_map: Mapping[U, type[T]]
    fallback_type: type[T] | None
    length_type: type[UnsignedInteger]
    default: T

    @property
    def signature_parameter(self) -> Parameter:
        assert self.name is not None  # noqa: S101 (used by type checkers)
        kwds = {} if self.default is NotImplemented else {'default': self.default}
        annotation = reduce(or_, chain(self.type_map.values(), [self.fallback_type] if self.fallback_type is not None else []))
        return Parameter(name=self.name, kind=Parameter.KEYWORD_ONLY, annotation=annotation, **kwds)


class ListElementDescriptor[T: DataWireProtocol](FieldDescriptor):
    name: str | None
    maxsize: int | None
    default: Sequence[T]
    item_type: type[T]
    list_type: type[List[T]]

    @property
    def signature_parameter(self) -> Parameter:
        assert self.name is not None  # noqa: S101 (used by type checkers)
        kwds = {} if self.default is NotImplemented else {'default': self.default}
        return Parameter(name=self.name, kind=Parameter.KEYWORD_ONLY, annotation=list[self.item_type], **kwds)  # type: ignore[name-defined]


# Helpers

class _reprproxy:  # noqa: N801
    # Provide better representation for certain types which can be evaluated to recreate the object.

    def __init__(self, value: object) -> None:
        self.value = value

    def __repr__(self) -> str:
        match self.value:
            case Enum() as value:  # this also covers Flag which is a subclass of Enum
                return f'{value.__class__.__qualname__}.{value.name}'
            case UnionType() as value:
                return ' | '.join('None' if _type is NoneType else _type.__qualname__ for _type in value.__args__)
            case type() as value:
                return value.__qualname__
            case value:
                return repr(value)

    __str__ = __repr__


def _protocol2adapter[T: DataWireProtocol](proto: type[T]) -> type[DataWireAdapter[T]]:
    # Turn a DataWireProtocol into a DataWireAdapter by creating a stand-in adapter on the fly.
    #
    # This is needed for field descriptors that need to treat DataWireProtocol and DataWireAdapter
    # interchangeably, but adapters have an extra validate() method that protocols don't need.
    # The stand-in adapter adds a no-op validate method that just returns its argument.
    #
    # This stand-in adapter is created mostly as a convenience to avoid if-else handling in the
    # code and to keep type checkers happy.

    def noop_validate(value: T, /) -> T:
        return value

    def prepare(ns: dict) -> None:
        ns['_abstract_'] = False
        ns['from_wire'] = staticmethod(proto.from_wire)
        ns['to_wire'] = staticmethod(proto.to_wire)
        ns['wire_length'] = staticmethod(proto.wire_length)
        ns['validate'] = staticmethod(noop_validate)

    adapter = new_class(f'{proto.__name__}AdapterStandIn', (DataWireAdapter[T],), exec_body=prepare)
    adapter.__module__ = __name__
    adapter.__qualname__ = f'_protocol2adapter.<generated>.{adapter.__name__}'

    return adapter


# Field descriptor implementations

class Element[T](ElementDescriptor[T]):
    @overload
    def __init__(self, element_type: type[T], /, *, default: T = ..., adapter: DataWireAdapterType[T] | None = ...) -> None: ...

    @overload
    def __init__(self, element_type: UnionType, /, *, default: T = ..., adapter: DataWireAdapterType[T]) -> None: ...

    def __init__(self, element_type: type[T] | UnionType, /, *, default: T = NotImplemented, adapter: DataWireAdapterType[T] | None = None) -> None:
        self.name = None
        self.type = element_type
        self.default = default
        self.provided_adapter = adapter
        if adapter is None:
            if isinstance(element_type, UnionType):
                raise TypeError('When the element type is a union of types a composite adapter for the same types must be provided')
            if issubclass(element_type, DataWireProtocol):
                adapter = cast(DataWireAdapterType[T], _protocol2adapter(element_type))
            else:
                adapter = AdapterRegistry.get_adapter(element_type)
        if adapter is None:
            raise TypeError('Either the element type must implement the DataWireProtocol or an adapter must be provided')
        if adapter._abstract_:
            raise TypeError(f'Cannot use abstract adapter {adapter.__qualname__!r} (need to select a concrete implementation of it, usually one that defines its size or value)')
        self.adapter = adapter

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({_reprproxy(self.type)!r}, default={self.default!r}, adapter={_reprproxy(self.provided_adapter)!r})'

    def __set_name__(self, owner: type[Structure], name: str) -> None:
        if self.name is None:
            self.name = name
        elif name != self.name:
            raise TypeError(f'Cannot assign the same {self.__class__.__qualname__!r} to two different names: {self.name!r} and {name!r}')

    @overload
    def __get__(self, instance: None, owner: type[Structure]) -> Self: ...

    @overload
    def __get__(self, instance: Structure, owner: type[Structure] | None = None) -> T: ...

    def __get__(self, instance: Structure | None, owner: type[Structure] | None = None) -> Self | T:
        if instance is None:
            return self
        if self.name is None:
            raise TypeError(f'Cannot use {self.__class__.__qualname__!r} instance without calling __set_name__ on it.')
        try:
            return instance.__dict__[self.name]
        except KeyError as exc:
            raise AttributeError(f'Attribute {self.name!r} of object {instance.__class__.__qualname__!r} is not set') from exc

    def __set__(self, instance: Structure, value: T) -> None:
        if self.name is None:
            raise TypeError(f'Cannot use {self.__class__.__qualname__!r} instance without calling __set_name__ on it.')
        instance.__dict__[self.name] = self.adapter.validate(value)

    def __delete__(self, instance: Structure) -> None:
        raise AttributeError(f'Attribute {self.name!r} of {instance.__class__.__qualname__!r} object cannot be deleted')

    def from_wire(self, instance: Structure, buffer: WireData) -> None:
        if self.name is None:
            raise TypeError(f'Cannot use {self.__class__.__qualname__!r} instance without calling __set_name__ on it.')
        try:
            instance.__dict__[self.name] = self.adapter.from_wire(buffer)
        except ValueError as exc:
            raise ValueError(f'Failed to read the {instance.__class__.__qualname__}.{self.name} element from wire: {exc}') from exc

    def to_wire(self, instance: Structure) -> bytes:
        return self.adapter.to_wire(self.__get__(instance))

    def wire_length(self, instance: Structure) -> int:
        return self.adapter.wire_length(self.__get__(instance))


@dataclass(kw_only=True)
class LinkedElementSpecification[T: DataWireProtocol, U]:
    type_map: Mapping[U, type[T]]
    fallback_type: type[T] | None = None
    length_type: type[UnsignedInteger]
    check_length: bool = False

    def __post_init__(self) -> None:
        if self.length_type._size_ is NotImplemented:
            raise TypeError('The length type cannot be an abstract UnsignedInteger type that does not define its size')
        if self.length_type is NoLength:
            if not self.type_map:
                raise TypeError(f'A {self.__class__.__qualname__!r} that has no length prefix must have a non-empty type_map')
            if self.fallback_type is not None:
                raise TypeError(f'A {self.__class__.__qualname__!r} that has no length prefix must have fallback_type=None')
            if self.check_length:
                raise TypeError(f'A {self.__class__.__qualname__!r} that has no length prefix must have check_length=False')
        elif not self.type_map and self.fallback_type is None:
            raise TypeError(f'A {self.__class__.__qualname__!r} with a length prefix and an empty type_map must specify a fallback type')
        if self.fallback_type is not None:
            if not issubclass(self.fallback_type, Opaque) or self.fallback_type._sizelen_ is NotImplemented:
                raise TypeError('The fallback type should either be None or an Opaque type which defines its size')
            if self.fallback_type._sizelen_ != self.length_type._size_:
                raise TypeError(f'The fallback type size length does not match the length type size ({self.fallback_type._sizelen_} != {self.length_type._size_})')

    def __repr__(self) -> str:
        type_map = {_reprproxy(name): _reprproxy(value) for name, value in self.type_map.items()}
        fallback_type = _reprproxy(self.fallback_type)
        length_type = _reprproxy(self.length_type)
        return f'{self.__class__.__qualname__}({type_map=}, {fallback_type=}, {length_type=}, check_length={self.check_length!r})'


class LinkedElement[T: DataWireProtocol, U](LinkedElementDescriptor[T, U]):
    def __init__(self, *, linked_field: ElementDescriptor[U], specification: LinkedElementSpecification[T, U], default: T = NotImplemented) -> None:
        self.name = None
        self.linked_field = linked_field
        self.specification = specification
        self.default = default
        self.type_map = specification.type_map
        self.fallback_type = specification.fallback_type
        self.length_type = specification.length_type
        self.check_length = specification.check_length

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}(linked_field={self.linked_field.name!s}, specification={self.specification!r}, default={self.default!r})'

    def __set_name__(self, owner: type[Structure], name: str) -> None:
        if self.name is None:
            self.name = name
        elif name != self.name:
            raise TypeError(f'Cannot assign the same {self.__class__.__qualname__!r} to two different names: {self.name!r} and {name!r}')

    @overload
    def __get__(self, instance: None, owner: type[Structure]) -> Self: ...

    @overload
    def __get__(self, instance: Structure, owner: type[Structure] | None = None) -> T: ...

    def __get__(self, instance: Structure | None, owner: type[Structure] | None = None) -> Self | T:
        if instance is None:
            return self
        if self.name is None:
            raise TypeError(f'Cannot use {self.__class__.__qualname__!r} instance without calling __set_name__ on it.')
        try:
            return instance.__dict__[self.name]
        except KeyError as exc:
            raise AttributeError(f'Attribute {self.name!r} of object {instance.__class__.__qualname__!r} is not set') from exc

    def __set__(self, instance: Structure, value: T) -> None:
        if self.name is None or self.linked_field.name is None:
            raise TypeError(f'Cannot use {self.__class__.__qualname__!r} instance without calling __set_name__ on it.')
        try:
            linked_field_value = instance.__dict__[self.linked_field.name]
        except KeyError as exc:
            raise AttributeError(f'Linked attribute {self.linked_field.name!r} of object {instance.__class__.__qualname__!r} is not set') from exc
        element_type = self.type_map.get(linked_field_value, self.fallback_type)
        if element_type is None:
            raise ValueError(f'Cannot find associated type for linked field {self.linked_field.name!r} with value {linked_field_value!r}')
        if not isinstance(value, element_type):
            raise TypeError(f'The value for the {self.name!r} field should be of type {element_type.__qualname__!r}')
        instance.__dict__[self.name] = value

    def __delete__(self, instance: Structure) -> None:
        raise AttributeError(f'Attribute {self.name!r} of {instance.__class__.__qualname__!r} object cannot be deleted')

    def from_wire(self, instance: Structure, buffer: WireData) -> None:
        if self.name is None or self.linked_field.name is None:
            raise TypeError(f'Cannot use {self.__class__.__qualname__!r} instance without calling __set_name__ on it.')

        try:
            linked_field_value = instance.__dict__[self.linked_field.name]
        except KeyError as exc:
            raise AttributeError(f'Linked attribute {self.linked_field.name!r} of object {instance.__class__.__qualname__!r} is not set') from exc

        element_type = self.type_map.get(linked_field_value, None)

        if element_type is not None:
            if not isinstance(buffer, BytesIO):
                buffer = BytesIO(buffer)

            length_data = buffer.read(self.length_type._size_)
            if len(length_data) < self.length_type._size_:
                raise ValueError(f'Insufficient data in buffer to get the length for the {instance.__class__.__qualname__}.{self.name} element')

            if self.check_length:
                length = self.length_type.from_wire(length_data)
                element_data = buffer.read(length)
                if len(element_data) < length:
                    raise ValueError(f'Insufficient data in buffer to get the {instance.__class__.__qualname__}.{self.name} element')
            else:
                element_data = buffer  # When check_length is False, it means the element knows its size and doesn't need the length to parse itself.
        else:
            if self.fallback_type is None:
                raise ValueError(f'Cannot find associated type for linked field {instance.__class__.__qualname__}.{self.linked_field.name} with value {linked_field_value!r}')
            element_type = self.fallback_type
            element_data = buffer  # The fallback type handles the length field internally

        try:
            instance.__dict__[self.name] = element_type.from_wire(element_data)
        except ValueError as exc:
            raise ValueError(f'Failed to read the {instance.__class__.__qualname__}.{self.name} element from wire: {exc}') from exc

    def to_wire(self, instance: Structure) -> bytes:
        # By using self.__get__(instance) we make sure that the element value was properly set, which also
        # implies that self.name and self.linked_field.name are not None and the linked field is also set.
        value = self.__get__(instance)
        assert self.linked_field.name is not None  # noqa: S101 (used by type checkers)
        linked_field_value = instance.__dict__[self.linked_field.name]
        if linked_field_value in self.type_map:
            return self.length_type(value.wire_length()).to_wire() + value.to_wire()
        return value.to_wire()

    def wire_length(self, instance: Structure) -> int:
        # By using self.__get__(instance) we make sure that the element value was properly set, which also
        # implies that self.name and self.linked_field.name are not None and the linked field is also set.
        value = self.__get__(instance)
        assert self.linked_field.name is not None  # noqa: S101 (used by type checkers)
        linked_field_value = instance.__dict__[self.linked_field.name]
        if linked_field_value in self.type_map:
            return self.length_type._size_ + value.wire_length()
        return value.wire_length()


class ListElement[T: DataWireProtocol](ListElementDescriptor[T]):
    def __init__(self, item_type: type[T], /, *, default: Sequence[T] = NotImplemented, maxsize: int | None = None) -> None:
        self.name = None
        self.default = default
        self.maxsize = maxsize
        self.item_type = item_type
        if maxsize is not None:
            self.list_type = make_variable_length_list_type(item_type, maxsize=maxsize, custom_repr=False)
        else:
            self.list_type = make_list_type(item_type, custom_repr=False)

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.item_type.__qualname__}, default={self.default!r}, maxsize={self.maxsize!r})'

    def __set_name__(self, owner: type[Structure], name: str) -> None:
        if self.name is None:
            self.name = name
        elif name != self.name:
            raise TypeError(f'Cannot assign the same {self.__class__.__qualname__!r} to two different names: {self.name!r} and {name!r}')

    @overload
    def __get__(self, instance: None, owner: type[Structure]) -> Self: ...

    @overload
    def __get__(self, instance: Structure, owner: type[Structure] | None = None) -> List[T]: ...

    def __get__(self, instance: Structure | None, owner: type[Structure] | None = None) -> Self | List[T]:
        if instance is None:
            return self
        if self.name is None:
            raise TypeError(f'Cannot use {self.__class__.__qualname__!r} instance without calling __set_name__ on it.')
        try:
            return instance.__dict__[self.name]
        except KeyError as exc:
            raise AttributeError(f'Attribute {self.name!r} of object {instance.__class__.__qualname__!r} is not set') from exc

    def __set__(self, instance: Structure, value: Sequence[T]) -> None:
        if self.name is None:
            raise TypeError(f'Cannot use {self.__class__.__qualname__!r} instance without calling __set_name__ on it.')
        instance.__dict__[self.name] = self.list_type(value)

    def __delete__(self, instance: Structure) -> None:
        raise AttributeError(f'Attribute {self.name!r} of {instance.__class__.__qualname__!r} object cannot be deleted')

    def from_wire(self, instance: Structure, buffer: WireData) -> None:
        if self.name is None:
            raise TypeError(f'Cannot use {self.__class__.__qualname__!r} instance without calling __set_name__ on it.')
        try:
            instance.__dict__[self.name] = self.list_type.from_wire(buffer)
        except ValueError as exc:
            raise ValueError(f'Failed to read the {instance.__class__.__qualname__}.{self.name} element from wire: {exc}') from exc

    def to_wire(self, instance: Structure) -> bytes:
        return self.__get__(instance).to_wire()

    def wire_length(self, instance: Structure) -> int:
        return self.__get__(instance).wire_length()


@dataclass_transform(kw_only_default=True, field_specifiers=(Element, LinkedElement, ListElement))
class AnnotatedStructure(Structure):
    pass
