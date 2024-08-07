# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Iterator, MutableMapping
from copy import copy
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from inspect import Parameter, Signature
from pathlib import Path
from typing import ClassVar, Protocol, Self, cast, dataclass_transform, overload

from lxml import etree

from reload.python.weakref import defaultweakobjectmap, weakobjectmap

from .datamodel import AdapterRegistry, DataAdapter, DataConverter

__all__ = (  # noqa: RUF022
    'Namespace',

    'XMLElement',
    'AnnotatedXMLElement',

    'Attribute',
    'OptionalAttribute',

    'Element',
    'OptionalElement',
    'MultiElement',

    'DataElement',
    'OptionalDataElement',
    'MultiDataElement',

    'TextValue',
)


type ETreeElement = etree._Element  # noqa: SLF001
type NSMap = dict[str | None, str]
type XMLData = str | bytes | int | float | Decimal | bool | datetime | DataConverter
type DataAdapterType[T] = type[DataAdapter[T]]

NoneType = type(None)  # this one is used at runtime, so it cannot be a type alias


class Namespace(str):
    __slots__ = 'prefix', 'schema'

    prefix: str | None
    schema: str | None

    def __new__(cls, namespace: str, /, *, prefix: str | None = None, schema: str | None = None) -> Self:
        self = super().__new__(cls, namespace)
        self.prefix = prefix
        self.schema = schema
        return self

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({super().__repr__()}, prefix={self.prefix!r}, schema={self.schema!r})'

    def __setattr__(self, name: str, value: object, /) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError(f'{self.__class__.__name__} object attribute {name!r} is read-only')
        return super().__setattr__(name, value)


class XMLElement:
    # Public attributes. These can either be overwritten by subclasses, or preferably specified via class parameters:
    #
    # class MyElement(XMLElement, name=..., namespace=...):
    #     ...
    #
    # Note that class parameters use normal names, while class attributes use sunder names to avoid conflicts with
    # application defined attributes and elements.

    _name_: ClassVar[str | None] = None
    _namespace_: ClassVar[Namespace | None] = None

    # Derived and internal attributes (these should not be overwritten in subclasses)

    _etree_element_: ETreeElement

    _tag_: ClassVar[str | None] = None
    _qualname_: ClassVar[str | None] = None
    _xpath_: ClassVar[etree.XPath | None] = None

    _fields_: ClassVar[dict[str, 'FieldDescriptor']] = {}
    _associated_namespaces_: ClassVar[set[Namespace]] = set()  # all the namespaces associated with this element and its subelements
    _nsmap_: ClassVar[NSMap | None] = None

    __signature__: ClassVar[Signature] = Signature()

    _all_arguments: ClassVar[frozenset[str]]
    _mandatory_arguments: ClassVar[frozenset[str]]

    def __new__(cls, **kw: object) -> Self:
        if cls._tag_ is None:
            raise TypeError(f'Cannot instantiate abstract class {cls.__qualname__!r} that does not specify a name and namespace')
        if not cls._all_arguments.issuperset(kw):
            raise TypeError(f'got an unexpected keyword argument {next(iter(set(kw) - cls._all_arguments))!r}')
        if not cls._mandatory_arguments.issubset(kw):
            raise TypeError(f'missing a required keyword argument {next(iter(cls._mandatory_arguments - set(kw)))!r}')
        return super().__new__(cls)

    def __init__(self, **kw: object) -> None:
        self._etree_element_ = etree.Element(self._tag_, nsmap=self._nsmap_)  # type: ignore[arg-type]  # lxml stubs are a mess
        for name, value in kw.items():
            setattr(self, name, value)

    def __init_subclass__(cls, name: str | None = None, namespace: Namespace | None = None, **kw: object) -> None:
        super().__init_subclass__(**kw)

        if name is not None:
            if '_name_' in cls.__dict__ and cls._name_ != name:
                raise TypeError(f'The name specified via class parameter and the "_name_" class attribute are different ({name!r} != {cls._name_!r})')
            cls._name_ = name
        if namespace is not None:
            if '_namespace_' in cls.__dict__ and cls._namespace_ != namespace:
                raise TypeError(f'The namespace specified via class parameter and the "_namespace_" class attribute are different ({namespace!r} != {cls._namespace_!r})')
            cls._namespace_ = namespace

        if cls._name_ is not None:
            if cls._namespace_ is not None:
                cls._tag_ = f'{{{cls._namespace_}}}{cls._name_}'
                cls._qualname_ = f'{cls._namespace_.prefix}:{cls._name_}' if cls._namespace_.prefix is not None else cls._name_
                cls._xpath_ = etree.XPath(f'ns:{cls._name_}', namespaces={'ns': cls._namespace_})
            else:
                cls._tag_ = cls._name_
                cls._qualname_ = cls._name_
                cls._xpath_ = etree.XPath(cls._name_)

        # all the fields on this element (both inherited and locally defined)
        fields = cls._fields_ | {name: value for name, value in cls.__dict__.items() if isinstance(value, FieldDescriptor)}

        # all the namespaces associated with this element and its subelements
        namespaces = {cls._namespace_} if cls._namespace_ is not None else set()
        namespaces.update(*(field.type._associated_namespaces_ for field in fields.values() if issubclass(field.type, XMLElement)))
        namespaces.update(field.xml_namespace for field in fields.values() if isinstance(field, DataElementDescriptor) and field.xml_namespace is not None)

        cls._fields_ = fields
        cls._associated_namespaces_ = namespaces
        cls._nsmap_ = {ns.prefix: ns for ns in sorted(namespaces)} if namespaces else None

        cls.__signature__ = Signature(parameters=[descriptor.signature_parameter for descriptor in fields.values()])
        cls._all_arguments = frozenset(cls.__signature__.parameters)
        cls._mandatory_arguments = frozenset(p.name for p in cls.__signature__.parameters.values() if p.default is Parameter.empty)

    def __del__(self) -> None:
        self._etree_element_.clear()

    def __bytes__(self) -> bytes:
        return self.to_string()

    def __str__(self) -> str:
        return self.to_string(encoding=None)

    @classmethod
    def from_file(cls, path: str | Path) -> Self:
        if isinstance(path, str):
            path = Path(path)
        return cls.from_string(path.read_bytes())

    @classmethod
    def from_string(cls, data: str | bytes) -> Self:
        return cls.from_xml(etree.XML(data))

    @classmethod
    def from_xml(cls, element: ETreeElement) -> Self:
        if cls._tag_ is None:
            raise TypeError(f'Cannot instantiate abstract class {cls.__qualname__} that does not specify a name and namespace')
        if element.tag != cls._tag_:
            raise TypeError(f'The etree element tag does not match the {cls.__qualname__} element tag: {element.tag!r} != {cls._tag_!r}')
        instance = super().__new__(cls)
        instance._etree_element_ = element
        for field in instance._fields_.values():
            field.from_xml(instance)
        return instance

    def to_file(self, path: str | Path, *, encoding: str = 'UTF-8') -> None:
        if isinstance(path, str):
            path = Path(path)
        path.write_bytes(self.to_string(encoding=encoding))

    @overload
    def to_string(self, *, encoding: None, pretty: bool = ..., xml_declaration: bool = ...) -> str: ...

    @overload
    def to_string(self, *, encoding: str = 'UTF-8', pretty: bool = ..., xml_declaration: bool = ...) -> bytes: ...

    def to_string(self, *, encoding: str | None = 'UTF-8', pretty: bool = True, xml_declaration: bool = True) -> bytes | str:
        if encoding is None:
            encoding = 'unicode'
            xml_declaration = False
        return etree.tostring(self._etree_element_, encoding=encoding, pretty_print=pretty, xml_declaration=xml_declaration)

    def to_xml(self) -> ETreeElement:
        return copy(self._etree_element_)


class FieldDescriptor[F](ABC):
    name: str | None
    type: type[F]

    @property
    def signature_parameter(self) -> Parameter:
        assert self.name is not None  # noqa: S101 (used by type checkers)
        return Parameter(name=self.name, kind=Parameter.KEYWORD_ONLY, annotation=self.type)

    @abstractmethod
    def from_xml(self, instance: XMLElement) -> None:
        """Fill in the instance's field value from its corresponding etree element"""
        raise NotImplementedError


class AttributeDescriptor[D: XMLData](FieldDescriptor[D]):
    name: str | None
    type: type[D]

    xml_name: str
    xml_build: Callable[[D], str]
    xml_parse: Callable[[str], D]

    adapter: DataAdapterType[D] | None

    @property
    def signature_parameter(self) -> Parameter:
        assert self.name is not None  # noqa: S101 (used by type checkers)
        return Parameter(name=self.name, kind=Parameter.KEYWORD_ONLY, annotation=self.type)


class OptionalAttributeDescriptor[D: XMLData](AttributeDescriptor[D]):
    default: D | None

    @property
    def signature_parameter(self) -> Parameter:
        assert self.name is not None  # noqa: S101 (used by type checkers)
        return Parameter(name=self.name, kind=Parameter.KEYWORD_ONLY, annotation=self.type | None, default=self.default)


class ElementDescriptor[E: XMLElement](FieldDescriptor[E]):
    name: str | None
    type: type[E]

    @property
    def signature_parameter(self) -> Parameter:
        assert self.name is not None  # noqa: S101 (used by type checkers)
        return Parameter(name=self.name, kind=Parameter.KEYWORD_ONLY, annotation=self.type)


class OptionalElementDescriptor[E: XMLElement](ElementDescriptor[E]):
    @property
    def signature_parameter(self) -> Parameter:
        assert self.name is not None  # noqa: S101 (used by type checkers)
        return Parameter(name=self.name, kind=Parameter.KEYWORD_ONLY, annotation=self.type | None, default=None)


class MultiElementDescriptor[E: XMLElement](ElementDescriptor[E]):
    optional: bool

    @property
    def signature_parameter(self) -> Parameter:
        assert self.name is not None  # noqa: S101 (used by type checkers)
        return Parameter(name=self.name, kind=Parameter.KEYWORD_ONLY, annotation=Iterable[self.type], default=() if self.optional else Parameter.empty)  # type: ignore[name-defined]


class DataElementDescriptor[D: XMLData](FieldDescriptor[D]):
    name: str | None
    type: type[D]

    xml_name: str
    xml_namespace: Namespace | None

    xml_tag: str
    xml_qualname: str

    xml_build: Callable[[D], str]
    xml_parse: Callable[[str], D]

    adapter: DataAdapterType[D] | None

    @property
    def signature_parameter(self) -> Parameter:
        assert self.name is not None  # noqa: S101 (used by type checkers)
        return Parameter(name=self.name, kind=Parameter.KEYWORD_ONLY, annotation=self.type)


class OptionalDataElementDescriptor[D: XMLData](DataElementDescriptor[D]):
    default: D | None

    @property
    def signature_parameter(self) -> Parameter:
        assert self.name is not None  # noqa: S101 (used by type checkers)
        return Parameter(name=self.name, kind=Parameter.KEYWORD_ONLY, annotation=self.type | None, default=self.default)


class MultiDataElementDescriptor[D: XMLData](DataElementDescriptor[D]):
    optional: bool

    @property
    def signature_parameter(self) -> Parameter:
        assert self.name is not None  # noqa: S101 (used by type checkers)
        return Parameter(name=self.name, kind=Parameter.KEYWORD_ONLY, annotation=Iterable[self.type], default=() if self.optional else Parameter.empty)  # type: ignore[name-defined]


@dataclass
class DataElementValue[D: XMLData]:  # noqa: PLW1641
    value: D
    element: ETreeElement

    def __eq__(self, other: object) -> bool:
        if isinstance(other, DataElementValue):
            return self.value == other.value
        else:  # noqa: RET505
            return self.value == other


class ElementList[E: XMLElement]:  # noqa: PLW1641
    __slots__ = '_descriptor', '_elements', '_instance'

    def __init__(self, descriptor: MultiElementDescriptor[E], instance: XMLElement, elements: list[E]) -> None:
        self._descriptor = descriptor
        self._instance = instance
        self._elements = elements

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}[{self._descriptor.type.__qualname__}, optional={self._descriptor.optional!r}]: {self._elements!r}'

    def __contains__(self, item: E) -> bool:
        return type(item) is self._descriptor.type and item._etree_element_ in self._instance._etree_element_

    def __iter__(self) -> Iterator[E]:
        return iter(self._elements)

    def __len__(self) -> int:
        return len(self._elements)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ElementList):
            return self._elements == other._elements
        else:  # noqa: RET505
            return self._elements == other

    @overload
    def __getitem__(self, key: int) -> E: ...

    @overload
    def __getitem__(self, key: slice) -> list[E]: ...

    def __getitem__(self, key: int | slice) -> E | list[E]:
        return self._elements[key]

    def __delitem__(self, key: int | slice) -> None:
        deleted_elements = self._elements[key] if isinstance(key, slice) else [self._elements[key]]
        if not self._descriptor.optional and len(deleted_elements) == len(self._elements):
            raise ValueError(f'the {self._descriptor.name!r} element must have at least one item')
        del self._elements[key]
        parent_element = self._instance._etree_element_
        for element in deleted_elements:
            parent_element.remove(element._etree_element_)

    def __iadd__(self, other: Iterable[E]) -> Self:
        for element in other:
            self.add(element)
        return self

    def index(self, item: E) -> int:
        # find item by identity not equality
        elements = self._elements
        offset = 0
        while True:
            index = elements.index(item, offset)
            if elements[index] is item:
                return index
            offset = index + 1

    def add(self, element: E) -> None:
        if type(element) is not self._descriptor.type:
            raise TypeError(f'element must be of type {self._descriptor.type.__qualname__}')
        if element._etree_element_ in self._instance._etree_element_:
            return
        if element._etree_element_.getparent() is not None:
            raise ValueError(f'element {element!r} already belongs to another container')
        self._elements.append(element)
        if len(self._elements) > 1:
            self._elements[-2]._etree_element_.addnext(element._etree_element_)  # add as next sibling of the previous element
        else:
            self._instance._etree_element_.append(element._etree_element_)  # NOTE @dan: find insertion point

    def remove(self, element: E) -> None:
        if type(element) is not self._descriptor.type:
            raise ValueError(f'{element!r} is not in {self.__class__.__name__}')
        if not self._descriptor.optional and len(self._elements) == 1 and self._elements[0] is element:
            raise ValueError(f'the {self._descriptor.name!r} element must have at least one item')
        self._elements.pop(self.index(element))
        self._instance._etree_element_.remove(element._etree_element_)

    def clear(self) -> None:
        if not self._descriptor.optional:
            raise ValueError(f'the {self._descriptor.name!r} element must have at least one item')
        parent_element = self._instance._etree_element_
        for element in self._elements:
            parent_element.remove(element._etree_element_)
        self._elements.clear()


class DataElementList[D: XMLData]:  # noqa: PLW1641
    __slots__ = '_descriptor', '_elements', '_instance'

    def __init__(self, descriptor: MultiDataElementDescriptor[D], instance: XMLElement, elements: list[DataElementValue[D]]) -> None:
        self._descriptor = descriptor
        self._instance = instance
        self._elements = elements

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}[{self._descriptor.type.__qualname__}, optional={self._descriptor.optional!r}]: {[e.value for e in self._elements]!r}'

    def __contains__(self, item: D) -> bool:
        return item in self._elements

    def __iter__(self) -> Iterator[D]:
        return (e.value for e in self._elements)

    def __len__(self) -> int:
        return len(self._elements)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, DataElementList):
            return self._elements == other._elements
        else:  # noqa: RET505
            return self._elements == other

    @overload
    def __getitem__(self, key: int) -> D: ...

    @overload
    def __getitem__(self, key: slice) -> list[D]: ...

    def __getitem__(self, key: int | slice) -> D | list[D]:
        if isinstance(key, slice):
            return [e.value for e in self._elements[key]]
        else:  # noqa: RET505
            return self._elements[key].value

    def __delitem__(self, key: int | slice) -> None:
        deleted_elements = self._elements[key] if isinstance(key, slice) else [self._elements[key]]
        if not self._descriptor.optional and len(self._elements) == len(deleted_elements):
            raise ValueError(f'the {self._descriptor.name!r} element must have at least one item')
        del self._elements[key]
        parent_element = self._instance._etree_element_
        for data_element in deleted_elements:
            parent_element.remove(data_element.element)

    def __iadd__(self, other: Iterable[D]) -> Self:
        for value in other:
            self.add(value)
        return self

    def index(self, item: D) -> int:
        return self._elements.index(item)  # type: ignore[arg-type]

    def add(self, value: D) -> None:
        if not isinstance(value, self._descriptor.type):
            raise TypeError(f'value must be of type {self._descriptor.type.__qualname__}')
        xml_value = self._descriptor.xml_build(value)
        data_element = DataElementValue(value, etree.Element(self._descriptor.xml_tag))
        data_element.element.text = xml_value
        self._elements.append(data_element)
        if len(self._elements) > 1:
            self._elements[-2].element.addnext(data_element.element)  # add as next sibling of the previous element
        else:
            self._instance._etree_element_.append(data_element.element)  # NOTE @dan: find insertion point

    def remove(self, value: D) -> None:
        if not self._descriptor.optional and len(self._elements) == 1 and self._elements[0].value == value:
            raise ValueError(f'the {self._descriptor.name!r} element must have at least one item')
        try:
            data_element = self._elements.pop(self.index(value))
        except ValueError:
            raise ValueError(f'{value!r} is not in {self.__class__.__name__}') from None
        else:
            self._instance._etree_element_.remove(data_element.element)

    def clear(self) -> None:
        if not self._descriptor.optional:
            raise ValueError(f'the {self._descriptor.name!r} element must have at least one item')
        parent_element = self._instance._etree_element_
        for data_element in self._elements:
            parent_element.remove(data_element.element)
        self._elements.clear()


class Attribute[D: XMLData](AttributeDescriptor[D]):
    def __init__(self, data_type: type[D], /, *, name: str | None = None, adapter: DataAdapterType[D] | None = None) -> None:
        self.name = None
        self.xml_name = name or ''
        self.type = data_type
        self.adapter = adapter

        if adapter is None:
            if issubclass(data_type, DataConverter):
                adapter = cast(DataAdapterType[D], data_type)  # A type that implements the DataConverter protocol is its own DataAdapter
            else:
                adapter = AdapterRegistry.get_adapter(data_type)

        if adapter is not None:
            self.xml_parse = adapter.xml_parse
            self.xml_build = adapter.xml_build
        else:
            assert not issubclass(data_type, bool | bytes | datetime | DataConverter)  # noqa: S101 (used by type checkers)
            self.xml_parse = data_type
            self.xml_build = str

    def __repr__(self) -> str:
        name = self.xml_name if self.xml_name != self.name else None
        adapter_name = self.adapter.__qualname__ if self.adapter else None
        return f'{self.__class__.__name__}({self.type.__qualname__}, {name=}, adapter={adapter_name})'

    def __set_name__(self, owner: type[XMLElement], name: str) -> None:
        if not issubclass(owner, XMLElement):  # static type analysis does not catch this
            raise TypeError(f'Can only use {self.__class__.__qualname__} descriptors on XMLElement objects')
        if self.name is None:
            self.name = name
            self.xml_name = self.xml_name or name
        elif name != self.name:
            raise TypeError(f'cannot assign the same {self.__class__.__name__} descriptor to two different names: {self.name} and {name}')

    @overload
    def __get__(self, instance: None, owner: type[XMLElement]) -> Self: ...

    @overload
    def __get__(self, instance: XMLElement, owner: type[XMLElement] | None = None) -> D: ...

    def __get__(self, instance: XMLElement | None, owner: type[XMLElement] | None = None) -> Self | D:
        if instance is None:
            return self
        try:
            return self.xml_parse(cast(str, instance._etree_element_.attrib[self.xml_name]))
        except KeyError as exc:
            raise AttributeError(f'mandatory attribute {self.name!r} is missing') from exc

    def __set__(self, instance: XMLElement, value: D) -> None:
        if not isinstance(value, self.type):
            raise TypeError(f'the {self.name!r} attribute must be of type {self.type.__qualname__}')
        instance._etree_element_.set(self.xml_name, self.xml_build(value))

    def __delete__(self, instance: XMLElement) -> None:
        raise AttributeError(f'mandatory attribute {self.name!r} cannot be deleted')

    def from_xml(self, instance: XMLElement) -> None:
        """Fill in the instance's field value from its corresponding etree element"""
        try:
            self.__get__(instance)
        except AttributeError as exc:
            match exc.__cause__:
                case KeyError(args=(self.xml_name,)):
                    raise ValueError(f'Missing mandatory attribute {self.xml_name!r} from element {ElementInfo.from_element(instance._etree_element_):l}') from exc
                case _:
                    raise
        except ValueError as exc:
            raise ValueError(f'Invalid value for attribute {self.xml_name!r} from element {ElementInfo.from_element(instance._etree_element_):l}: {exc!s}') from exc


class OptionalAttribute[D: XMLData](OptionalAttributeDescriptor[D]):
    def __init__(self, data_type: type[D], /, *, name: str | None = None, default: D | None = None, adapter: DataAdapterType[D] | None = None) -> None:
        self.name = None
        self.xml_name = name or ''
        self.type = data_type
        self.default = default
        self.adapter = adapter

        if adapter is None:
            if issubclass(data_type, DataConverter):
                adapter = cast(DataAdapterType[D], data_type)  # A type that implements the DataConverter protocol is its own DataAdapter
            else:
                adapter = AdapterRegistry.get_adapter(data_type)

        if adapter is not None:
            self.xml_parse = adapter.xml_parse
            self.xml_build = adapter.xml_build
        else:
            assert not issubclass(data_type, bool | bytes | datetime | DataConverter)  # noqa: S101 (used by type checkers)
            self.xml_parse = data_type
            self.xml_build = str

    def __repr__(self) -> str:
        name = self.xml_name if self.xml_name != self.name else None
        adapter_name = self.adapter.__qualname__ if self.adapter else None
        return f'{self.__class__.__name__}({self.type.__qualname__}, {name=}, default={self.default!r}, adapter={adapter_name})'

    def __set_name__(self, owner: type[XMLElement], name: str) -> None:
        if not issubclass(owner, XMLElement):  # static type analysis does not catch this
            raise TypeError(f'Can only use {self.__class__.__qualname__} descriptors on XMLElement objects')
        if self.name is None:
            self.name = name
            self.xml_name = self.xml_name or name
        elif name != self.name:
            raise TypeError(f'cannot assign the same {self.__class__.__name__} descriptor to two different names: {self.name} and {name}')

    @overload
    def __get__(self, instance: None, owner: type[XMLElement]) -> Self: ...

    @overload
    def __get__(self, instance: XMLElement, owner: type[XMLElement] | None = None) -> D | None: ...

    def __get__(self, instance: XMLElement | None, owner: type[XMLElement] | None = None) -> Self | D | None:
        if instance is None:
            return self
        attribute = instance._etree_element_.get(self.xml_name)
        return self.default if attribute is None else self.xml_parse(attribute)

    def __set__(self, instance: XMLElement, value: D | None) -> None:
        if value is None:
            instance._etree_element_.attrib.pop(self.xml_name, '')
        else:
            if not isinstance(value, self.type):
                raise TypeError(f'the {self.name!r} attribute must be of type {self.type.__qualname__}')
            instance._etree_element_.set(self.xml_name, self.xml_build(value))

    def __delete__(self, instance: XMLElement) -> None:
        instance._etree_element_.attrib.pop(self.xml_name, '')

    def from_xml(self, instance: XMLElement) -> None:
        """Fill in the instance's field value from its corresponding etree element"""
        try:
            self.__get__(instance)
        except ValueError as exc:
            raise ValueError(f'Invalid value for attribute {self.xml_name!r} from element {ElementInfo.from_element(instance._etree_element_):l}: {exc!s}') from exc


class Element[E: XMLElement](ElementDescriptor[E]):
    def __init__(self, element_type: type[E], /) -> None:
        if not (isinstance(element_type, type) and issubclass(element_type, XMLElement)):
            raise TypeError(f"element type must be a subclass of XMLElement, not '{type(element_type)}'")
        if element_type._tag_ is None:
            raise TypeError(f'{element_type.__qualname__!r} must specify a name and namespace to be usable as element type')
        self.name = None
        self.type = element_type
        self.values: MutableMapping[XMLElement, E] = weakobjectmap()

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.type.__name__})'

    def __set_name__(self, owner: type[XMLElement], name: str) -> None:
        if not issubclass(owner, XMLElement):  # static type analysis does not catch this
            raise TypeError(f'Can only use {self.__class__.__qualname__} descriptors on XMLElement objects')
        if self.name is None:
            self.name = name
        elif name != self.name:
            raise TypeError(f'cannot assign the same {self.__class__.__name__} descriptor to two different names: {self.name} and {name}')

    @overload
    def __get__(self, instance: None, owner: type[XMLElement]) -> Self: ...

    @overload
    def __get__(self, instance: XMLElement, owner: type[XMLElement] | None = None) -> E: ...

    def __get__(self, instance: XMLElement | None, owner: type[XMLElement] | None = None) -> Self | E:
        if instance is None:
            return self
        try:
            return self.values[instance]
        except KeyError as exc:
            raise AttributeError(f'mandatory element {self.name!r} is missing') from exc

    def __set__(self, instance: XMLElement, value: E) -> None:
        new_element = value
        old_element = self.values.get(instance, None)

        # to consistently reject value=None, check type before identity
        if type(new_element) is not self.type:
            raise TypeError(f'the {self.name!r} element must be of type {self.type.__qualname__}')
        if new_element is old_element:
            return
        if new_element._etree_element_.getparent() is not None:
            raise ValueError(f'the etree element {new_element!r} for {self.name!r} already belongs to another container')
        if old_element is not None:
            instance._etree_element_.replace(old_element._etree_element_, new_element._etree_element_)
        else:
            instance._etree_element_.append(new_element._etree_element_)  # NOTE @dan: find insertion point
        self.values[instance] = new_element

    def __delete__(self, instance: XMLElement) -> None:
        raise AttributeError(f'mandatory element {self.name!r} cannot be deleted')

    def from_xml(self, instance: XMLElement) -> None:
        """Fill in the instance's field value from its corresponding etree element"""
        elements = [element for element in instance._etree_element_ if element.tag == self.type._tag_]
        element_count = len(elements)
        if element_count == 0:
            raise ValueError(f'Missing mandatory {self.type._qualname_!r} element from {ElementInfo.from_element(instance._etree_element_):l}')
        if element_count > 1:
            raise ValueError(f'Excess elements for {ElementInfo.from_element(elements[1]):l}')
        self.values[instance] = self.type.from_xml(elements[0])


class OptionalElement[E: XMLElement](OptionalElementDescriptor[E]):
    def __init__(self, element_type: type[E], /) -> None:
        if not (isinstance(element_type, type) and issubclass(element_type, XMLElement)):
            raise TypeError(f"element type must be a subclass of XMLElement, not '{type(element_type)}'")
        if element_type._tag_ is None:
            raise TypeError(f'{element_type.__qualname__!r} must specify a name and namespace to be usable as element type')
        self.name = None
        self.type = element_type
        self.values: MutableMapping[XMLElement, E | None] = defaultweakobjectmap(NoneType)

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.type.__name__})'

    def __set_name__(self, owner: type[XMLElement], name: str) -> None:
        if not issubclass(owner, XMLElement):  # static type analysis does not catch this
            raise TypeError(f'Can only use {self.__class__.__qualname__} descriptors on XMLElement objects')
        if self.name is None:
            self.name = name
        elif name != self.name:
            raise TypeError(f'cannot assign the same {self.__class__.__name__} descriptor to two different names: {self.name} and {name}')

    @overload
    def __get__(self, instance: None, owner: type[XMLElement]) -> Self: ...

    @overload
    def __get__(self, instance: XMLElement, owner: type[XMLElement] | None = None) -> E | None: ...

    def __get__(self, instance: XMLElement | None, owner: type[XMLElement] | None = None) -> Self | E | None:
        if instance is None:
            return self
        return self.values[instance]

    def __set__(self, instance: XMLElement, value: E | None) -> None:
        if value is None:
            self.__delete__(instance)
            self.values[instance] = value
        else:
            new_element = value
            old_element = self.values.get(instance, None)

            if new_element is old_element:
                return
            if type(new_element) is not self.type:
                raise TypeError(f'the {self.name!r} element must be of type {self.type.__qualname__}')
            if new_element._etree_element_.getparent() is not None:
                raise ValueError(f'the etree element {new_element!r} for {self.name!r} already belongs to another container')
            if old_element is not None:
                instance._etree_element_.replace(old_element._etree_element_, new_element._etree_element_)
            else:
                instance._etree_element_.append(new_element._etree_element_)  # NOTE @dan: find insertion point
            self.values[instance] = new_element

    def __delete__(self, instance: XMLElement) -> None:
        value = self.values.pop(instance, None)
        if value is not None:
            instance._etree_element_.remove(value._etree_element_)

    def from_xml(self, instance: XMLElement) -> None:
        """Fill in the instance's field value from its corresponding etree element"""
        elements = [element for element in instance._etree_element_ if element.tag == self.type._tag_]
        element_count = len(elements)
        if element_count > 1:
            raise ValueError(f'Excess elements for {ElementInfo.from_element(elements[1]):l}')
        if element_count == 0:
            value = None
        else:
            value = self.type.from_xml(elements[0])
        self.values[instance] = value


class MultiElement[E: XMLElement](MultiElementDescriptor[E]):
    def __init__(self, element_type: type[E], /, *, optional: bool = False) -> None:
        if not (isinstance(element_type, type) and issubclass(element_type, XMLElement)):
            raise TypeError(f"element type must be a subclass of XMLElement, not '{type(element_type)}'")
        if element_type._tag_ is None:
            raise TypeError(f'{element_type.__qualname__!r} must specify a name and namespace to be usable as element type')
        self.name = None
        self.type = element_type
        self.optional = optional
        self.values: MutableMapping[XMLElement, list[E]] = defaultweakobjectmap(list)

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.type.__name__}, optional={self.optional})'

    def __set_name__(self, owner: type[XMLElement], name: str) -> None:
        if not issubclass(owner, XMLElement):  # static type analysis does not catch this
            raise TypeError(f'Can only use {self.__class__.__qualname__} descriptors on XMLElement objects')
        if self.name is None:
            self.name = name
        elif name != self.name:
            raise TypeError(f'cannot assign the same {self.__class__.__name__} descriptor to two different names: {self.name} and {name}')

    @overload
    def __get__(self, instance: None, owner: type[XMLElement]) -> Self: ...

    @overload
    def __get__(self, instance: XMLElement, owner: type[XMLElement] | None = None) -> ElementList[E]: ...

    def __get__(self, instance: XMLElement | None, owner: type[XMLElement] | None = None) -> Self | ElementList[E]:
        if instance is None:
            return self
        elements = self.values[instance]
        if not elements and not self.optional:
            raise AttributeError(f'mandatory element {self.name!r} is missing')
        return ElementList(self, instance, elements)

    def __set__(self, instance: XMLElement, value: Iterable[E]) -> None:
        elements = list(value)

        if not elements and not self.optional:
            raise ValueError(f'the {self.name!r} element must have at least one item')

        # FIX @dan: check that ETreeElements are not reused (len(set(e.element for e in elements)) must be the same as len(elements))
        # same goes for ElementList, also check other descriptors and containers.
        parent_element = instance._etree_element_
        acceptable_parents = {parent_element, None}
        for element in elements:
            if type(element) is not self.type:
                raise TypeError(f'the {self.name!r} element must be of type {self.type.__qualname__}')
            if element._etree_element_.getparent() not in acceptable_parents:
                raise ValueError(f'the etree element {element!r} for {self.name!r} already belongs to another container')
        # NOTE @dan: replace old elements to preserve positions in parent?
        for element in self.values.get(instance, []):
            parent_element.remove(element._etree_element_)
        # NOTE @dan: find insertion point
        parent_element.extend(element._etree_element_ for element in elements)
        self.values[instance] = elements

    def __delete__(self, instance: XMLElement) -> None:
        if not self.optional:
            raise AttributeError(f'mandatory element {self.name!r} cannot be deleted')
        for element in self.values.pop(instance, []):
            instance._etree_element_.remove(element._etree_element_)

    def from_xml(self, instance: XMLElement) -> None:
        """Fill in the instance's field value from its corresponding etree elements"""
        elements = [element for element in instance._etree_element_ if element.tag == self.type._tag_]
        if not self.optional and len(elements) == 0:
            raise ValueError(f'There must be at least one {self.type._qualname_!r} element in {ElementInfo.from_element(instance._etree_element_):l}')
        self.values[instance] = [self.type.from_xml(element) for element in elements]


class DataElement[D: XMLData](DataElementDescriptor[D]):
    def __init__(self, data_type: type[D], /, *, namespace: Namespace | None = None, name: str | None = None, adapter: DataAdapterType[D] | None = None) -> None:
        self.name = None
        self.type = data_type
        self.xml_name = name or ''
        self.xml_namespace = namespace
        self.xml_tag = f'{{{self.xml_namespace}}}{self.xml_name}' if self.xml_namespace is not None else self.xml_name
        self.xml_qualname = f'{self.xml_namespace.prefix}:{self.xml_name}' if self.xml_namespace is not None and self.xml_namespace.prefix is not None else self.xml_name
        self.adapter = adapter

        if adapter is None:
            if issubclass(data_type, DataConverter):
                adapter = cast(DataAdapterType[D], data_type)  # A type that implements the DataConverter protocol is its own DataAdapter
            else:
                adapter = AdapterRegistry.get_adapter(data_type)

        if adapter is not None:
            self.xml_parse = adapter.xml_parse
            self.xml_build = adapter.xml_build
        else:
            assert not issubclass(data_type, bool | bytes | datetime | DataConverter)  # noqa: S101 (used by type checkers)
            self.xml_parse = data_type
            self.xml_build = str

        self.values: MutableMapping[XMLElement, DataElementValue[D]] = weakobjectmap()

    def __repr__(self) -> str:
        name = self.xml_name if self.xml_name != self.name else None
        adapter_name = self.adapter.__qualname__ if self.adapter else None
        return f'{self.__class__.__name__}({self.type.__name__}, namespace={self.xml_namespace!r}, {name=}, adapter={adapter_name})'

    def __set_name__(self, owner: type[XMLElement], name: str) -> None:
        if not issubclass(owner, XMLElement):  # static type analysis does not catch this
            raise TypeError(f'Can only use {self.__class__.__qualname__} descriptors on XMLElement objects')
        if self.name is None:
            self.name = name
            self.xml_name = self.xml_name or name
            self.xml_namespace = self.xml_namespace or owner._namespace_
            self.xml_tag = f'{{{self.xml_namespace}}}{self.xml_name}' if self.xml_namespace is not None else self.xml_name
            self.xml_qualname = f'{self.xml_namespace.prefix}:{self.xml_name}' if self.xml_namespace is not None and self.xml_namespace.prefix is not None else self.xml_name
        elif name != self.name:
            raise TypeError(f'cannot assign the same {self.__class__.__name__} descriptor to two different names: {self.name} and {name}')

    @overload
    def __get__(self, instance: None, owner: type[XMLElement]) -> Self: ...

    @overload
    def __get__(self, instance: XMLElement, owner: type[XMLElement] | None = None) -> D: ...

    def __get__(self, instance: XMLElement | None, owner: type[XMLElement] | None = None) -> Self | D:
        if instance is None:
            return self
        try:
            return self.values[instance].value
        except KeyError as exc:
            raise AttributeError(f'mandatory element {self.name!r} is missing') from exc

    def __set__(self, instance: XMLElement, value: D) -> None:
        if not isinstance(value, self.type):
            raise TypeError(f'the {self.name!r} element must be of type {self.type.__qualname__}')
        xml_value = self.xml_build(value)
        try:
            data_element = self.values[instance]
        except KeyError:
            data_element = self.values.setdefault(instance, DataElementValue(value, etree.Element(self.xml_tag)))
            instance._etree_element_.append(data_element.element)  # NOTE @dan: find insertion point
        data_element.value = value
        data_element.element.text = xml_value

    def __delete__(self, instance: XMLElement) -> None:
        raise AttributeError(f'mandatory element {self.name!r} cannot be deleted')

    def from_xml(self, instance: XMLElement) -> None:
        """Fill in the instance's field value from its corresponding etree element"""
        elements = [element for element in instance._etree_element_ if element.tag == self.xml_tag]
        element_count = len(elements)
        if element_count == 0:
            raise ValueError(f'Missing mandatory {self.xml_qualname!r} element from {ElementInfo.from_element(instance._etree_element_):l}')
        if element_count > 1:
            raise ValueError(f'Excess elements for {ElementInfo.from_element(elements[1]):l}')
        element = elements[0]
        try:
            self.values[instance] = DataElementValue(self.xml_parse(element.text or ''), element)
        except ValueError as exc:
            raise ValueError(f'Invalid value for element {ElementInfo.from_element(element):l}: {exc!s}') from exc


class OptionalDataElement[D: XMLData](OptionalDataElementDescriptor[D]):
    def __init__(self, data_type: type[D], /, *, namespace: Namespace | None = None, name: str | None = None, default: D | None = None, adapter: DataAdapterType[D] | None = None) -> None:
        self.name = None
        self.type = data_type
        self.xml_name = name or ''
        self.xml_namespace = namespace
        self.xml_tag = f'{{{self.xml_namespace}}}{self.xml_name}' if self.xml_namespace is not None else self.xml_name
        self.xml_qualname = f'{self.xml_namespace.prefix}:{self.xml_name}' if self.xml_namespace is not None and self.xml_namespace.prefix is not None else self.xml_name
        self.default = default
        self.adapter = adapter

        if adapter is None:
            if issubclass(data_type, DataConverter):
                adapter = cast(DataAdapterType[D], data_type)  # A type that implements the DataConverter protocol is its own DataAdapter
            else:
                adapter = AdapterRegistry.get_adapter(data_type)

        if adapter is not None:
            self.xml_parse = adapter.xml_parse
            self.xml_build = adapter.xml_build
        else:
            assert not issubclass(data_type, bool | bytes | datetime | DataConverter)  # noqa: S101 (used by type checkers)
            self.xml_parse = data_type
            self.xml_build = str

        self.values: MutableMapping[XMLElement, DataElementValue[D] | None] = defaultweakobjectmap(NoneType)

    def __repr__(self) -> str:
        name = self.xml_name if self.xml_name != self.name else None
        adapter_name = self.adapter.__qualname__ if self.adapter else None
        return f'{self.__class__.__name__}({self.type.__name__}, namespace={self.xml_namespace!r}, {name=}, default={self.default!r}, adapter={adapter_name})'

    def __set_name__(self, owner: type[XMLElement], name: str) -> None:
        if not issubclass(owner, XMLElement):  # static type analysis does not catch this
            raise TypeError(f'Can only use {self.__class__.__qualname__} descriptors on XMLElement objects')
        if self.name is None:
            self.name = name
            self.xml_name = self.xml_name or name
            self.xml_namespace = self.xml_namespace or owner._namespace_
            self.xml_tag = f'{{{self.xml_namespace}}}{self.xml_name}' if self.xml_namespace is not None else self.xml_name
            self.xml_qualname = f'{self.xml_namespace.prefix}:{self.xml_name}' if self.xml_namespace is not None and self.xml_namespace.prefix is not None else self.xml_name
        elif name != self.name:
            raise TypeError(f'cannot assign the same {self.__class__.__name__} descriptor to two different names: {self.name} and {name}')

    @overload
    def __get__(self, instance: None, owner: type[XMLElement]) -> Self: ...

    @overload
    def __get__(self, instance: XMLElement, owner: type[XMLElement] | None = None) -> D | None: ...

    def __get__(self, instance: XMLElement | None, owner: type[XMLElement] | None = None) -> Self | D | None:
        if instance is None:
            return self
        data_element = self.values[instance]
        return self.default if data_element is None else data_element.value

    def __set__(self, instance: XMLElement, value: D | None) -> None:
        if value is None:
            self.__delete__(instance)
            self.values[instance] = value
        else:
            if not isinstance(value, self.type):
                raise TypeError(f'the {self.name!r} element must be of type {self.type.__qualname__}')
            xml_value = self.xml_build(value)
            data_element = self.values.get(instance, None)
            if data_element is None:
                data_element = DataElementValue(value, etree.Element(self.xml_tag))
                instance._etree_element_.append(data_element.element)  # NOTE @dan: find insertion point
                self.values[instance] = data_element
            data_element.value = value
            data_element.element.text = xml_value

    def __delete__(self, instance: XMLElement) -> None:
        value = self.values.pop(instance, None)
        if value is not None:
            instance._etree_element_.remove(value.element)

    def from_xml(self, instance: XMLElement) -> None:
        """Fill in the instance's field value from its corresponding etree element"""
        elements = [element for element in instance._etree_element_ if element.tag == self.xml_tag]
        element_count = len(elements)
        if element_count > 1:
            raise ValueError(f'Excess elements for {ElementInfo.from_element(elements[1]):l}')
        if element_count == 0:
            value = None
        else:
            element = elements[0]
            try:
                value = DataElementValue(self.xml_parse(element.text or ''), element)
            except ValueError as exc:
                raise ValueError(f'Invalid value for element {ElementInfo.from_element(element):l}: {exc!s}') from exc
        self.values[instance] = value


class MultiDataElement[D: XMLData](MultiDataElementDescriptor[D]):
    def __init__(self, data_type: type[D], /, *, namespace: Namespace | None = None, name: str | None = None, optional: bool = False, adapter: DataAdapterType[D] | None = None) -> None:
        self.name = None
        self.type = data_type
        self.xml_name = name or ''
        self.xml_namespace = namespace
        self.xml_tag = f'{{{self.xml_namespace}}}{self.xml_name}' if self.xml_namespace is not None else self.xml_name
        self.xml_qualname = f'{self.xml_namespace.prefix}:{self.xml_name}' if self.xml_namespace is not None and self.xml_namespace.prefix is not None else self.xml_name
        self.optional = optional
        self.adapter = adapter

        if adapter is None:
            if issubclass(data_type, DataConverter):
                adapter = cast(DataAdapterType[D], data_type)  # A type that implements the DataConverter protocol is its own DataAdapter
            else:
                adapter = AdapterRegistry.get_adapter(data_type)

        if adapter is not None:
            self.xml_parse = adapter.xml_parse
            self.xml_build = adapter.xml_build
        else:
            assert not issubclass(data_type, bool | bytes | datetime | DataConverter)  # noqa: S101 (used by type checkers)
            self.xml_parse = data_type
            self.xml_build = str

        self.values: MutableMapping[XMLElement, list[DataElementValue[D]]] = defaultweakobjectmap(list)

    def __repr__(self) -> str:
        name = self.xml_name if self.xml_name != self.name else None
        adapter_name = self.adapter.__qualname__ if self.adapter else None
        return f'{self.__class__.__name__}({self.type.__name__}, namespace={self.xml_namespace!r}, {name=}, optional={self.optional!r}, adapter={adapter_name})'

    def __set_name__(self, owner: type[XMLElement], name: str) -> None:
        if not issubclass(owner, XMLElement):  # static type analysis does not catch this
            raise TypeError(f'Can only use {self.__class__.__qualname__} descriptors on XMLElement objects')
        if self.name is None:
            self.name = name
            self.xml_name = self.xml_name or name
            self.xml_namespace = self.xml_namespace or owner._namespace_
            self.xml_tag = f'{{{self.xml_namespace}}}{self.xml_name}' if self.xml_namespace is not None else self.xml_name
            self.xml_qualname = f'{self.xml_namespace.prefix}:{self.xml_name}' if self.xml_namespace is not None and self.xml_namespace.prefix is not None else self.xml_name
        elif name != self.name:
            raise TypeError(f'cannot assign the same {self.__class__.__name__} descriptor to two different names: {self.name} and {name}')

    @overload
    def __get__(self, instance: None, owner: type[XMLElement]) -> Self: ...

    @overload
    def __get__(self, instance: XMLElement, owner: type[XMLElement] | None = None) -> DataElementList[D]: ...

    def __get__(self, instance: XMLElement | None, owner: type[XMLElement] | None = None) -> Self | DataElementList[D]:
        if instance is None:
            return self
        data_elements = self.values[instance]
        if not data_elements and not self.optional:
            raise AttributeError(f'mandatory element {self.name!r} is missing')
        return DataElementList(self, instance, data_elements)

    def __set__(self, instance: XMLElement, values: Iterable[D]) -> None:
        values = list(values)

        if not values and not self.optional:
            raise ValueError(f'the {self.name!r} element must have at least one item')

        if not all(isinstance(value, self.type) for value in values):
            raise TypeError(f'the {self.name!r} element must be of type {self.type.__qualname__}')

        # compute these early to catch errors in values to avoid ending up with an inconsistent list of data elements
        xml_values = [self.xml_build(value) for value in values]

        data_elements = self.values[instance]
        parent_element = instance._etree_element_

        # remove excess data elements
        while len(data_elements) > len(values):
            data_element = data_elements.pop()
            parent_element.remove(data_element.element)

        # add additional data elements if needed
        if len(values) > len(data_elements):
            extra_elements = [DataElementValue(value, etree.Element(self.xml_tag)) for value in values[len(data_elements):]]
            if data_elements:
                position = parent_element.index(data_elements[-1].element) + 1
            else:
                position = len(parent_element)  # NOTE @dan: find insertion point
            parent_element[position:position] = [data_element.element for data_element in extra_elements]
            data_elements.extend(extra_elements)

        for data_element, value, xml_value in zip(data_elements, values, xml_values, strict=True):
            data_element.value = value
            data_element.element.text = xml_value

    def __delete__(self, instance: XMLElement) -> None:
        if not self.optional:
            raise AttributeError(f'mandatory element {self.name!r} cannot be deleted')
        for data_element in self.values.pop(instance, []):
            instance._etree_element_.remove(data_element.element)

    def from_xml(self, instance: XMLElement) -> None:
        """Fill in the instance's field value from its corresponding etree element"""

        def build_element_value(element: ETreeElement) -> DataElementValue[D]:
            try:
                return DataElementValue(self.xml_parse(element.text or ''), element)
            except ValueError as exc:
                raise ValueError(f'Invalid value for element {ElementInfo.from_element(element):l}: {exc!s}') from exc

        elements = [element for element in instance._etree_element_ if element.tag == self.xml_tag]
        if not self.optional and len(elements) == 0:
            raise ValueError(f'There must be at least one {self.xml_qualname!r} element in {ElementInfo.from_element(instance._etree_element_):l}')
        self.values[instance] = [build_element_value(element) for element in elements]


class TextValue[D: XMLData](FieldDescriptor[D]):
    """An XMLElement descriptor used to access the text value of its ETreeElement"""

    adapter: DataAdapterType[D] | None

    xml_build: Callable[[D], str]
    xml_parse: Callable[[str], D]

    def __init__(self, data_type: type[D], /, adapter: DataAdapterType[D] | None = None) -> None:
        self.name = None
        self.type = data_type
        self.adapter = adapter

        if adapter is None:
            if issubclass(data_type, DataConverter):
                adapter = cast(DataAdapterType[D], data_type)  # A type that implements the DataConverter protocol is its own DataAdapter
            else:
                adapter = AdapterRegistry.get_adapter(data_type)

        if adapter is not None:
            self.xml_parse = adapter.xml_parse
            self.xml_build = adapter.xml_build
        else:
            assert not issubclass(data_type, bool | bytes | datetime | DataConverter)  # noqa: S101 (used by type checkers)
            self.xml_parse = data_type
            self.xml_build = str

    def __set_name__(self, owner: type[XMLElement], name: str) -> None:
        if not issubclass(owner, XMLElement):  # static type analysis does not catch this
            raise TypeError(f'Can only use {self.__class__.__qualname__} descriptors on XMLElement objects')
        if self.name is None:
            self.name = name
        elif name != self.name:
            raise TypeError(f'cannot assign the same {self.__class__.__name__} descriptor to two different names: {self.name} and {name}')

    @overload
    def __get__(self, instance: None, owner: type[XMLElement]) -> Self: ...

    @overload
    def __get__(self, instance: XMLElement, owner: type[XMLElement] | None = None) -> D: ...

    def __get__(self, instance: XMLElement | None, owner: type[XMLElement] | None = None) -> Self | D:
        if instance is None:
            return self
        return self.xml_parse(instance._etree_element_.text or '')

    def __set__(self, instance: XMLElement, value: D) -> None:
        if not isinstance(value, self.type):
            raise TypeError(f'the text value for the {instance.__class__.__qualname__!r} element must be of type {self.type.__qualname__}')
        instance._etree_element_.text = self.xml_build(value)

    def __delete__(self, instance: XMLElement) -> None:
        raise AttributeError(f'the text value for the {instance.__class__.__qualname__!r} element cannot be deleted')

    def from_xml(self, instance: XMLElement) -> None:
        try:
            self.__get__(instance)
        except ValueError as exc:
            raise ValueError(f'Invalid text value for element {ElementInfo.from_element(instance._etree_element_):l}: {exc!s}') from exc


class ElementInfo:
    """Encode identity and origin information for XML elements for error reporting"""

    qualname: str
    sourceline: int | None

    def __init__(self, qualname: str, sourceline: int | None = None) -> None:
        self.qualname = qualname
        self.sourceline = sourceline

    def __format__(self, spec: str) -> str:
        match spec:
            case '' | 'r':
                return f'{self.qualname!r}'
            case 's':
                return f'{self.qualname!s}'
            case 'l' | 'rl':
                return f'{self.qualname!r} on line {self.sourceline}' if self.sourceline is not None else repr(self.qualname)
            case 'sl':
                return f'{self.qualname!s} on line {self.sourceline}' if self.sourceline is not None else self.qualname
            case 'L' | 'rL':
                return f'{self.qualname!r} [line {self.sourceline}]' if self.sourceline is not None else repr(self.qualname)
            case 'sL':
                return f'{self.qualname!s} [line {self.sourceline}]' if self.sourceline is not None else self.qualname
            case _:
                raise ValueError(f'Invalid format specifier {spec!r} for object of type {self.__class__.__qualname__!r}')

    @classmethod
    def from_element(cls, element: ETreeElement) -> Self:
        _, _, name = element.tag.rpartition('}')
        qualname = f'{element.prefix}:{name}' if element.prefix is not None else name
        return cls(qualname, element.sourceline)  # type: ignore[arg-type]  # lxml stubs are a mess


class ElementHandler[E: XMLElement](Protocol):
    name: str | None
    type: type[E]
    values: MutableMapping

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: name={self.name!r} type={(self.type or NoneType).__name__} values={self.values!r}>'

    def get(self, instance: XMLElement) -> E | None: ...

    def set(self, instance: XMLElement, value: E | None) -> None: ...

    def delete(self, instance: XMLElement) -> None: ...


class MultiElementHandler[E: XMLElement](Protocol):
    name: str | None
    type: type[E]
    optional: bool
    values: MutableMapping

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: name={self.name!r} type={(self.type or NoneType).__name__} optional={self.optional} values={self.values!r}>'

    def get(self, instance: XMLElement) -> ElementList[E]: ...

    def set(self, instance: XMLElement, value: Iterable[E]) -> None: ...

    def delete(self, instance: XMLElement) -> None: ...


class FieldSpec(dict):  # name: XMLSpec
    def __repr__(self) -> str:
        return f'{self.__class__.__qualname__}({", ".join(f"{name!s}={value!r}" for name, value in self.items())})'


field_specifiers = (Attribute, OptionalAttribute, Element, OptionalElement, MultiElement, DataElement, OptionalDataElement, MultiDataElement, TextValue)


@dataclass_transform(kw_only_default=True, field_specifiers=field_specifiers)  # type: ignore[misc]
class AnnotatedXMLElement(XMLElement):
    """
    A static type checker friendly variant of XMLElement.

    Subclassing AnnotatedXMLElement allows static type checkers to identify the
    names and types of the arguments used to create instances, at the cost of
    being more verbose and redundant with the element definitions.

    The element definition needs to include both an annotation and the descriptor
    definition for the element (same for attributes):

      version: Attribute[int] = Attribute(int, adapter=IntAdapter)
      bad_nodes: MultiElement[BadNode] = MultiElement(BadNode, optional=True)

    With these, static type checkers will be able to infer the __init__ signature
    and identify problems with the arguments during instance creation, and it can
    also help with getting code completion suggestions from language servers.
    """


del field_specifiers
