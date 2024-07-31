# SPDX-FileCopyrightText: 2006-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from collections.abc import Callable, Collection, Iterable, Iterator, MutableMapping, Sized
from collections.abc import Set as AbstractSet
from copy import deepcopy
from reprlib import recursive_repr
from typing import Any, Literal, Protocol, Self, cast, overload
from weakref import ReferenceType
from weakref import ref as wref

from .types import MarkerEnum
from .typing import SupportsKeysAndGetItem

__all__ = 'defaultweakobjectmap', 'weakobjectid', 'weakobjectmap'


# ruff: noqa: N801

type DefaultFactory[T] = Callable[[], T]


class Marker(MarkerEnum):
    MissingArgument = 'Argument is not provided'


class WeakObjectContainer(Protocol):
    __data__: dict[int, Any]


class weakobjectid[T](int):
    ref: ReferenceType[T]
    _container_ref: ReferenceType[WeakObjectContainer]

    def __new__(cls, obj: T, mapping: WeakObjectContainer, /) -> Self:
        self = super().__new__(cls, id(obj))
        self.ref = wref(obj, self._remove)
        self._container_ref = wref(mapping)
        return self

    def __repr__(self) -> str:
        obj = self.ref()
        obj_repr = repr(obj) if obj is not None else 'dead'
        return f'WeakReference[{obj_repr}]'

    def _remove(self, _: ReferenceType) -> None:
        container = self._container_ref()
        if container is not None:
            container.__data__.pop(self, None)


# noinspection PyPep8Naming,PyAbstractClass,PyProtocol
class weakobjectmap_view(Sized, Iterable):
    __slots__ = ('__data__', )

    __data__: dict

    def __init__(self, mapping: WeakObjectContainer) -> None:
        self.__data__ = mapping.__data__

    def __len__(self) -> int:
        return len(self.__data__)

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({list(self)!r})'


# noinspection PyPep8Naming
class weakobjectmap_items[K, V](weakobjectmap_view, AbstractSet[tuple[K, V]]):
    __slots__ = ()

    __data__: dict[weakobjectid[K], V]

    @classmethod
    def _from_iterable[T](cls, iterable: Iterable[T]) -> set[T]:
        return set(iterable)

    def __contains__(self, item: object) -> bool:
        match item:
            case (key, value):
                return (id(key), value) in self.__data__.items()
            case _:
                return False

    def __iter__(self) -> Iterator[tuple[K, V]]:
        for key, value in list(self.__data__.items()):
            obj = key.ref()
            if obj is not None:
                yield obj, value


# noinspection PyPep8Naming
class weakobjectmap_keys[K](weakobjectmap_view, AbstractSet[K]):
    __slots__ = ()

    __data__: dict[weakobjectid[K], Any]

    @classmethod
    def _from_iterable[T](cls, iterable: Iterable[T]) -> set[T]:
        return set(iterable)

    def __contains__(self, key: object) -> bool:
        return id(key) in self.__data__

    def __iter__(self) -> Iterator[K]:
        for key in list(self.__data__):
            obj = key.ref()
            if obj is not None:
                yield obj


# noinspection PyPep8Naming
class weakobjectmap_values[V](weakobjectmap_view, Collection[V]):
    __slots__ = ()

    __data__: dict[weakobjectid, V]

    def __contains__(self, value: object) -> bool:
        return value in self.__data__.values()

    def __iter__(self) -> Iterator[V]:
        for key, value in list(self.__data__.items()):
            if key.ref() is not None:
                yield value


# The wekaobjectmap class offers the same functionality as WeakKeyDictionary
# from the standard python weakref module, with a few notable improvements:
#
#  - it works even with objects (keys) that are not hashable
#  - subclasses can implement __missing__ to define defaultdict like behavior
#  - it is thread safe, as all it's operations are atomic, in the sense that
#    they are the dict's methods executing in C while protected by the GIL
#  - iterating it as well as iterating the keys, values and items views is
#    safe from changes in the mapping during iteration, because it operates
#    on the snapshot of the items from the time the iteration starts
#  - it is easy to inspect because it provides a __repr__ implementation that
#    renders it similarly to a dict
#

# noinspection PyPep8Naming
class weakobjectmap[K, V](MutableMapping[K, V]):  # noqa: PLR0904
    """Map objects to data while keeping weak references to the objects"""

    __data__: dict[int, V]

    def __init__(self, other: SupportsKeysAndGetItem[K, V] | Iterable[tuple[K, V]] = (), /) -> None:
        self.__data__ = {}
        self.update(other)

    def __getitem__(self, key: K) -> V:
        try:
            return self.__data__[id(key)]
        except KeyError:
            return self.__missing__(key)

    def __setitem__(self, key: K, value: V) -> None:
        self.__data__[weakobjectid(key, self)] = value

    def __delitem__(self, key: K) -> None:
        try:
            del self.__data__[id(key)]
        except KeyError:
            raise KeyError(key) from None

    def __contains__(self, key: object) -> bool:
        return id(key) in self.__data__

    def __iter__(self) -> Iterator[K]:
        for key in list(cast(dict[weakobjectid[K], V], self.__data__)):
            obj = key.ref()
            if obj is not None:
                yield obj

    def __len__(self) -> int:
        return len(self.__data__)

    def __missing__(self, key: K) -> V:
        raise KeyError(key) from None

    def __copy__(self) -> Self:
        return self.__class__(self)

    def __deepcopy__(self, memo: dict[int, Any] | None) -> Self:
        return self.__class__((key, deepcopy(value, memo)) for key, value in self.items())

    @recursive_repr(fillvalue='{...}')
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({{{", ".join((f"{key!r}: {value!r}" for key, value in self.items()))}}})'

    @classmethod
    def fromkeys(cls, iterable: Iterable[K], value: V) -> Self:
        mapping = cls()
        for key in iterable:
            mapping[key] = value
        return mapping

    def clear(self) -> None:
        self.__data__.clear()

    def copy(self) -> Self:
        return self.__class__(self)

    def items(self) -> weakobjectmap_items[K, V]:  # type: ignore[override]
        return weakobjectmap_items(self)

    def keys(self) -> weakobjectmap_keys[K]:       # type: ignore[override]
        return weakobjectmap_keys(self)

    def values(self) -> weakobjectmap_values[V]:   # type: ignore[override]
        return weakobjectmap_values(self)

    @overload
    def get(self, key: K, /) -> V | None: ...

    @overload
    def get[T](self, key: K, /, default: T) -> V | T: ...

    def get[T](self, key: K, /, default: T | None = None) -> V | T | None:
        return self.__data__.get(id(key), default)

    @overload
    def pop(self, key: K, /) -> V: ...

    @overload
    def pop(self, key: K, /, default: V) -> V: ...

    @overload
    def pop[T](self, key: K, /, default: T) -> V | T: ...

    def pop[T](self, key: K, /, default: V | T | Literal[Marker.MissingArgument] = Marker.MissingArgument) -> V | T:
        try:
            if default is Marker.MissingArgument:
                return self.__data__.pop(id(key))
            return self.__data__.pop(id(key), default)
        except KeyError:
            raise KeyError(key) from None

    def popitem(self) -> tuple[K, V]:
        data = cast(dict[weakobjectid[K], V], self.__data__)
        while True:
            key, value = data.popitem()
            obj = key.ref()
            if obj is not None:
                return obj, value

    def setdefault(self, key: K, default: V, /) -> V:
        return self.__data__.setdefault(weakobjectid(key, self), default)


# noinspection PyPep8Naming
class defaultweakobjectmap[K, V](weakobjectmap[K, V]):
    default_factory: DefaultFactory[V]

    def __init__(self, default_factory: DefaultFactory[V], other: SupportsKeysAndGetItem[K, V] | Iterable[tuple[K, V]] = (), /) -> None:
        self.default_factory = default_factory
        super().__init__(other)

    def __missing__(self, key: K) -> V:
        return self.setdefault(key, self.default_factory())

    @recursive_repr(fillvalue='{...}')
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.default_factory.__qualname__}, {{{", ".join((f"{key!r}: {value!r}" for key, value in self.items()))}}})'
