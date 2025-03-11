# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from enum import Enum
from types import GenericAlias, NoneType, UnionType
from typing import TypeAliasType

__all__ = 'reprproxy',  # noqa: COM818


class reprproxy:  # noqa: N801
    """
    A proxy to provide better representation for certain types.

    The representation will mimic their appearance in the code,
    which can be useful to make error messages more readable.

    This applies to type aliases, generic aliases, union types,
    classes and Enum members. Everything else gets their normal
    representation.
    """

    def __init__(self, value: object) -> None:
        self.value = value

    def __repr__(self) -> str:
        match self.value:
            case TypeAliasType() as value:
                return reprproxy(value.__value__).__repr__()
            case GenericAlias() as value:
                match value.__origin__:
                    case TypeAliasType():
                        result = reprproxy(value.__origin__.__value__[*value.__args__]).__repr__()
                    case _:
                        result = f'{value.__origin__.__qualname__}[{', '.join(reprproxy(_value).__repr__() for _value in value.__args__)}]'
                return result
            case UnionType() as value:
                return ' | '.join('None' if _type is NoneType else reprproxy(_type).__repr__() for _type in value.__args__)
            case Enum() as value:  # this also covers Flag which is a subclass of Enum
                return f'{value.__class__.__qualname__}.{value.name}'
            case type() as value:
                return value.__qualname__
            case value:
                return '...' if value is Ellipsis else repr(value)

    __str__ = __repr__
