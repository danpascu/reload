# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from enum import Enum
from types import GenericAlias, NoneType, UnionType
from typing import TypeAliasType

__all__ = 'better_repr', 'reprproxy'


def better_repr(value: object) -> str:
    """
    Provide better representation for certain types.

    The representation will mimic their appearance in the code,
    which can be useful to make error messages more readable.

    This applies to type aliases, generic aliases, union types,
    classes and Enum members. Everything else gets their normal
    representation.
    """

    match value:
        case TypeAliasType():
            return better_repr(value.__value__)
        case GenericAlias():
            match value.__origin__:
                case TypeAliasType():
                    result = better_repr(value.__origin__.__value__[*value.__args__])
                case _:
                    result = f'{value.__origin__.__qualname__}[{', '.join(better_repr(_value) for _value in value.__args__)}]'
            return result
        case UnionType():
            return ' | '.join('None' if _type is NoneType else better_repr(_type) for _type in value.__args__)
        case Enum():  # this also covers Flag which is a subclass of Enum
            return f'{value.__class__.__qualname__}.{value.name}'
        case type():
            return value.__qualname__
        case _:
            return '...' if value is Ellipsis else repr(value)


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
        return better_repr(self.value)

    __str__ = __repr__
