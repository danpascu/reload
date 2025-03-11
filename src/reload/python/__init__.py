# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from enum import Enum
from types import NoneType, UnionType

__all__ = 'reprproxy',  # noqa: COM818


class reprproxy:  # noqa: N801
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
