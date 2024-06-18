# SPDX-FileCopyrightText: 2024-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later


from enum import Enum

__all__ = 'MarkerEnum',  # noqa: COM818


class MarkerEnum(Enum):
    """Base class for defining markers"""

    def __repr__(self) -> str:
        return f'{self.__class__.__qualname__}.{self.name}'
