# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from pathlib import Path
from typing import Protocol

from lxml import etree

__all__ = 'RelaxNGValidator', 'Validator'


type ETreeElement = etree._Element  # noqa: SLF001


class Validator(Protocol):
    def validate(self, element: ETreeElement) -> bool: ...


class RelaxNGValidator:
    schema_directory = Path(__file__).parent

    def __init__(self, schema_file: str) -> None:
        self.schema_path = self.schema_directory / schema_file
        self.schema = etree.RelaxNG(file=self.schema_path)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RelaxNGValidator):
            return self.schema_path == other.schema_path
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.schema_path)

    def validate(self, element: ETreeElement) -> bool:
        return self.schema.validate(element)
