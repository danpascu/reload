# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# The Kinds are defined by Usages, however creating and parsing messages needs
# access to both the Kind information (Kind id, data model, ...) as well as
# the Kind meta-information (the Kind structure and data types involved) in
# order to be able to automatically create and parse messages that have a
# dynamic structure based on the Kind's id. As a result the Kind structure
# as well as the types used by Kinds will be defined here. While individual
# Kinds can be defined elsewhere as they automatically register and become
# available here, in order to keep messages self contained and testable it
# is recommended to define all the Kinds here.


from collections.abc import MutableMapping
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar, Final, Self, assert_never

from .datamodel import UInt32Adapter

__all__ = 'AccessControl', 'DataModel', 'Kind', 'KindID', 'KindName', 'SIPRegistration', 'TurnService', 'CertificateByNode', 'CertificateByUser'  # noqa: RUF022


type KindID = int
type KindName = str


class StringEnum(StrEnum):
    def __repr__(self) -> str:
        return f'{self.__class__.__qualname__}.{self.name}'


class AccessControl(StringEnum):
    USER_MATCH = 'USER-MATCH'
    NODE_MATCH = 'NODE-MATCH'
    USER_NODE_MATCH = 'USER-NODE-MATCH'
    NODE_MULTIPLE = 'NODE-MULTIPLE'


class DataModel(StringEnum):
    SINGLE = 'SINGLE'
    ARRAY = 'ARRAY'
    DICTIONARY = 'DICTIONARY'


@dataclass(kw_only=True, slots=True)
class Kind:
    id: Final[int]
    name: Final[str]
    data_model: Final[DataModel]
    access_control: Final[AccessControl]

    max_count: int
    max_size: int
    max_node_multiple: int | None = None

    _id_map: ClassVar[MutableMapping[int, Self]] = {}
    _name_map: ClassVar[MutableMapping[str, Self]] = {}

    def __post_init__(self) -> None:
        UInt32Adapter.validate(self.id)
        if self.access_control is AccessControl.NODE_MULTIPLE and self.max_node_multiple is None:
            raise ValueError('Kinds with access control set to NODE_MULTIPLE must define max_node_multiple')
        if self.id in self._id_map:
            raise ValueError(f'The Kind id is already used by another Kind: {self._id_map[self.id]}')
        if self.name in self._name_map:
            raise ValueError(f'The Kind name is already used by another Kind: {self._name_map[self.name]}')
        self._id_map[self.id] = self
        self._name_map[self.name] = self

    @classmethod
    def lookup(cls, identifier: KindID | KindName) -> Self:
        match identifier:
            case int():
                return cls._id_map[identifier]
            case str():
                return cls._name_map[identifier]
            case _:
                assert_never(identifier)


SIPRegistration = Kind(
    id=1,
    name='SIP-REGISTRATION',
    data_model=DataModel.DICTIONARY,
    access_control=AccessControl.USER_NODE_MATCH,
    max_count=1,
    max_size=100,
)

TurnService = Kind(
    id=2,
    name='TURN-SERVICE',
    data_model=DataModel.SINGLE,
    access_control=AccessControl.NODE_MULTIPLE,
    max_count=1,
    max_size=100,
    max_node_multiple=20,
)

CertificateByNode = Kind(
    id=3,
    name='CERTIFICATE_BY_NODE',
    data_model=DataModel.ARRAY,
    access_control=AccessControl.NODE_MATCH,
    max_count=2,
    max_size=1000,
)

CertificateByUser = Kind(
    id=16,
    name='CERTIFICATE_BY_USER',
    data_model=DataModel.ARRAY,
    access_control=AccessControl.USER_MATCH,
    max_count=2,
    max_size=1000,
)
