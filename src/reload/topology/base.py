# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from collections.abc import Mapping, MutableMapping
from typing import Any, ClassVar, Protocol

from reload.messages.datamodel import NodeID, ResourceID

__all__ = 'TopologyPlugin', 'PluginRegistry'  # noqa: RUF022


class TopologyPlugin(Protocol):
    _name_: ClassVar[str]

    def __init__(self, node_id: NodeID) -> None: ...

    def get_next_hop(self, destination: NodeID | ResourceID, /, *, connected_nodes: Mapping[str, Any] = {}) -> NodeID | None: ...

    def is_responsible_for(self, destination: NodeID | ResourceID, /) -> bool: ...


class PluginRegistry:
    _plugins: ClassVar[MutableMapping[str, type[TopologyPlugin]]] = {}

    @classmethod
    def register(cls, plugin: type[TopologyPlugin]) -> None:
        cls._plugins[plugin._name_] = plugin

    @classmethod
    def get_plugin(cls, name: str) -> type[TopologyPlugin]:
        return cls._plugins[name]
