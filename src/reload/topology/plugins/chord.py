# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# ruff: noqa: INP001, COM818

from bisect import bisect
from collections.abc import Mapping
from typing import Any, ClassVar

from reload.messages.datamodel import NodeID, ResourceID
from reload.topology.base import PluginRegistry

__all__ = 'ChordTopologyPlugin',


class ChordTopologyPlugin:
    _name_: ClassVar[str] = 'CHORD-RELOAD'

    node_id: NodeID

    _routing_table: list[NodeID]  # These will be kept sorted
    _finger_table: list[NodeID]   # These will be kept sorted

    _predecessors: list[NodeID]
    _successors: list[NodeID]

    def __init__(self, node_id: NodeID) -> None:
        self.node_id = node_id
        self._routing_table = [self.node_id]
        self._finger_table = []
        self._predecessors = []
        self._successors = []

    def __repr__(self) -> str:
        return f'<{self.__class__.__qualname__}: {self.node_id.hex()}>'

    def get_next_hop(self, destination: NodeID | ResourceID, /, *, connected_nodes: Mapping[str, Any] = {}) -> NodeID | None:
        if destination in connected_nodes:
            return destination if isinstance(destination, NodeID) else NodeID(destination)
        if self.is_responsible_for(destination):
            return None
        # RFC6940 10.3 Routing
        pos = bisect(self._routing_table, destination)
        table_len = len(self._routing_table)
        if (node_id := self._routing_table[(pos - 1) % table_len]) != self.node_id:
            return node_id
        return self._routing_table[pos % table_len]

    def is_responsible_for(self, destination: NodeID | ResourceID, /) -> bool:
        if not self._predecessors:
            return True
        return self._inbetween(destination, self._predecessors[-1], self.node_id)

    @staticmethod
    def _inbetween(destination: NodeID | ResourceID, node1: NodeID, node2: NodeID) -> bool:
        """Return True if node1 < destination <= node2 using modulo arithmetic"""
        return (node1.value < destination.value <= node2.value) if node1 < node2 else not (node2.value < destination.value <= node1.value)


PluginRegistry.register(ChordTopologyPlugin)
