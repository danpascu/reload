# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from importlib import import_module
from pathlib import Path

from reload.configuration import Configuration
from reload.messages.datamodel import NodeID
from reload.topology import plugins

from .base import PluginRegistry, TopologyPlugin

__all__ = 'TopologyPlugin', 'topology_plugin'


def topology_plugin(node_id: NodeID, configuration: Configuration) -> TopologyPlugin:
    plugin_name = configuration.topology_plugin or 'CHORD-RELOAD'
    try:
        topology_plugin_class = PluginRegistry.get_plugin(plugin_name)
    except KeyError as exc:
        raise NotImplementedError(f'The {plugin_name!r} topology plugin could not be found') from exc
    return topology_plugin_class(node_id)


def _load_available_plugins() -> None:
    for location in plugins.__spec__.submodule_search_locations or []:
        for module_file in Path(location).glob('[!_]*.py'):
            import_module(f'reload.topology.plugins.{module_file.stem}')


_load_available_plugins()
del _load_available_plugins
