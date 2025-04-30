# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio
import contextlib
import ssl
from collections.abc import Mapping, Sequence
from enum import auto
from io import BytesIO
from typing import Any, ClassVar, Protocol

from reload import aio
from reload.configuration import BootstrapNode, Configuration
from reload.link.transport.common import NodeCertificate
from reload.messages import Destination, ForwardingHeader, Message, MessageContents
from reload.messages.datamodel import List, NodeID, OpaqueID, ResourceID
from reload.python.types import MarkerEnum

from .security import NodeIdentity
from .transport.dtls import DTLSLink
from .transport.tls import TLSLink

__all__ = 'LinkManager',  # noqa: COM818


type NodeLink = DTLSLink | TLSLink


class TopologyPlugin(Protocol):
    def get_next_hop(self, destination: NodeID | ResourceID, /, *, connected_nodes: Mapping[str, Any] = {}) -> NodeID | None: ...

    def is_responsible_for(self, resource: NodeID | ResourceID, /) -> bool: ...


class AttachState(MarkerEnum):
    RequestIn = auto()
    RequestOut = auto()
    ResponseIn = auto()
    ResponseOut = auto()


class LinkManager:
    identity: NodeIdentity
    node_cert: NodeCertificate

    default_port: ClassVar[int] = 6084

    tls_handshake_timeout: ClassVar[int] = 30
    tls_shutdown_timeout: ClassVar[int] = 3

    # Internal attributes

    _topology_plugin: TopologyPlugin

    _bootstrap_nodes: set[NodeID]
    _connected_nodes: dict[NodeID, NodeLink]

    _pending_attach: dict[NodeID, AttachState]

    _transaction_map: dict[int, tuple[ForwardingHeader, Message]]

    _main_task: asyncio.Task[None]
    _task_list: set[asyncio.Task[None]]
    _server: asyncio.Server
    _ready: asyncio.Future[None]
    _done: asyncio.Future[None]

    def __init__(self, identity: NodeIdentity, configuration: Configuration) -> None:
        self.configuration = configuration
        self.identity = identity
        self.node_cert = NodeCertificate(identity.certificate)
        self._started = False
        self._stopped = False
        self._listen_address = None
        self._listen_port = self.default_port
        self._is_bootstrap_node = False
        self._bootstrap_nodes = set()
        self._connected_nodes = {}
        self._pending_attach = {}
        self._transaction_map = {}
        self._topology_plugin = NotImplemented  # should be set before start
        self._main_task = NotImplemented        # will be set upon start
        self._task_list = set()
        self._server = NotImplemented           # will be set upon start
        self._ready = NotImplemented            # will be set upon start
        self._done = NotImplemented             # will be set upon start

    def __repr__(self) -> str:
        return f'{self.__class__.__qualname__}(identity={self.identity!r}, configuration={self.configuration!r})'

    def set_topology_plugin(self, topology_plugin: TopologyPlugin) -> None:
        self._topology_plugin = topology_plugin

    async def start(self) -> None:
        if self._topology_plugin is NotImplemented:
            raise RuntimeError('The topology plugin must be set before starting the link manager')
        if self._started:
            return
        self._started = True
        self._ready = asyncio.Future()
        self._done = asyncio.Future()
        self._main_task = asyncio.create_task(self._main_loop())
        await self._ready

    async def stop(self) -> None:
        if not self._started or self._stopped:
            return
        self._stopped = True
        self._done.set_result(None)
        await self._main_task

    def _check_link(self, link: NodeLink) -> None:
        """
        Will raise an exception if there is a problem with the link:

        - ValueError -> the peer certificate does not contain a valid identity
        - ConnectedToSelf -> the link connects this node to itself
        - NodeAlreadyConnected -> already have a connection with this node
        """
        # Accessing peer_cert, peer_cert.node_ids and peer_cert.user will raise
        # ValueError if the peer certificate does not contain a valid identity.
        # Let this exception fall through to indicate that the link is invalid.
        peer_cert = link.peer_cert
        _ = peer_cert.node_ids
        _ = peer_cert.user
        if peer_cert == self.node_cert:
            raise ConnectedToSelf
        if peer_cert.node_id in self._connected_nodes:
            raise AlreadyConnectedNode

    @staticmethod
    async def _close_link(link: NodeLink) -> None:
        with contextlib.suppress(aio.ClosedResourceError, aio.BrokenResourceError):
            await link.close()

    async def _shutdown(self) -> None:
        async with asyncio.TaskGroup() as group:
            self._server.close()
            for link in self._connected_nodes.values():
                group.create_task(self._close_link(link))
            group.create_task(self._server.wait_closed())
        self._connected_nodes.clear()
        self._bootstrap_nodes.clear()

    async def _main_loop(self) -> None:
        self._server = await self._start_server(self._listen_address, self._listen_port)
        await self._connect_to_bootstrap_nodes()
        if not self._is_bootstrap_node and not self._connected_nodes:
            self._stopped = True
            await self._shutdown()
            self._ready.set_exception(OverlayUnreachable)
        else:
            self._ready.set_result(None)
            await self._done
            await self._shutdown()

    async def _connect_to_bootstrap_nodes(self) -> None:
        async with asyncio.TaskGroup() as group:
            for node in self.configuration.bootstrap_nodes:
                group.create_task(self._connect_to_bootstrap_node(node))

    async def _connect_to_bootstrap_node(self, node: BootstrapNode) -> None:
        try:
            reader, writer = await asyncio.open_connection(
                host=node.address,
                port=node.port or self.default_port,
                ssl=TLSLink.get_context(purpose=ssl.Purpose.SERVER_AUTH, identity=self.identity),
                ssl_handshake_timeout=self.tls_handshake_timeout,
                ssl_shutdown_timeout=self.tls_shutdown_timeout,
            )
        except OSError:
            return
        tls_link = TLSLink(reader, writer, identity=self.identity)
        try:
            self._check_link(tls_link)
        except ValueError:
            await self._close_link(tls_link)
            return
        except ConnectedToSelf:
            self._is_bootstrap_node = True
            await self._close_link(tls_link)
            return
        except AlreadyConnectedNode:
            # Outgoing connections to bootstrap nodes are recorded in _bootstrap_nodes and we only
            # attempt connections to bootstrap nodes if there are none established. If we already
            # have a connection with this node, it must be a connection they made with us, which
            # was not recorded in _bootstrap_nodes, so we should record it now.
            self._bootstrap_nodes.update(tls_link.peer_cert.node_ids)
            await self._close_link(tls_link)
            return
        self._bootstrap_nodes.update(tls_link.peer_cert.node_ids)
        task = asyncio.create_task(self._tls_link_handler(tls_link))
        self._task_list.add(task)
        task.add_done_callback(self._task_list.discard)

    async def _tls_client_connected_callback(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        tls_link = TLSLink(reader, writer, identity=self.identity)
        if self._stopped:
            await self._close_link(tls_link)
            return
        try:
            self._check_link(tls_link)
        except (ValueError, ConnectedToSelf, AlreadyConnectedNode):
            await self._close_link(tls_link)
            return
        task = asyncio.create_task(self._tls_link_handler(tls_link))
        self._task_list.add(task)
        task.add_done_callback(self._task_list.discard)

    async def _tls_link_handler(self, tls_link: TLSLink) -> None:
        node_ids = tls_link.peer_cert.node_ids
        for node_id in node_ids:
            self._connected_nodes[node_id] = tls_link
        task = asyncio.create_task(self._handle_link_messages(tls_link), name=f'_handle_link_messages[{tls_link.peer_cert.node_id.hex()}]')
        try:
            await task
        except (aio.ClosedResourceError, aio.BrokenResourceError):
            pass
        finally:
            for node_id in node_ids:
                del self._connected_nodes[node_id]
            self._bootstrap_nodes.difference_update(node_ids)

    async def _handle_link_messages(self, link: NodeLink) -> None:
        try:
            async for message in link:
                # NOTE @dan: handle max_message_size
                # NOTE @dan: split this body into 2 methods decode_message/route_message?
                message_bytes = BytesIO(message)
                try:
                    forwarding_header = ForwardingHeader.from_wire(message_bytes)
                except ValueError:
                    continue
                try:
                    next_hop = self._find_next_hop(forwarding_header.destination_list)
                except (InvalidMessageError, NotImplementedError):
                    continue  # NOTE @dan: ignore or send error reply?
                forwarding_header.via_list.append(Destination.for_data(link.peer_cert.node_id))
                if next_hop is None:
                    # message is for this node
                    await self._message_received(forwarding_header, message_bytes)
                else:
                    updated_message = forwarding_header.to_wire() + message_bytes.read()
                    link = self._connected_nodes[next_hop]
                    await link.send(updated_message)
        except (aio.ClosedResourceError, aio.BrokenResourceError):
            pass

    def _find_next_hop(self, destination_list: List[Destination]) -> NodeID | None:  # noqa: C901
        """Return the next hop for the message or None if the message is for this node"""

        if (list_length := len(destination_list)) == 0:
            raise InvalidMessageError

        final_destination: bool = list_length == 1

        match destination_list[0].data:
            case NodeID() as node_id:
                if node_id in self._connected_nodes:
                    return node_id
                if node_id in self.node_cert.node_ids:
                    if final_destination:
                        return None
                    # transit through this node
                    del destination_list[0]
                    return self._find_next_hop(destination_list)
                next_hop = self._topology_plugin.get_next_hop(node_id)
                if next_hop is None:
                    # We are responsible for this node_id, but it's not ours. Drop it (see RFC6940 6.1.1)
                    raise InvalidMessageError
                return next_hop
            case ResourceID() as resource_id:
                if not final_destination:
                    raise InvalidMessageError
                if resource_id in self._connected_nodes:
                    return NodeID(resource_id)
                return self._topology_plugin.get_next_hop(resource_id)
            case OpaqueID():
                raise NotImplementedError

    async def _message_received(self, forwarding_header: ForwardingHeader, message_bytes: BytesIO) -> None:
        message_contents = MessageContents.from_wire(message_bytes)
        message = Message[message_contents.code].from_wire(message_contents.body)
        self._transaction_map[forwarding_header.transaction_id] = (forwarding_header, message)

    async def _start_server(self, address: str | Sequence[str] | None = None, port: int | str | None = None) -> asyncio.Server:
        return await asyncio.start_server(
            self._tls_client_connected_callback,
            host=address,
            port=port,
            ssl=TLSLink.get_context(purpose=ssl.Purpose.CLIENT_AUTH, identity=self.identity),
            ssl_handshake_timeout=self.tls_handshake_timeout,
            ssl_shutdown_timeout=self.tls_shutdown_timeout,
            start_serving=True,
        )


class AlreadyConnectedNode(Exception):
    pass


class ConnectedToSelf(Exception):
    pass


class OverlayUnreachable(Exception):
    pass


class InvalidMessageError(ValueError):
    pass
