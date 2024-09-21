# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio
import unittest
from typing import cast

import trustme
from OpenSSL.SSL import Context

from reload import link


class _TestIdentity:
    _key_: int

    def __init__(self, authority: trustme.CA) -> None:
        self.authority = authority
        self.certificate = authority.issue_cert('test.com')
        self._key_ = hash(self.certificate.private_key_and_cert_chain_pem.bytes())

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}()'

    def __hash__(self) -> int:
        return self._key_

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _TestIdentity):
            return self._key_ == other._key_
        return NotImplemented

    def configure(self, context: Context) -> None:
        self.authority.configure_trust(context)
        self.certificate.configure_cert(context)


class TestDTLS(unittest.IsolatedAsyncioTestCase):

    def setUp(self) -> None:
        link.DTLSEndpoint.stun_server = None
        self._authority = trustme.CA()
        self._client_identity = cast(link.NodeIdentity, _TestIdentity(self._authority))
        self._server_identity = cast(link.NodeIdentity, _TestIdentity(self._authority))
        self._client_conn = link.DTLSEndpoint(purpose=link.Purpose.AttachResponse, identity=self._client_identity)
        self._server_conn = link.DTLSEndpoint(purpose=link.Purpose.AttachRequest, identity=self._server_identity)

    async def asyncSetUp(self) -> None:
        await self._client_conn.prepare()
        await self._server_conn.prepare()
        client_peer = link.ICEPeer(self._client_conn.ice.local_username, self._client_conn.ice.local_password, self._client_conn.ice.local_candidates)
        server_peer = link.ICEPeer(self._server_conn.ice.local_username, self._server_conn.ice.local_password, self._server_conn.ice.local_candidates)
        client_task = asyncio.create_task(self._connect_peer(self._client_conn, server_peer))
        server_task = asyncio.create_task(self._connect_peer(self._server_conn, client_peer))
        await asyncio.gather(client_task, server_task)
        await self._client_conn.send(b'client message')
        await self._server_conn.send(b'server message')

    @staticmethod
    async def _connect_peer(conn: link.DTLSEndpoint, ice_peer: link.ICEPeer) -> None:
        await conn.connect(ice_peer)

    @staticmethod
    async def _disconnect_peer(conn: link.DTLSEndpoint) -> None:
        await conn.close()

    async def test_dtls(self) -> None:
        client_message = await self._server_conn.receive()
        server_message = await self._client_conn.receive()
        self.assertEqual(client_message, b'client message')
        self.assertEqual(server_message, b'server message')

    def tearDown(self) -> None:
        pass

    async def asyncTearDown(self) -> None:
        client_task = asyncio.create_task(self._disconnect_peer(self._client_conn))
        server_task = asyncio.create_task(self._disconnect_peer(self._server_conn))
        await asyncio.gather(client_task, server_task)


if __name__ == '__main__':
    unittest.main()
