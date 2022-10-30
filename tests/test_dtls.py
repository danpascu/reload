# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio
import trustme
import unittest

from OpenSSL.SSL import Context
from functools import cached_property
from typing import cast

from reload import link


class _TestIdentity:
    def __init__(self, authority: trustme.CA):
        self.authority = authority
        self.certificate = authority.issue_cert('test.com')

    @cached_property
    def __key__(self):
        return hash(self.certificate.private_key_and_cert_chain_pem.bytes())

    def __repr__(self):
        return f'{self.__class__.__name__}()'

    def __hash__(self):
        return hash(self.__key__)

    def __eq__(self, other):
        if isinstance(other, _TestIdentity):
            return self.__key__ == other.__key__
        return NotImplemented

    def configure(self, context: Context):
        self.authority.configure_trust(context)
        self.certificate.configure_cert(context)


class TestDTLS(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        link.DTLSEndpoint.stun_server = None
        self._authority = trustme.CA()
        self._client_identity = cast(link.NodeIdentity, _TestIdentity(self._authority))
        self._server_identity = cast(link.NodeIdentity, _TestIdentity(self._authority))
        self._client_conn = link.DTLSEndpoint(purpose=link.Purpose.AttachResponse, identity=self._client_identity)
        self._server_conn = link.DTLSEndpoint(purpose=link.Purpose.AttachRequest, identity=self._server_identity)

    async def asyncSetUp(self):
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
    async def _connect_peer(conn: link.DTLSEndpoint, ice_peer: link.ICEPeer):
        await conn.connect(ice_peer)

    @staticmethod
    async def _disconnect_peer(conn: link.DTLSEndpoint):
        await conn.close()

    async def test_dtls(self):
        self.assertEqual(await self._server_conn.receive(), b'client message')
        self.assertEqual(await self._client_conn.receive(), b'server message')

    def tearDown(self):
        pass

    async def asyncTearDown(self):
        client_task = asyncio.create_task(self._disconnect_peer(self._client_conn))
        server_task = asyncio.create_task(self._disconnect_peer(self._server_conn))
        await asyncio.gather(client_task, server_task)


if __name__ == '__main__':
    unittest.main()
