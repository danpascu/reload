# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import asyncio
import unittest
from typing import ClassVar

from OpenSSL.crypto import X509
from OpenSSL.SSL import Context

from reload import link, trust
from reload.messages.datamodel import NodeID


class _TestIdentity:
    overlay_domain: ClassVar[str] = 'test.link'

    def __init__(self, authority: trust.CA) -> None:
        node_id = NodeID.generate()
        email = f'{node_id.hex()}@{self.overlay_domain}'
        private_key = trust.KeyType.ECDSA.generate()
        signing_request = trust.x509.certificate_signing_request(private_key)
        certificate = authority.issue_node_certificate(signing_request, email=email, node_id=node_id, overlay_domain=self.overlay_domain)
        self._authority = authority
        self._private_key = private_key
        self._certificate = certificate

    def configure(self, context: Context) -> None:
        store = context.get_cert_store()
        assert store is not None
        store.add_cert(X509.from_cryptography(self._authority.certificate))
        context.use_certificate(self._certificate)
        context.use_privatekey(self._private_key)
        context.check_privatekey()


class TestDTLS(unittest.IsolatedAsyncioTestCase):

    def setUp(self) -> None:
        link.DTLSLink.stun_server = None
        subject = trust.x509.Subject(organization='RELOAD', organizational_unit='Trust PKI', common_name=f'Test CA #{NodeID.generate().hex()[:16]}')
        self._authority = trust.CA.new(subject=subject.name)
        self._client_identity = _TestIdentity(self._authority)
        self._server_identity = _TestIdentity(self._authority)
        self._client_conn = link.DTLSLink(purpose=link.Purpose.AttachResponse, identity=self._client_identity)
        self._server_conn = link.DTLSLink(purpose=link.Purpose.AttachRequest, identity=self._server_identity)

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
    async def _connect_peer(conn: link.DTLSLink, ice_peer: link.ICEPeer) -> None:
        await conn.connect(ice_peer)

    @staticmethod
    async def _disconnect_peer(conn: link.DTLSLink) -> None:
        await conn.close()

    async def test_dtls(self) -> None:
        client_message = await self._server_conn.receive()
        server_message = await self._client_conn.receive()
        assert client_message == b'client message'
        assert server_message == b'server message'

    def tearDown(self) -> None:
        pass

    async def asyncTearDown(self) -> None:
        client_task = asyncio.create_task(self._disconnect_peer(self._client_conn))
        server_task = asyncio.create_task(self._disconnect_peer(self._server_conn))
        await asyncio.gather(client_task, server_task)
