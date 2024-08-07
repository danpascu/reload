# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime
from typing import Final

from .xml import AnnotatedXMLElement, Attribute, DataElement, Element, MultiDataElement, MultiElement, Namespace, OptionalAttribute, OptionalDataElement, OptionalElement, TextValue
from .xml.datamodel import IntAdapter, LongAdapter, UnsignedByteAdapter, UnsignedIntAdapter

__all__ = 'OverlayConfiguration', 'Configuration', 'SelfSignedPermitted', 'BootstrapNode', 'RequiredKinds', 'KindBlock', 'Kind', 'KindSignature'  # noqa: RUF022


ns_reload: Final[Namespace] = Namespace('urn:ietf:params:xml:ns:p2p:config-base', schema='reload.rng', prefix=None)
ns_chord: Final[Namespace] = Namespace('urn:ietf:params:xml:ns:p2p:config-chord', schema='reload.rng', prefix='chord')


class ReloadElement(AnnotatedXMLElement, namespace=ns_reload):
    pass


class ChordElement(AnnotatedXMLElement, namespace=ns_chord):
    pass


class SelfSignedPermitted(ReloadElement, name='self-signed-permitted'):
    digest: Attribute[str] = Attribute(str)
    value: TextValue[bool] = TextValue(bool)


class BootstrapNode(ReloadElement, name='bootstrap-node'):
    address: Attribute[str] = Attribute(str)
    port: OptionalAttribute[int] = OptionalAttribute(int, default=6084, adapter=IntAdapter)


class Kind(ReloadElement, name='kind'):
    name: OptionalAttribute[str] = OptionalAttribute(str, default=None)
    id: OptionalAttribute[int] = OptionalAttribute(int, default=None, adapter=UnsignedIntAdapter)

    data_model: DataElement[str] = DataElement(str, name='data-model')
    access_control: DataElement[str] = DataElement(str, name='access-control')
    max_count: DataElement[int] = DataElement(int, name='max-count', adapter=IntAdapter)
    max_size: DataElement[int] = DataElement(int, name='max-size', adapter=IntAdapter)
    max_node_multiple: OptionalDataElement[int] = OptionalDataElement(int, name='max-node-multiple', adapter=IntAdapter, default=None)


class KindSignature(ReloadElement, name='kind-signature'):
    algorithm: OptionalAttribute[str] = OptionalAttribute(str, default=None)
    value: TextValue[bytes] = TextValue(bytes)


class KindBlock(ReloadElement, name='kind-block'):
    kind: Element[Kind] = Element(Kind)
    kind_signature: OptionalElement[KindSignature] = OptionalElement(KindSignature)


class RequiredKinds(ReloadElement, name='required-kinds'):
    kind_blocks: MultiElement[KindBlock] = MultiElement(KindBlock, optional=True)


class Signature(ReloadElement, name='signature'):
    algorithm: OptionalAttribute[str] = OptionalAttribute(str, default=None)
    value: TextValue[bytes] = TextValue(bytes)


class Configuration(ReloadElement, name='configuration'):
    instance_name: Attribute[str] = Attribute(str, name='instance-name')
    sequence: OptionalAttribute[int] = OptionalAttribute(int, adapter=LongAdapter, default=None)
    expiration: OptionalAttribute[datetime] = OptionalAttribute(datetime, default=None)

    topology_plugin: OptionalDataElement[str] = OptionalDataElement(str, name='topology-plugin', default='CHORD-RELOAD')
    node_id_length: OptionalDataElement[int] = OptionalDataElement(int, name='node-id-length', default=16, adapter=IntAdapter)
    root_certs: MultiDataElement[bytes] = MultiDataElement(bytes, name='root-cert', optional=True)
    enrollment_servers: MultiDataElement[str] = MultiDataElement(str, name='enrollment-server', optional=True)
    self_signed_permitted: OptionalElement[SelfSignedPermitted] = OptionalElement(SelfSignedPermitted)
    bootstrap_nodes: MultiElement[BootstrapNode] = MultiElement(BootstrapNode, optional=True)
    turn_density: OptionalDataElement[int] = OptionalDataElement(int, name='turn-density', adapter=UnsignedByteAdapter, default=1)
    clients_permitted: OptionalDataElement[bool] = OptionalDataElement(bool, name='clients-permitted', default=True)
    no_ice: OptionalDataElement[bool] = OptionalDataElement(bool, name='no-ice', default=False)

    chord_update_interval: OptionalDataElement[int] = OptionalDataElement(int, namespace=ns_chord, name='chord-update-interval', adapter=IntAdapter, default=600)
    chord_ping_interval: OptionalDataElement[int] = OptionalDataElement(int, namespace=ns_chord, name='chord-ping-interval', adapter=IntAdapter, default=3600)
    chord_reactive: OptionalDataElement[bool] = OptionalDataElement(bool, namespace=ns_chord, name='chord-reactive', default=True)

    shared_secret: OptionalDataElement[str] = OptionalDataElement(str, name='shared-secret', default=None)
    max_message_size: OptionalDataElement[int] = OptionalDataElement(int, name='max-message-size', adapter=UnsignedIntAdapter, default=5000)
    initial_ttl: OptionalDataElement[int] = OptionalDataElement(int, name='initial-ttl', adapter=IntAdapter, default=100)
    overlay_reliability_timer: OptionalDataElement[int] = OptionalDataElement(int, name='overlay-reliability-timer', adapter=IntAdapter, default=3000)
    overlay_link_protocols: MultiDataElement[str] = MultiDataElement(str, name='overlay-link-protocol', optional=True)
    kind_signers: MultiDataElement[str] = MultiDataElement(str, name='kind-signer', optional=True)
    configuration_signers: MultiDataElement[str] = MultiDataElement(str, name='configuration-signer', optional=True)
    bad_nodes: MultiDataElement[str] = MultiDataElement(str, name='bad-node', optional=True)
    mandatory_extensions: MultiDataElement[str] = MultiDataElement(str, name='mandatory-extension', optional=True)
    required_kinds: OptionalElement[RequiredKinds] = OptionalElement(RequiredKinds)


class OverlayConfiguration(ReloadElement, name='overlay'):
    configurations: MultiElement[Configuration] = MultiElement(Configuration, optional=False)
