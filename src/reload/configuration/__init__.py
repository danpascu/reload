# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime

from .xml import (
    AnnotatedXMLElement,
    Attribute,
    DataElement,
    Element,
    IntAdapter,
    LongAdapter,
    MultiDataElement,
    MultiElement,
    Namespace,
    NamespaceRegistry,
    OptionalAttribute,
    OptionalDataElement,
    OptionalElement,
    TextValue,
    UnsignedByteAdapter,
    UnsignedIntAdapter,
)

__all__ = 'Overlay', 'Configuration', 'SelfSignedPermitted', 'BootstrapNode', 'RequiredKinds', 'KindBlock', 'Kind', 'KindSignature'  # noqa: RUF022


ns_registry = NamespaceRegistry()

ns_reload = Namespace('urn:ietf:params:xml:ns:p2p:config-base', schema='reload.rng', prefix=None)
ns_chord = Namespace('urn:ietf:params:xml:ns:p2p:config-chord', schema='reload.rng', prefix='chord')

ns_registry.add(ns_reload)
ns_registry.add(ns_chord)


class ReloadElement(AnnotatedXMLElement):
    namespace = ns_reload


class ChordElement(AnnotatedXMLElement):
    namespace = ns_chord


class SelfSignedPermitted(ReloadElement):
    name = 'self-signed-permitted'

    digest: Attribute[str] = Attribute(str)
    value: TextValue[bool] = TextValue(bool)


class BootstrapNode(ReloadElement):
    name = 'bootstrap-node'

    address: Attribute[str] = Attribute(str)
    port: OptionalAttribute[int] = OptionalAttribute(int, default=6084, adapter=IntAdapter)


class Kind(ReloadElement):
    name = 'kind'

    # FIX @dan: decide what to do about name clashes (name, namespace, default, type, ...)
    kind_name: OptionalAttribute[str] = OptionalAttribute(str, name='name', default=None)
    id: OptionalAttribute[int] = OptionalAttribute(int, default=None, adapter=UnsignedIntAdapter)

    data_model: DataElement[str] = DataElement(str, namespace=ns_reload, name='data-model')
    access_control: DataElement[str] = DataElement(str, namespace=ns_reload, name='access-control')
    max_count: DataElement[int] = DataElement(int, namespace=ns_reload, name='max-count', adapter=IntAdapter)
    max_size: DataElement[int] = DataElement(int, namespace=ns_reload, name='max-size', adapter=IntAdapter)
    max_node_multiple: OptionalDataElement[int] = OptionalDataElement(int, namespace=ns_reload, name='max-node-multiple', adapter=IntAdapter, default=None)


class KindSignature(ReloadElement):
    name = 'kind-signature'

    algorithm: OptionalAttribute[str] = OptionalAttribute(str, default=None)
    value: TextValue[str] = TextValue(str)


class KindBlock(ReloadElement):
    name = 'kind-block'

    kind: Element[Kind] = Element(Kind)
    kind_signature: OptionalElement[KindSignature] = OptionalElement(KindSignature)


class RequiredKinds(ReloadElement):
    name = 'required-kinds'

    kind_blocks: MultiElement[KindBlock] = MultiElement(KindBlock, optional=True)


class Signature(ReloadElement):
    name = 'signature'

    algorithm: OptionalAttribute[str] = OptionalAttribute(str, default=None)
    value: TextValue[str] = TextValue(str)


class Configuration(ReloadElement):
    name = 'configuration'

    instance_name: Attribute[str] = Attribute(str, name='instance-name')
    sequence: OptionalAttribute[int] = OptionalAttribute(int, adapter=LongAdapter, default=None)
    expiration: OptionalAttribute[datetime] = OptionalAttribute(datetime, default=None)

    topology_plugin: OptionalDataElement[str] = OptionalDataElement(str, namespace=ns_reload, name='topology-plugin', default='CHORD-RELOAD')
    node_id_length: OptionalDataElement[int] = OptionalDataElement(int, namespace=ns_reload, name='node-id-length', default=16, adapter=IntAdapter)
    root_certs: MultiDataElement[str] = MultiDataElement(str, namespace=ns_reload, name='root-cert', optional=True)
    enrollment_servers: MultiDataElement[str] = MultiDataElement(str, namespace=ns_reload, name='enrollment-server', optional=True)
    self_signed_permitted: OptionalElement[SelfSignedPermitted] = OptionalElement(SelfSignedPermitted)
    bootstrap_nodes: MultiElement[BootstrapNode] = MultiElement(BootstrapNode, optional=True)
    turn_density: OptionalDataElement[int] = OptionalDataElement(int, namespace=ns_reload, name='turn-density', adapter=UnsignedByteAdapter, default=1)
    clients_permitted: OptionalDataElement[bool] = OptionalDataElement(bool, namespace=ns_reload, name='clients-permitted', default=True)
    no_ice: OptionalDataElement[bool] = OptionalDataElement(bool, namespace=ns_reload, name='no-ice', default=False)

    chord_update_interval: OptionalDataElement[int] = OptionalDataElement(int, namespace=ns_chord, name='chord-update-interval', adapter=IntAdapter, default=600)
    chord_ping_interval: OptionalDataElement[int] = OptionalDataElement(int, namespace=ns_chord, name='chord-ping-interval', adapter=IntAdapter, default=3600)
    chord_reactive: OptionalDataElement[bool] = OptionalDataElement(bool, namespace=ns_chord, name='chord-reactive', default=True)

    shared_secret: OptionalDataElement[str] = OptionalDataElement(str, namespace=ns_reload, name='shared-secret', default=None)
    max_message_size: OptionalDataElement[int] = OptionalDataElement(int, namespace=ns_reload, name='max-message-size', adapter=UnsignedIntAdapter, default=5000)
    initial_ttl: OptionalDataElement[int] = OptionalDataElement(int, namespace=ns_reload, name='initial-ttl', adapter=IntAdapter, default=100)
    overlay_reliability_timer: OptionalDataElement[int] = OptionalDataElement(int, namespace=ns_reload, name='overlay-reliability-timer', adapter=IntAdapter, default=3000)
    overlay_link_protocols: MultiDataElement[str] = MultiDataElement(str, namespace=ns_reload, name='overlay-link-protocol', optional=True)
    kind_signers: MultiDataElement[str] = MultiDataElement(str, namespace=ns_reload, name='kind-signer', optional=True)
    configuration_signers: MultiDataElement[str] = MultiDataElement(str, namespace=ns_reload, name='configuration-signer', optional=True)
    bad_nodes: MultiDataElement[str] = MultiDataElement(str, namespace=ns_reload, name='bad-node', optional=True)
    mandatory_extensions: MultiDataElement[str] = MultiDataElement(str, namespace=ns_reload, name='mandatory-extension', optional=True)


class Overlay(ReloadElement):
    name = 'overlay'
    nsmap = ns_registry.nsmap

    configurations: MultiElement[Configuration] = MultiElement(Configuration, optional=False)
