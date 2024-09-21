# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import pytest

from reload.configuration import Configuration, OverlayConfiguration, SelfSignedPermitted
from reload.configuration.xml import (
    Attribute,
    DataElement,
    DataElementList,
    Element,
    ElementList,
    MultiDataElement,
    MultiElement,
    Namespace,
    OptionalAttribute,
    OptionalDataElement,
    OptionalElement,
    TextValue,
    XMLElement,
)
from reload.configuration.xml.datamodel import Int32Adapter, UInt8Adapter, UInt32Adapter


class TestXMLFramework:

    def test_namespaces(self) -> None:
        main_ns = Namespace('main', prefix=None)
        extra_ns = Namespace('extra', prefix='ext')

        class MainElement(XMLElement, namespace=main_ns):
            pass

        class Child(MainElement, name='child'):
            attr = Attribute(int)

        class RootElement(MainElement):
            name = Attribute(str)
            data = DataElement(str, namespace=extra_ns)
            child = Element(Child)

        assert RootElement._associated_namespaces_ == {main_ns, extra_ns}
        assert RootElement._nsmap_ == {None: main_ns, extra_ns.prefix: extra_ns}

    def test_xml_element(self) -> None:
        # An XMLElement that doesn't define its 'name' is abstract and cannot be instantiated
        class AbstractElement(XMLElement):
            pass

        with pytest.raises(TypeError, match=r'Cannot instantiate abstract class .+'):
            AbstractElement()

        with pytest.raises(TypeError, match=r'Cannot instantiate abstract class .+'):
            AbstractElement.from_string('<root/>')

        class RootElement(XMLElement, name='root'):
            attr = Attribute(int)
            data = DataElement(str)

        # When instantiated, only keyword arguments are allowed
        with pytest.raises(TypeError, match=r'XMLElement\.__new__\(\) takes 1 positional argument but 3 were given'):
            RootElement(1, 'data')  # pyright: ignore[reportCallIssue]

        # When instantiated, all provided arguments must correspond to an existing attributes or elements
        with pytest.raises(TypeError, match=r'got an unexpected keyword argument .+'):
            RootElement(other=None)

        # When instantiated, all the mandatory attributes and elements must be provided as arguments
        with pytest.raises(TypeError, match=r'missing a required keyword argument .+'):
            RootElement(attr=1)

        with pytest.raises(TypeError, match=r'The etree element tag does not match .+'):
            RootElement.from_string('<other/>')

        root = RootElement.from_string('<root attr="1"><data>text</data></root>')
        assert root.attr == 1
        assert root.data == 'text'

    def test_attributes(self) -> None:
        class RootElement(XMLElement, name='root'):
            m_attr = Attribute(int, adapter=UInt8Adapter)
            o_attr = OptionalAttribute(int, adapter=Int32Adapter, default=None)

        root = RootElement(m_attr=1)

        assert root.m_attr == 1
        assert root.o_attr is None

        with pytest.raises(TypeError, match=rf'the {RootElement.m_attr.name!r} attribute must be of type {RootElement.m_attr.type.__qualname__}'):
            root.m_attr = ''  # pyright: ignore[reportAttributeAccessIssue]

        with pytest.raises(ValueError, match=r'invalid value .+? for unsigned 8-bit integer'):
            root.m_attr = -1

        with pytest.raises(ValueError, match=r'invalid value .+? for signed 32-bit integer'):
            root.o_attr = 111111111111111111111

        with pytest.raises(AttributeError, match=rf'mandatory attribute {RootElement.m_attr.name!r} cannot be deleted'):
            del root.m_attr

        root.m_attr = c1 = 17
        root.o_attr = c2 = -3
        assert root.m_attr == c1
        assert root.o_attr == c2

        del root.o_attr
        assert root.o_attr is None

        # parsing XML

        with pytest.raises(ValueError, match=r'Missing mandatory attribute .+'):
            RootElement.from_string('<root/>')

        with pytest.raises(ValueError, match=r'Invalid value for attribute .+'):
            RootElement.from_string('<root m_attr="text"/>')

        with pytest.raises(ValueError, match=r'Invalid value for attribute .+'):
            RootElement.from_string('<root m_attr="-1"/>')

        with pytest.raises(ValueError, match=r'Invalid value for attribute .+'):
            RootElement.from_string('<root m_attr="1" o_attr="text"/>')

        with pytest.raises(ValueError, match=r'Invalid value for attribute .+'):
            RootElement.from_string('<root m_attr="1" o_attr="111111111111111111111"/>')

        root = RootElement.from_string('<root m_attr="1"/>')
        assert root.m_attr == 1
        assert root.o_attr is None

    def test_elements(self) -> None:
        class Node(XMLElement, name='node'):
            name = Attribute(str)

        class Point(XMLElement, name='point'):
            x = OptionalAttribute(int, adapter=Int32Adapter, default=0)
            y = OptionalAttribute(int, adapter=Int32Adapter, default=0)

        class Signature(XMLElement, name='signature'):
            value: TextValue[bytes] = TextValue(bytes)

        class RootElement(XMLElement, name='root'):
            node = Element(Node)
            point = OptionalElement(Point)
            signatures = MultiElement(Signature, optional=False)

        root = RootElement(node=Node(name='N7'), signatures=[Signature(value=b'test')])

        assert root.point is None

        # type of value must match element type
        with pytest.raises(TypeError, match=r'the .+? element must be of type .+'):
            root.node = None  # pyright: ignore[reportAttributeAccessIssue]

        with pytest.raises(TypeError, match=r'the .+? element must be of type .+'):
            root.point = 1  # pyright: ignore[reportAttributeAccessIssue]

        with pytest.raises(TypeError, match=r'the .+? element must be of type .+'):
            root.signatures = 'test'  # pyright: ignore[reportAttributeAccessIssue]

        # signatures is not optional, i.e. it must contain at least one element
        with pytest.raises(ValueError, match=rf'the {RootElement.signatures.name!r} element must have at least one item'):
            root.signatures = []

        # this will both assert the type for the test and reset the type for the static type checkers
        # (since we attempted to assign values of different type to this in the tests above)
        assert isinstance(root.signatures, ElementList)

        with pytest.raises(ValueError, match=rf'the {RootElement.signatures.name!r} element must have at least one item'):
            root.signatures.clear()

        with pytest.raises(ValueError, match=rf'the {RootElement.signatures.name!r} element must have at least one item'):
            del root.signatures[0]

        with pytest.raises(ValueError, match=rf'the {RootElement.signatures.name!r} element must have at least one item'):
            root.signatures.remove(root.signatures[0])

        with pytest.raises(AttributeError, match=r'mandatory element .+? cannot be deleted'):
            del root.node

        with pytest.raises(AttributeError, match=r'mandatory element .+? cannot be deleted'):
            del root.signatures

        root.point = Point()
        assert root.point.x == 0
        assert root.point.y == 0

        del root.point
        assert root.point is None

        root.signatures.add(Signature(value=b'extra'))
        assert len(root.signatures) == 2

        root.signatures.remove(root.signatures[0])
        assert len(root.signatures) == 1

        # parsing XML

        with pytest.raises(ValueError, match=rf'Missing mandatory {RootElement.node.type._qualname_!r} element from .+'):
            RootElement.from_string('<root><signature>dGVzdA==</signature></root>')

        with pytest.raises(ValueError, match=rf'Excess elements for {RootElement.node.type._qualname_!r}'):
            RootElement.from_string('<root><node name="N7"/><node name="N7"/><signature>dGVzdA==</signature></root>')

        with pytest.raises(ValueError, match=rf'Excess elements for {RootElement.point.type._qualname_!r}'):
            RootElement.from_string('<root><node name="N7"/><point/><point/><signature>dGVzdA==</signature></root>')

        with pytest.raises(ValueError, match=rf'There must be at least one {RootElement.signatures.type._qualname_!r} element in .+'):
            RootElement.from_string('<root><node name="N7"/></root>')

        root = RootElement.from_string('<root><node name="N7"/><point x="1" y="-1"/><signature>dGVzdA==</signature></root>')
        assert root.node.name == 'N7'
        assert root.point is not None
        assert root.point.x == +1
        assert root.point.y == -1
        assert len(root.signatures) == 1
        assert root.signatures[0].value == b'test'

    def test_data_elements(self) -> None:
        class RootElement(XMLElement, name='root'):
            name = DataElement(str)
            size = OptionalDataElement(int, adapter=UInt32Adapter, default=0)
            notes = MultiDataElement(str, name='note', optional=False)

        root = RootElement(name='N7', notes=['note01'])

        assert root.size == 0

        # type of value must match element type
        with pytest.raises(TypeError, match=r'the .+? element must be of type .+'):
            root.name = None  # pyright: ignore[reportAttributeAccessIssue]

        with pytest.raises(TypeError, match=r'the .+? element must be of type .+'):
            root.size = 'abc'  # pyright: ignore[reportAttributeAccessIssue]

        with pytest.raises(TypeError, match=r'.+? object is not iterable'):
            root.notes = True  # pyright: ignore[reportAttributeAccessIssue]

        with pytest.raises(TypeError, match=r'the .+? element must be of type .+'):
            root.notes = b'abc'  # pyright: ignore[reportAttributeAccessIssue]

        # notes is not optional, i.e. it must contain at least one element
        with pytest.raises(ValueError, match=rf'the {RootElement.notes.name!r} element must have at least one item'):
            root.notes = []

        # this will both assert the type for the test and reset the type for the static type checkers
        # (since we attempted to assign values of different type to this in the tests above)
        assert isinstance(root.notes, DataElementList)

        with pytest.raises(ValueError, match=rf'the {RootElement.notes.name!r} element must have at least one item'):
            root.notes.clear()

        with pytest.raises(ValueError, match=rf'the {RootElement.notes.name!r} element must have at least one item'):
            del root.notes[0]

        with pytest.raises(ValueError, match=rf'the {RootElement.notes.name!r} element must have at least one item'):
            root.notes.remove(root.notes[0])

        with pytest.raises(AttributeError, match=r'mandatory element .+? cannot be deleted'):
            del root.name

        with pytest.raises(AttributeError, match=r'mandatory element .+? cannot be deleted'):
            del root.notes

        with pytest.raises(ValueError, match=r'invalid value .+? for unsigned 32-bit integer'):
            root.size = -1

        root.size = 1
        assert root.size == 1

        del root.size
        assert root.size == 0

        root.notes.add('note02')
        assert root.notes == ['note01', 'note02']

        root.notes.remove('note01')
        assert root.notes == ['note02']

        # parsing XML

        with pytest.raises(ValueError, match=rf'Missing mandatory {RootElement.name.xml_qualname!r} element from .+'):
            RootElement.from_string('<root><note>note01</note></root>')

        with pytest.raises(ValueError, match=rf'Excess elements for {RootElement.name.xml_qualname!r}'):
            RootElement.from_string('<root><name>N7</name><name>N7</name><note>note01</note></root>')

        with pytest.raises(ValueError, match=rf'Excess elements for {RootElement.size.xml_qualname!r}'):
            RootElement.from_string('<root><name>N7</name><size/><size/><note>note01</note></root>')

        with pytest.raises(ValueError, match=rf'Invalid value for element {RootElement.size.xml_qualname!r}'):
            RootElement.from_string('<root><name>N7</name><size/><note>note01</note></root>')

        with pytest.raises(ValueError, match=rf'Invalid value for element {RootElement.size.xml_qualname!r}'):
            RootElement.from_string('<root><name>N7</name><size>-1</size><note>note01</note></root>')

        with pytest.raises(ValueError, match=rf'There must be at least one {RootElement.notes.xml_qualname!r} element in .+'):
            RootElement.from_string('<root><name>N7</name></root>')

        root = RootElement.from_string('<root><name>N7</name><size>1</size><note>note01</note><note>note02</note></root>')
        assert root.name == 'N7'
        assert root.size == 1
        assert root.notes == ['note01', 'note02']

    def test_text_value(self) -> None:
        class RootElement(XMLElement, name='root'):
            value = TextValue(bool)

        root = RootElement(value=True)

        assert root.value is True

        with pytest.raises(TypeError, match=r'the text value for the .+? element must be of type .+'):
            root.value = None  # pyright: ignore[reportAttributeAccessIssue]

        with pytest.raises(AttributeError, match=r'the text value for the .+? element cannot be deleted'):
            del root.value

        # parsing XML

        with pytest.raises(ValueError, match=r'Invalid text value for element .+'):
            RootElement.from_string('<root/>')

        with pytest.raises(ValueError, match=r'Invalid text value for element .+'):
            RootElement.from_string('<root>123</root>')

        with pytest.raises(ValueError, match=r'Invalid text value for element .+'):
            RootElement.from_string('<root>False</root>')

        root = RootElement.from_string('<root>0</root>')
        assert root.value is False

        root = RootElement.from_string('<root> true </root>')
        assert root.value is True


class TestConfiguration:
    xml_configuration = b"""\
<?xml version='1.0' encoding='UTF-8'?>
<overlay xmlns="urn:ietf:params:xml:ns:p2p:config-base" xmlns:chord="urn:ietf:params:xml:ns:p2p:config-chord">
  <configuration instance-name="test.example.com" sequence="1">
    <self-signed-permitted digest="sha1">true</self-signed-permitted>
  </configuration>
</overlay>
"""

    def test_configuration(self) -> None:
        overlay = OverlayConfiguration.from_string(self.xml_configuration)
        assert self.xml_configuration == overlay.to_string()

        config = Configuration(instance_name='test.example.com', sequence=1, self_signed_permitted=SelfSignedPermitted(digest='sha1', value=True))  # pyright: ignore[reportCallIssue]
        overlay = OverlayConfiguration(configurations=[config])
        assert self.xml_configuration == overlay.to_string()
