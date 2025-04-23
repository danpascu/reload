# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from dataclasses import dataclass
from os.path import expanduser, realpath
from ssl import SSLContext
from typing import assert_never

from OpenSSL import SSL

__all__ = 'NodeIdentity',  # noqa: COM818


class PathAttribute:
    name: str = NotImplemented

    def __set_name__(self, owner: type, name: str) -> None:
        if self.name is NotImplemented:
            self.name = name
        elif name != self.name:
            raise TypeError(f'cannot assign the same {self.__class__.__name__} to two different names: {self.name} and {name}')

    def __get__(self, instance: object | None, owner: type | None = None) -> str:
        if instance is None:
            raise AttributeError
        return instance.__dict__[self.name]

    def __set__(self, instance: object, value: str) -> None:
        instance.__dict__[self.name] = realpath(expanduser(value))  # noqa: PTH111


@dataclass(frozen=True)
class NodeIdentity:
    certificate_file: PathAttribute = PathAttribute()
    private_key_file: PathAttribute = PathAttribute()
    authority_file:   PathAttribute = PathAttribute()

    def configure(self, context: SSLContext | SSL.Context) -> None:
        """Configure the SSL context with this object's certificate and authority files"""
        match context:
            case SSLContext():
                context.load_verify_locations(cafile=self.authority_file)
                context.load_cert_chain(certfile=self.certificate_file, keyfile=self.private_key_file)
            case SSL.Context():
                context.load_verify_locations(self.authority_file)
                context.use_certificate_chain_file(self.certificate_file)
                context.use_privatekey_file(self.private_key_file)
                context.check_privatekey()
            case _:
                assert_never(context)
