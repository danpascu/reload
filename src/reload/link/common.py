# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from dataclasses import dataclass
from os.path import expanduser, realpath
from OpenSSL.SSL import Context


__all__ = 'NodeIdentity',


class PathAttribute:
    def __init__(self):
        self.name = None

    def __set_name__(self, owner, name):
        assert self.name is None or name == self.name
        self.name = name

    def __get__(self, instance, owner=None):
        if instance is None:
            raise AttributeError
        return instance.__dict__[self.name]

    def __set__(self, instance, value):
        instance.__dict__[self.name] = realpath(expanduser(value))


@dataclass(frozen=True)
class NodeIdentity:
    certificate_file: PathAttribute = PathAttribute()
    private_key_file: PathAttribute = PathAttribute()
    authority_file:   PathAttribute = PathAttribute()

    def configure(self, context: Context):
        """Configure the SSL context with this object's certificate and authority files"""
        context.load_verify_locations(self.authority_file)
        context.use_certificate_chain_file(self.certificate_file)
        context.use_privatekey_file(self.private_key_file)
