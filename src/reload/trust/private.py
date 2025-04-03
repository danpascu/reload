# SPDX-FileCopyrightText: 2024-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from os import PathLike
from pathlib import Path
from tempfile import NamedTemporaryFile

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, Encoding, NoEncryption, PrivateFormat, load_pem_private_key

from reload.python import reprproxy
from reload.python.types import MarkerEnum

__all__ = 'KeyType', 'load_private_key', 'save_private_key'


type PrivateKey = Ed25519PrivateKey | Ed448PrivateKey | EllipticCurvePrivateKey


class KeyType(MarkerEnum):
    ED25519 = 'ED25519'
    ED448 = 'ED448'
    ECDSA = 'ECDSA'

    def generate(self) -> PrivateKey:
        match self:
            case KeyType.ED25519:
                return Ed25519PrivateKey.generate()
            case KeyType.ED448:
                return Ed448PrivateKey.generate()
            case KeyType.ECDSA:
                return ec.generate_private_key(ec.SECP256R1())


def load_private_key(path: str | PathLike[str], *, password: str | None = None) -> PrivateKey:
    key_data = Path(path).expanduser().read_bytes()
    key = load_pem_private_key(key_data, password=password.encode() if password is not None else None)
    match key:
        case Ed25519PrivateKey() | Ed448PrivateKey() | EllipticCurvePrivateKey():
            return key
        case _:
            raise TypeError(f'Unsupported key type: {key.__class__.__qualname__!r} (expected {reprproxy(PrivateKey.__value__)})')


def save_private_key(key: PrivateKey, path: str | PathLike[str], *, password: str | None = None) -> None:
    key_encryption = BestAvailableEncryption(password.encode()) if password is not None else NoEncryption()
    key_data = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, key_encryption)
    path = Path(path).expanduser()
    with NamedTemporaryFile(dir=path.parent, delete=False) as tempfile:
        tempfile.write(key_data)
    Path(tempfile.name).replace(path)
