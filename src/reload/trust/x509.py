# SPDX-FileCopyrightText: 2024-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later


from collections.abc import Iterable
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime, timedelta
from functools import cached_property
from os import PathLike
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Self, assert_never

import idna
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate, CertificateBuilder, CertificateSigningRequest, GeneralName, Name
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from reload.messages.datamodel import NodeID
from reload.python import reprproxy

from .private import KeyType, PrivateKey

__all__ = 'CA', 'Subject', 'load_certificate', 'save_certificate'


type PublicKey = Ed25519PublicKey | Ed448PublicKey | EllipticCurvePublicKey


@dataclass(kw_only=True)
class Subject:
    country: str | None = field(default=None, metadata={'OID': NameOID.COUNTRY_NAME})
    state_or_province: str | None = field(default=None, metadata={'OID': NameOID.STATE_OR_PROVINCE_NAME})
    locality: str | None = field(default=None, metadata={'OID': NameOID.LOCALITY_NAME})
    organization: str | None = field(default=None, metadata={'OID': NameOID.ORGANIZATION_NAME})
    organizational_unit: str | None = field(default=None, metadata={'OID': NameOID.ORGANIZATIONAL_UNIT_NAME})
    common_name: str | None = field(default=None, metadata={'OID': NameOID.COMMON_NAME})
    email_address: str | None = field(default=None, metadata={'OID': NameOID.EMAIL_ADDRESS})

    @property
    def name(self) -> Name:
        return Name(x509.NameAttribute(field.metadata['OID'], value) for field in fields(self) if (value := getattr(self, field.name)) is not None)


@dataclass
class CA:
    private_key: PrivateKey
    certificate: Certificate

    def __post_init__(self) -> None:
        if self.private_key.public_key() != self.certificate.public_key():
            raise ValueError('The certificate and the private key do not match each other!')
        if not self.certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError('The certificate is not a CA!')

    @cached_property
    def path_length(self) -> int | None:
        return self.certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length

    @classmethod
    def new(cls, subject: Name, private_key: KeyType | PrivateKey = KeyType.ED25519, parent_ca: Self | None = None, path_length: int | None = None, years: int | None = None) -> Self:
        if not subject:
            raise ValueError('The subject name must have at least one name attribute')
        if path_length is not None and path_length < 0:
            raise ValueError('The path_length argument must be a non-negative integer or None')
        if parent_ca is not None:
            if parent_ca.path_length is not None:
                if parent_ca.path_length == 0:
                    raise ValueError('The parent CA cannot create any other intermediary CAs')
                if path_length is not None and path_length >= parent_ca.path_length:
                    raise ValueError(f'path_length must be smaller than the parent CA path_length (requested value: {path_length}, parent CA value: {parent_ca.path_length})')
                max_path_length = parent_ca.path_length - 1
                path_length = max_path_length if path_length is None else min(path_length, max_path_length)
            issuer = parent_ca.certificate.subject
            years = years or 10
            start_date = datetime.now(tz=UTC)
            end_date = min(start_date.replace(year=start_date.year + years), parent_ca.certificate.not_valid_after_utc)
        else:
            issuer = subject
            years = years or 30
            start_date = datetime.now(tz=UTC)
            end_date = start_date.replace(year=start_date.year + years)

        if isinstance(private_key, KeyType):
            private_key = private_key.generate()

        public_key = private_key.public_key()

        cert_builder = CertificateBuilder(
            issuer_name=issuer,
            subject_name=subject,
            public_key=public_key,
            serial_number=x509.random_serial_number(),
            not_valid_before=start_date,
            not_valid_after=end_date,
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        if parent_ca is not None:
            certificate = cert_builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(parent_ca.certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value),
                critical=False,
            ).sign(parent_ca.private_key, algorithm=_hash_algorithm(parent_ca.private_key))
        else:
            certificate = cert_builder.sign(private_key, algorithm=_hash_algorithm(private_key))

        return cls(private_key, certificate)

    def sign_request(self, request: CertificateSigningRequest, *, subject: Name, identities: Iterable[GeneralName], days: int = 365) -> Certificate:
        if not request.is_signature_valid:
            raise ValueError('The certificate signing request signature is not valid')
        if not (identities := list(identities)):
            raise ValueError('The certificate needs to have at least one identity')

        public_key = request.public_key()
        match public_key:
            case Ed25519PublicKey() | Ed448PublicKey():
                key_agreement = False
            case EllipticCurvePublicKey():
                key_agreement = True
            case _:
                raise ValueError(f'Invalid key type in request: {public_key.__class__.__qualname__!r} (expected {reprproxy(PublicKey.__value__)})')

        start_date = datetime.now(tz=UTC)
        end_date = start_date + timedelta(days=days)
        if end_date > self.certificate.not_valid_after_utc:
            raise ValueError(f'The requested period of {days} days exceeds the lifetime of this certificate authority')

        cert_builder = CertificateBuilder(
            issuer_name=self.certificate.subject,
            subject_name=subject,
            public_key=public_key,
            serial_number=x509.random_serial_number(),
            not_valid_before=start_date,
            not_valid_after=end_date,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=key_agreement,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            # RFC 5280, section 4.1.2.6: If subject naming information is present only in the SubjectAlternativeName
            # extension, (e.g., a key bound only to an email address or URI), then the subject name MUST be an empty
            # sequence and the SubjectAlternativeName extension MUST be critical. When subject is not empty, it MUST
            # be unique for each subject entity certified by the one CA as defined by the issuer field.
            x509.SubjectAlternativeName(identities),
            critical=not subject,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(self.certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value),
            critical=False,
        )

        return cert_builder.sign(self.private_key, algorithm=_hash_algorithm(self.private_key))

    def issue_node_certificate(self, request: CertificateSigningRequest, *, email: str, node_id: NodeID, overlay_domain: str, days: int = 365, add_common_name: bool = True) -> Certificate:
        user_identity = _email_address_to_name(email)
        node_identity = x509.UniformResourceIdentifier(f'reload://{node_id.hex()}@{idna_encode(overlay_domain)}')
        return self.sign_request(request, subject=Subject(common_name=node_id.hex() if add_common_name else None).name, identities=[node_identity, user_identity], days=days)


def _hash_algorithm(key: PrivateKey) -> hashes.SHA256 | None:
    """Return a hash algorithm that is suitable for signing with the key"""
    match key:
        case Ed25519PrivateKey() | Ed448PrivateKey():
            return None
        case EllipticCurvePrivateKey():
            return hashes.SHA256()
        case _:
            assert_never(key)


def _email_address_to_name(email: str) -> GeneralName:
    if email.count('@') != 1:
        raise ValueError(f'Invalid email address: {email!r}')
    username, _, domain = email.partition('@')
    if not username.isascii():
        # NOTE @dan: Add support for unicode username (requires cryptography >= 45.0.0 w/ SMTP_UTF8_MAILBOX, but is not supported by RFC 6940)
        raise ValueError('Unicode characters in the username part of the email address are not supported')
    return x509.RFC822Name(f'{username}@{idna_encode(domain)}')


def idna_encode(string: str, /) -> str:
    """Turn a string into an ASCII representation by encoding it with IDNA"""
    return idna.encode(string, uts46=True).decode('ascii')


def load_certificate(path: str | PathLike[str]) -> Certificate:
    return x509.load_pem_x509_certificate(Path(path).expanduser().read_bytes())


def save_certificate(certificate: Certificate, path: str | PathLike[str]) -> None:
    certificate_data = certificate.public_bytes(Encoding.PEM)
    path = Path(path).expanduser()
    with NamedTemporaryFile(dir=path.parent, delete=False) as tempfile:
        tempfile.write(certificate_data)
    Path(tempfile.name).replace(path)
    path.chmod(0o644)
