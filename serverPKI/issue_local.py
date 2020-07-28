# -*- coding: utf-8 -*-

"""
Copyright (C) 2015-2020  Axel Rau <axel.rau@chaos1.de>

This file is part of serverPKI.

serverPKI is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Foobar is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with serverPKI.  If not, see <http://www.gnu.org/licenses/>.
"""

# issue local certificates


# --------------- imported modules --------------
import datetime
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

# --------------- local imports --------------
from serverPKI.cert import Certificate, CertInstance, CertState
from serverPKI.cacert import get_cacert_and_key
from serverPKI.utils import sld, sli, sln, sle,  Pathes, X509atts


# --------------- public functions --------------


def issue_local_cert(cert_meta: Certificate) -> Optional[CertInstance]:
    """
    Ask local CA to issue a certificate.
    Will ask for a passphrase to access the CA key.
    On success, inserts a row into CertInstances.
    If this is the first local instance, additional rows are inserted
    into Subjects, Certificates and CertInstances for local CA cert.
    Additional Certinstances may also be inserted if the local CA cert
    changes.
    FIXME: Currently only supports rsa keys

    :param cert_meta:   Cert meta instance to issue an certificate for
    :rtype:             cert instance id in DB of new cert or None
    """

    cacert, cakey, cacert_ci = get_cacert_and_key(cert_meta.db)

    sli('Creating key ({} bits) and cert for {} {}. Using CA cert {}'.format(
        int(X509atts.bits),
        cert_meta.subject_type,
        cert_meta.name,
        cacert_ci.row_id)
    )
    serial = x509.random_serial_number()
    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(X509atts.bits),
        backend=default_backend()
    )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cert_meta.name),
    ]))
    builder = builder.issuer_name(x509.Name(
        cacert.subject,
    ))

    not_valid_before = datetime.datetime.utcnow() - datetime.timedelta(
        days=1)
    not_valid_after = datetime.datetime.utcnow() + datetime.timedelta(
        days=X509atts.lifetime)
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)
    builder = builder.serial_number(serial)

    public_key = key.public_key()
    builder = builder.public_key(public_key)

    builder = builder.add_extension(
        x509.BasicConstraints(
            ca=False,
            path_length=None
        ),
        critical=True,
    )

    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    builder = builder.add_extension(
        ski,
        critical=False,
    )

    try:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier.from_public_key(cakey.public_key())),
            critical=False,
        )
    except x509.extensions.ExtensionNotFound:
        sle('Could not add a AuthorityKeyIdentifier, because CA has no SubjectKeyIdentifier')

    if cert_meta.subject_type == 'client':
        alt_names = [x509.RFC822Name(cert_meta.name), ]
    else:
        alt_names = [x509.DNSName(cert_meta.name), ]
    for n in cert_meta.altnames:
        if cert_meta.subject_type == 'client':
            alt_names.append(x509.RFC822Name(n))
        else:
            alt_names.append(x509.DNSName(n))
    builder = builder.add_extension(
        x509.SubjectAlternativeName(
            alt_names
        ),
        critical=False,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True if cert_meta.subject_type == 'server' else False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    )

    eku = None
    if cert_meta.subject_type == 'server':
        eku = x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
    elif cert_meta.subject_type == 'client':
        eku = x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
    if eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                (eku,)
            ),
            critical=True,
        )

    cert = builder.sign(
        private_key=cakey, algorithm=hashes.SHA384(),
        backend=default_backend()
    )
    ci = cert_meta.create_instance(state=CertState('issued'),
                                   not_before=not_valid_before,
                                   not_after=not_valid_after,
                                   ca_cert_ci=cacert_ci
                                   )
    ci.store_cert_key(algo=cert_meta.encryption_algo, cert=cert, key=key)
    cert_meta.save_instance(ci)

    sli('Certificate for {} {}, serial {}, valid until {} created.'.format(
        cert_meta.subject_type,
        cert_meta.name,
        serial,
        not_valid_after.isoformat())
    )

    return ci
