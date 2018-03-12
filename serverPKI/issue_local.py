# -*- coding: utf-8 -*-

"""
Copyright (C) 2015-2017  Axel Rau <axel.rau@chaos1.de>

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


#--------------- imported modules --------------
import binascii
import datetime
import logging
from pathlib import Path
import os
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID


from OpenSSL import crypto

TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA


#--------------- local imports --------------
from serverPKI.config import Pathes, X509atts
from serverPKI.cacert import get_cacert_and_key
from serverPKI.utils import sld, sli, sln, sle, options, encrypt_key
from serverPKI.utils import insert_certinstance, update_certinstance


#--------------- classes --------------

class DBStoreException(Exception):
    pass

class KeyCertException(Exception):
    pass

        
#--------------- public functions --------------

    
def issue_local_cert(cert_meta):
    """
    Ask local CA to issue a certificate.
    Will ask for a passphrase to access the CA key.
    On success, inserts a row into CertInstances.
    If this is the first local instance, additional rows are inserted
    into Subjects, Certificates and CertInstances for local CA cert.
    Additional Certinstances may also be inserted if the local CA cert
    changes.
    
    @param cert_meta:   Cert meta instance to issue an certificate for
    @type cert_meta:    Cert meta instance
    @rtype:             cert instance id in DB of new cert or None
    @exceptions:        DBStoreException
    """
    
    (cacert, cakey, cacert_id) = get_cacert_and_key(cert_meta.db)
    
    instance_serial = insert_certinstance(cert_meta.db, cert_meta.cert_id)
    if not instance_serial:
        raise DBStoreException('?Failed to store new Cerificate in the DB' )
    else:
        sld('Serial of new certificate is {}'.format(instance_serial))    

    sli('Creating key ({} bits) and cert for {} {}'.format(
            int(X509atts.bits),
            cert_meta.subject_type,
            cert_meta.name)
    )
    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(X509atts.bits),
        backend=default_backend()
    )
    # convert it to storage format
    key_pem = encrypt_key(key)
    if not key_pem: # no encryption of keys in DB in use
        key_pem = key.private_bytes(
             encoding=serialization.Encoding.PEM,
             format=serialization.PrivateFormat.TraditionalOpenSSL,
             encryption_algorithm=serialization.NoEncryption())

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
    builder = builder.serial_number(int(instance_serial))
    
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
        ska = cacert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        builder = builder.add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    ska),
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
                    digital_signature = True,
                    key_encipherment = True if cert_meta.subject_type == 'server' else False,
                    content_commitment = False,
                    data_encipherment = False,
                    key_agreement = False,
                    key_cert_sign = False,
                    crl_sign = False,
                    encipher_only = False,
                    decipher_only = False
                ),
                critical=True,
    )
    
    eku = None
    if cert_meta.subject_type == 'server': eku = x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
    elif cert_meta.subject_type == 'client': eku = x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
    if eku:
        builder = builder.add_extension(
                x509.ExtendedKeyUsage(
                    (eku,)
               ),
                critical=True,
        )
    
    cert = builder.sign(
        private_key=cakey, algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    
    # convert our cert to PEM format to store in DB backend for safe keeping.
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    sli('Certificate for {} {}, serial {}, valid until {} created.'.format(
                    cert_meta.subject_type,
                    cert_meta.name,
                    instance_serial,
                    not_valid_after.isoformat())
    )
    tlsa_hash = binascii.hexlify(
        cert.fingerprint(hashes.SHA256())).decode('ascii').upper()
    
    
    (updates) = update_certinstance(
                cert_meta.db,
                instance_serial,
                cert_pem,
                key_pem,
                tlsa_hash,
                not_valid_before,
                not_valid_after,
                cacert_id
    )
    if updates != 1:
        raise DBStoreException('?Failed to store certificate in DB')

    return instance_serial
