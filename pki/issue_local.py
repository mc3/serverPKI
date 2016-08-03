# -*- coding: utf-8 -*-

"""
 Copyright (c) 2006-2014 Axel Rau, axel.rau@chaos1.de
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:

    - Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    - Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

"""

# serverpki Certificate class module
# requires python 3.4.

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


from OpenSSL import crypto,rand,crypto

TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA


#--------------- local imports --------------
from pki.config import Pathes, X509atts
from pki.cacert import get_cacert_and_key
from pki.utils import sld, sli, sln, sle, options
from pki.utils import insert_certinstance, update_certinstance

#--------------- Places --------------
places = {}

#--------------- classes --------------

class DBStoreException(Exception):
    pass

class KeyCertException(Exception):
    pass

        
#--------------- public functions --------------

    
def issue_local_cert(cert_meta):
    
    (cacert, cakey) = get_cacert_and_key(cert_meta.db)
    
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
    )
    if updates != 1:
        raise DBStoreException('?Failed to store certificate in DB')

    return True
