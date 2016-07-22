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
from hashlib import sha256
import logging
from pathlib import Path
import os
import sys

from cryptography.hazmat.primitives.hashes import SHA256


from manuale import acme as manuale_acme
from manuale import crypto as manuale_crypto
from manuale import issue as manuale_issue
from manuale import cli as manuale_cli
from manuale import errors as manuale_errors

#--------------- local imports --------------
from pki.config import Pathes, X509atts, LE_SERVER

from pki.utils import sld, sli, sln, sle, options

# --------------- manuale logging ----------------

logger = logging.getLogger(__name__)

#--------------- Places --------------
places = {}

#--------------- classes --------------

class DBStoreException(Exception):
    pass

class KeyCertException(Exception):
    pass

#---------------  prepared SQL queries for create_LE_instance  --------------

q_insert_LE_instance = """
    INSERT INTO CertInstances 
            (certificate, state, cert, key, TLSA, not_before, not_after)
        VALUES ($1::INTEGER, 'issued', $2, $3, $4, $5::TIMESTAMP, $6::TIMESTAMP)
        RETURNING id::int
"""
ps_insert_LE_instance = None

        
#--------------- class Certificate --------------

        
def create_LE_instance(cert_meta):

    global ps_insert_LE_instance

    # Set up logging
    root = logging.getLogger('manuale')
    root.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(handler)

    alt_names = [cert_meta.name, ]
    if len(cert_meta.altnames) > 0:
        alt_names.extend(cert_meta.altnames)

    os.chdir(str(Pathes.work))
    try:
        account = manuale_cli.load_account(str(Pathes.le_account))
    except:
        sle('Problem with Lets Encrypt account data at {}'.format(
                                                str(Pathes.le_account)))
        exit(1)
    if not (cert_meta.authorized_until and
                    cert_meta.authorized_until >= datetime.datetime.now()):
        sle('LE Authorization not yet implemented')                    # needing authorization
        exit(1)
    ##try:
    sli('Creating key (%d bits) and cert for %s %s' %
        (int(X509atts.bits), cert_meta.subject_type, cert_meta.name))
    certificate_key = manuale_crypto.generate_rsa_key(X509atts.bits)
    csr = manuale_crypto.create_csr(certificate_key, alt_names)
    acme = manuale_acme.Acme(LE_SERVER, account)
    try:
        sli('Requesting certificate issuance from LE...')
        result = acme.issue_certificate(csr)
    except IOError as e:
        sle("Connection or service request failed. Aborting.")
        raise ManualeError(e)
    try:
        certificate = manuale_crypto.load_der_certificate(result.certificate)
    except IOError as e:
        sle("Failed to load new certificate. Aborting.")
        raise ManualeError(e)
    ##except:
    ##    return False
    not_valid_before = certificate.not_valid_before
    not_valid_after = certificate.not_valid_after
    sli('Certificate issued. Valid until {}'.format(not_valid_after.isoformat()))
    tlsa_hash = binascii.hexlify(
        certificate.fingerprint(SHA256())).decode('ascii').upper()
    sli('Hash is: {}'.format(tlsa_hash))

    
    if not ps_insert_LE_instance:
        ps_insert_LE_instance = cert_meta.db.prepare(q_insert_LE_instance)
    """
    if not ps_insert_LE_instance:
        cert_meta.db.execute("PREPARE q_insert_LE_instance(integer, text, text, text, timestamp, timestamp) AS " + q_insert_LE_instance)
        ps_insert_LE_instance = cert_meta.db.statement_from_id('q_insert_LE_instance')
    """
    c = manuale_crypto.export_pem_certificate(certificate).decode('ascii')
    if result.intermediate:
        c += manuale_crypto.export_pem_certificate(
            manuale_crypto.load_der_certificate(result.intermediate)).decode('ascii')
    (instance_serial) = ps_insert_LE_instance.first(
            cert_meta.cert_id,
            c,
            manuale_crypto.export_rsa_key(certificate_key).decode('ascii'),
            tlsa_hash,
            not_valid_before,
            not_valid_after)
    if instance_serial:
        return True
    sle('Failed to store new cert in DB backend')
    
    
