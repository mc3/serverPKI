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
import datetime
from hashlib import sha256
import logging
from pathlib import Path
import os
import sys

from OpenSSL import crypto,rand,crypto

TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA


#--------------- local imports --------------
from pki.config import Pathes, X509atts

from pki.utils import sld, sli, sln, sle, options

#--------------- Places --------------
places = {}

#--------------- classes --------------

class DBStoreException(Exception):
    pass

class KeyCertException(Exception):
    pass

#---------------  prepared SQL queries for create_local_instance  --------------

q_insert_instance = """
    INSERT INTO CertInstances (certificate, state, cert, key, TLSA)
        VALUES ($1::INTEGER, 'reserved', '', '', '')
        RETURNING id::int
"""
q_update_instance = """
    UPDATE CertInstances 
        SET state = 'issued',
            cert = $2,
            key = $3, 
            TLSA = $4,
            not_before = CURRENT_DATE::DATE,
            not_after = $5::DATE
        WHERE id = $1
"""

ps_insert_instance = None
ps_update_instance = None

        
#--------------- public functions --------------

    
def create_local_instance(cert_meta):
    
    global ps_insert_instance, ps_update_instance
    
    if not cert_meta._get_cacert(): return False
    
    sli('Creating key (%d bits) and cert for %s %s and loading %d bytes of random data...' %
            (int(X509atts.bits), cert_meta.subject_type, cert_meta.name, int(X509atts.bits)))
    rand.load_file(b'/dev/urandom', X509atts.bits)
    if not rand.status:
        sle('Random device failed to produce enough entropy')
        return False
    pkey = _createKeyPair(cert_meta, TYPE_RSA, X509atts.bits)
    name_dict = X509atts.names
    name_dict['CN'] = cert_meta.name
    req = _createCertRequest(pkey, 'SHA256', name_dict)
    
    if not ps_insert_instance:
        cert_meta.db.execute("PREPARE q_insert_instance(integer) AS " + q_insert_instance)
        ps_insert_instance = cert_meta.db.statement_from_id('q_insert_instance')
    (instance_serial) = ps_insert_instance.first(cert_meta.cert_id)
    if not instance_serial:
        raise DBStoreException('?Failed to store new Cerificate in the DB' )
    else:
        sld('Serial of new certificate is {}'.format(instance_serial))    
    alt_names = [cert_meta.name, ]
    if len(cert_meta.altnames) > 0:
        alt_names.extend(cert_meta.altnames)

    lifetime_days = X509atts.lifetime/(60*60*24)
    not_after = datetime.date.today()+datetime.timedelta(days=lifetime_days)
    sld('Certificate expires after {} days, which will be at {}'.format(
                                                lifetime_days, not_after))

    cert = _createLocalCertificate(cert_meta, req, instance_serial,
            datetime.date.today(), not_after, alt_names, digest='SHA256')
    
    #?# hostname = cert_meta.name[2:] if cert_meta.name.startswith('*.') else cert_meta.name
    #'store(hostname, cert_meta.subject_type, cert_meta.cacert_text, cert, pkey, cert_meta)
    
    key_text = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
    cert_text = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

    tlsa_hash = sha256(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)).hexdigest()

    if not ps_update_instance:
        ps_update_instance = cert_meta.db.prepare(q_update_instance)
        
    (updates) = ps_update_instance.first(
                instance_serial, cert_text.decode('ascii'),
                key_text.decode('ascii'), tlsa_hash, not_after)
    if updates != 1:
        raise DBStoreException('?Failed to store certificate in DB')
    sli('Cert for %s, serial %d/%x created' % (cert_meta.name, instance_serial, instance_serial))
    return True
    
def _createLocalCertificate(cert_meta, req, serial, notBefore, notAfter, alt_names, digest="sha1"):
    """
    Generate a certificate given a certificate request.

    Arguments: req        - Certificate request to use
               serial     - Serial number for the certificate
               notBefore  - Timestamp (relative to now) when the certificate
                            starts being valid
               notAfter   - Timestamp (relative to now) when the certificate
                            stops being valid
               digest     - Digest method to use for signing
    Returns:   The signed certificate in an X509 object
    """
    cert = crypto.X509()
    cert.set_version(2)         # X509.v3
    cert.set_serial_number(serial)
    try:
    	assert cert.get_serial_number()==serial		# something is wrong here
    except AssertionError:
    	sle('Internal inconsitency: serial is %d/%x but should be %d/%x', (
    		cert.get_serial_number(), cert.get_serial_number(), serial, serial))
    
    notBefore_text = str('{:04}{:02}{:02}000000Z'.format(
                            notBefore.year,notBefore.month,notBefore.day))
    notAfter_text = str('{:04}{:02}{:02}000000Z'.format(
                            notAfter.year,notAfter.month,notAfter.day))
    cert.set_notBefore(notBefore_text.encode('ascii'))
    cert.set_notAfter(notAfter_text.encode('ascii'))
    
    cert.set_issuer(cert_meta.cacert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    
    subj_altnames = ''
    delim = ''
    for alt_name in alt_names:
        subj_altnames += delim + 'DNS:' + alt_name
        delim = ','
    cert.add_extensions((
        # If critical=True then gives error: error 26 at 0 depth lookup:unsupported certificate purpose
        crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert_meta.cacert),
        crypto.X509Extension(b'basicConstraints', True, b'CA:false', subject=cert_meta.cacert),
        crypto.X509Extension(b'keyUsage', True, b'digitalSignature,keyEncipherment' 
                                    if cert_meta.subject_type == 'server' else b'digitalSignature'),
        crypto.X509Extension(b'extendedKeyUsage', True, b'serverAuth'
                                    if cert_meta.subject_type  == 'server' else b'clientAuth'),
        crypto.X509Extension(b'subjectAltName', True, bytes(subj_altnames, 'ascii'))))
    try:
        cert.sign(cert_meta.cakey, digest)
    except KeyCertException:
        sle('Wrong pass phrase')
        sys.exit(1) 
    return cert

def _createKeyPair(cert_meta, type, bits):
    """
    Create a public/private key pair.

    Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
               bits - Number of bits to use in the key
    Returns:   The public/private key pair in a PKey object
    """
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey

def _createCertRequest(pkey, digest, name_dict):
    """
    Create a certificate request.

    Arguments: pkey   - The key to associate with the request
               digest - Digestion method to use for signing, default is md5
               **name - The name of the subject of the request, possible
                        arguments are:
                          C     - Country name
                          ST    - State or province name
                          L     - Locality name
                          O     - Organization name
                          OU    - Organizational unit name
                          CN    - Common name
                          emailAddress - E-mail address
    Returns:   The certificate request in an X509Req object
    """
    req = crypto.X509Req()
    subj = req.get_subject()

    for (key,value) in name_dict.items():
        setattr(subj, key, value)

    req.set_pubkey(pkey)
    req.sign(pkey, digest)
    return req
    
