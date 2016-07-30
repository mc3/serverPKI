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

# serverpki db primitives module
# requires python 3.4.

#--------------- imported modules --------------

import binascii
import datetime
import getpass
import sys
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

#--------------- local imports --------------
from pki.config import Pathes, X509atts, LE_SERVER, SUBJECT_LOCAL_CA
from pki.config import LOCAL_CA_BITS, LOCAL_CA_LIFETIME
from pki.utils import sld, sli, sln, sle
from pki.utils import insert_certinstance, update_certinstance


ps_insert_instance = None
ps_update_instance = None

# ----------------- globals --------------------

local_cacert = None
local_cakey = None

#--------------- classes --------------

class DBStoreException(Exception):
    pass

#--------------- public functions --------------

def get_cacert_and_key(db):
    """
    Return a valied local certificate and a loaded private key.
    If necessary, create a local CAcert or read a historical one from disk.
    Store Cacert in DB creating necessary rows in Subjects, Certificates
    and Certinstances.
    
    @param db:          open database connection in readwrite transaction
    @type db:           pki.db.DbConnection instance
    @rtype:             Tuple of cacert and cakey or tuple of None, None
    @exceptions:
    """
    
    global local_cacert, local_cakey

    if local_cacert and local_cakey:
        return (local_cacert, local_cakey)

    retval = _query_cacert(db)
    if retval:
        (cacert_pem, cakey_pem) = retval
        ##sld('cert:\d{}\nkey:\n{}'.format(cacert_pem.decode('utf-8'), cakey_pem.decode('utf-8')))
        cacert = x509.load_pem_x509_certificate(
                data = cacert_pem,
                backend = default_backend()
        )
        cakey = _load_cakey(cakey_pem)
        if not cakey:
            sle('Can''t create certificates without passphrase')
            exit(1)
        local_cacert, local_cakey = cacert, cakey
        return (cacert, cakey)
        
    # create rows for cacert meta and instance
    cacert_instance_id = create_CAcert_meta(db, 'local', SUBJECT_LOCAL_CA)
    if not cacert_instance_id:
        raise DBStoreException('?Failed to store certificate in DB')
    
    # do we have a historical CA cert on disk?
    if Pathes.ca_cert.exists() and Pathes.ca_key.exists:
        sli('Using CA key at {}'.format(Pathes.ca_key))
        
        with Path.open(Pathes.ca_cert, 'rb') as f:
            cacert_pem = f.read()
        cacert = x509.load_pem_x509_certificate(cacert_pem, default_backend())
        with Path.open(Pathes.ca_key, 'rb') as f:
            cakey_pem = f.read()
        cakey = _load_cakey(cakey_pem)
    
    else:                           # no - crate one
        sln('No CA cert found. Creating one.')
        match = False
        while not match:
            sli('Please enter passphrase for new CA cert (ASCII only).')
            try:
                pp1 = getpass.getpass(prompt='passphrase: ')
            except UnicodeDecodeError:
                sle('None-ASCII character found.')
                continue
            if pp1 == '':
                sln('Passphrases must not be empty.')
                continue
            sli('Please enter it again.')
            try:
                pp2 = getpass.getpass(prompt='passphrase: ')
            except UnicodeDecodeError:
                pass
            if pp1 == pp2:
                match = True
            else:
                sln('Both passphrases differ.')
        
        # Generate our key
        cakey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=LOCAL_CA_BITS,
            backend=default_backend()
        )
        # convert our key to PEM format to store in DB backend for safe keeping
        cakey_pem = cakey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    pp1.encode('utf-8')
                )
            )
    
        # Various details about who we are. For a self-signed certificate the
        # subject and issuer are always the same.
        name_dict = X509atts.names
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, name_dict['C']),
            x509.NameAttribute(NameOID.LOCALITY_NAME, name_dict['L']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, name_dict['O']),
            x509.NameAttribute(NameOID.COMMON_NAME, name_dict['CN']),
        ])
        
        not_valid_after = datetime.datetime.utcnow() + datetime.timedelta(
                                                        days=LOCAL_CA_LIFETIME)
        not_valid_before = datetime.datetime.utcnow() - datetime.timedelta(
                                                        days=1)
        ski = x509.SubjectKeyIdentifier.from_public_key(cakey.public_key())

        cacert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            cakey.public_key()
        ).serial_number(
            cacert_instance_id
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            # Our certificate will be valid for 10 days
            not_valid_after
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).add_extension(
        # CA and no intermediate CAs
            x509.BasicConstraints(
                ca=True,
                path_length=0),
            critical=True
        ).add_extension(
            ski,
            critical=False,
        # Sign our certificate with our private key
        ).sign(cakey, hashes.SHA256(), default_backend())
        
        # convert our cert to PEM format to store in DB backend for safe keeping.
        cacert_pem = cacert.public_bytes(serialization.Encoding.PEM)
        sli('CA cert serial {} with {} bit key, valid until {} created.'.format(
                        cacert_instance_id,
                        LOCAL_CA_BITS,
                        not_valid_after.isoformat()
        ))

    ##sld('cert:\d{}\nkey:\n{}'.format(cacert_pem.decode('utf-8'), cakey_pem.decode('utf-8')))

    tlsa_hash = binascii.hexlify(
        cacert.fingerprint(hashes.SHA256())).decode('ascii').upper()
    sli('Hash is: {}'.format(tlsa_hash))

    not_before = cacert.not_valid_before
    not_after = cacert.not_valid_after
                
    (updates) = update_certinstance(
                db,
                cacert_instance_id,
                cacert_pem,
                cakey_pem,
                tlsa_hash,
                not_before,
                not_after
    )
    if updates != 1:
        raise DBStoreException('?Failed to store certificate in DB')

    local_cacert = cacert
    local_cakey = cakey
    return (cacert, cakey)



#--------------- load private key and query passphrase --------------

def _load_cakey(cakey_pem):

    cakey = None
    
    def _load_it(cakey_pem, passphrase):
        cakey = serialization.load_pem_private_key(
                    data=cakey_pem,
                    password=passphrase,
                    backend=default_backend())
        return cakey
    
    try:
        cakey = _load_it(cakey_pem, None)
    except (TypeError):   # needing passphrase
    
        sli('Please enter passphrase to unlock key of CA cert.')
        
        while not cakey:
            pp1 = getpass.getpass(prompt='passphrase (empty to abort): ')
            if pp1 == '':
                return None
            try:
                cakey = _load_it(cakey_pem, pp1.encode('utf-8'))
            except (TypeError, ValueError, UnicodeDecodeError):
                sle('Wrong passphrase. Please retry')
       
    return cakey
        
#--------------- query CA cert in DB --------------
#--------------- queries --------------

q_cacert = """
    SELECT ca.cert, ca.key
        FROM Subjects s, Certificates c, Certinstances ca
        WHERE
            s.type = 'CA' AND
            s.certificate = c.id AND
            c.type = 'local' AND
            ca.certificate = c.id AND
            ca.not_before <= 'TODAY'::DATE AND
            ca.not_after >= 'TODAY'::DATE
        ORDER BY ca.id DESC
        LIMIT 1
"""

#--------------- function --------------

def _query_cacert(db):
    """
    Return the most recent valid CA cert for provided cert meta.
    
    @param db:          open database connection
    @type db:           pki.db.DbConnection instance
    @rtype:             Tuple of bytes, bytes (cacert and cakey) or None
    @exceptions:
    """
    
    ps_cacert = db.prepare(q_cacert)
    retval = ps_cacert.first()
    return retval       # return tuple or None


#--------------- queries --------------

q_query_CA_subject_and_certificate = """
    SELECT c.id
        FROM certificates c, subjects s
        WHERE
            s.type = 'CA' AND
            c.type = $1 AND
            s.certificate = c.id
"""
q_insert_cacert = """
    INSERT INTO Certificates(type)
        VALUES ($1)
        RETURNING id::int
"""
q_insert_cacert_subject = """
    INSERT INTO Subjects(type, name, isAltName, certificate)
        VALUES ($1, $2, FALSE, $3)
        RETURNING id::int
"""
q_insert_cacert_instance = """
    INSERT INTO CertInstances (certificate, state, cert, key, hash)
        VALUES ($1::INTEGER, 'reserved', '', '', '')
        RETURNING id::int
"""

ps_query_CA_subject_and_certificate = None

#--------------- function --------------

def create_CAcert_meta(db, cert_type, name):
    
    global ps_query_CA_subject_and_certificate
    
    if not ps_query_CA_subject_and_certificate:
        ps_query_CA_subject_and_certificate = \
            db.prepare(q_query_CA_subject_and_certificate)
    certificate_id = ps_query_CA_subject_and_certificate.first(cert_type)
    
    if not certificate_id:      # no subject and certifcate - create both
        ps = db.prepare(q_insert_cacert)
        certificate_id = ps.first(cert_type)
        if not certificate_id:
            sle('Failed to create row in Certificates for {}'.format(name))
            return None
        ps = db.prepare(q_insert_cacert_subject)
        subject_id = ps.first('CA', name, certificate_id)
        if not subject_id:
            sle('Failed to create row in Subjects for {}'.format(name))
            return None
    cacert_instance_id = insert_certinstance(db, certificate_id)
    if not cacert_instance_id:
        sle('Failed to create row in Certinstances for {}'.format(name))
        return None
    return cacert_instance_id

