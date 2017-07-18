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

# CA cert creation, storage and presentation module


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
from serverPKI.config import Pathes, X509atts, LE_SERVER, SUBJECT_LOCAL_CA
from serverPKI.config import LOCAL_CA_BITS, LOCAL_CA_LIFETIME
from serverPKI.utils import sld, sli, sln, sle
from serverPKI.utils import insert_certinstance, update_certinstance


ps_insert_instance = None
ps_update_instance = None

# ----------------- globals --------------------

local_cacert = None
local_cakey = None
local_cacert_id = None

#--------------- classes --------------

class DBStoreException(Exception):
    pass

#--------------- public functions --------------

def get_cacert_and_key(db):
    """
    Return a valid local certificate and a loaded private key.
    If necessary, create a local CAcert or read a historical one from disk.
    Store Cacert in DB, creating necessary rows in Subjects, Certificates
    and Certinstances.
    
    @param db:          open database connection in readwrite transaction
    @type db:           serverPKI.db.DbConnection instance
    @rtype:             Tuple of cacert, cakey and cacert instance id 
                            or tuple of None, None,None
    @exceptions:
    """
    
    global local_cacert, local_cakey, local_cacert_id

    if local_cacert and local_cakey and local_cacert_id:
        return (local_cacert, local_cakey, local_cacert_id)

    retval = _query_cacert(db)
    if retval:
        (cacert_pem, cakey_pem, cacert_id) = retval
        ##sld('cert:\d{}\nkey:\n{}'.format(cacert_pem.decode('utf-8'), cakey_pem.decode('utf-8')))
        cacert = x509.load_pem_x509_certificate(
                data = cacert_pem,
                backend = default_backend()
        )
        cakey = _load_cakey(cakey_pem)
        if not cakey:
            sle('Can''t create certificates without passphrase')
            exit(1)
        local_cacert, local_cakey, local_cacert_id = cacert, cakey, cacert_id
        return (cacert, cakey, local_cacert_id)
        
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
                not_after,
                cacert_instance_id
    )
    if updates != 1:
        raise DBStoreException('?Failed to store certificate in DB')

    local_cacert = cacert
    local_cakey = cakey
    local_cacert_id = cacert_instance_id
    return (cacert, cakey, cacert_instance_id)



#--------------- load private key and query passphrase --------------

def _load_cakey(cakey_pem):
    """
    Return a CA key instance. If it is encrypted, it will be decrypted
    any needed passphrase queries from user.
    
    @param cakey_pem:   text form of CA key in PEM format
    @type cakey_pem:    bytes
    @rtype:             Instance of serialization.load_pem_private_key
    @exceptions:
    """

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
    SELECT ca.cert, ca.key, ca.id
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
    @type db:           serverPKI.db.DbConnection instance
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
    """
    Create a Cert meta instance along with the rows in relations Certificates
    and Subjects.
    
    @param db:          opened database connection
    @type db:           serverPKI.db.DbConnection instance
    @param cert_type:   either 'local' or 'LE' for local or Letsencrypt certs
    @type cert_type:    str
    @param name:        name of CA cert
    @type name:         str
    @rtype:             int (cacert_instance_id) or None
    @exceptions:
    """
    
    global ps_query_CA_subject_and_certificate
    
    if not ps_query_CA_subject_and_certificate:
        ps_query_CA_subject_and_certificate = \
            db.prepare(q_query_CA_subject_and_certificate)
    
    #FIXME: There must be only one result row! Check that!
    #rationale: Only one Local CA or one LE CA may exist ever.
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

