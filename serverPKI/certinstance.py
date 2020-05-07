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

# module for classes CertInstance and CertKeyStore

# --------------- imported modules --------------
import binascii
import datetime
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PrivateFormat,
    NoEncryption,
    BestAvailableEncryption
)
from cryptography import x509

# --------------- local imports --------------
from serverPKI.config import Pathes, X509atts, LE_SERVER
from serverPKI.cert import Certificate

from serverPKI.utils import sld, sli, sln, sle, options, decrypt_key

# ---------------  prepared SQL queries for class CertInstance  --------------

q_load_instance = """
    SELECT ci.id, ci.certificate AS cm_id, ci.state, ci.ocsp_must_staple, ci.not_before, ci.not_after,
                    ca.cert AS ca_cert, d.id AS ckd_id, d.encryption_algo, d.cert, d.key, d.hash
        FROM CertInstances ci, CertInstances ca, CertKeyData d
        WHERE
            ci.id = $1::INT AND
            ci.CAcert = ca.id AND
            d.certinstance = $1::INT
"""
q_store_instance = """
    INSERT INTO CertInstances
            (certificate, state, ocsp_must_staple, not_before, not_after, cacert)
        VALUES ($1::INTEGER, $2, $3::BOOLEAN, $4::DATE, $5::DATE, $6::INTEGER)
        RETURNING id::int
"""
q_fqdn_from_serial = """
SELECT s.name::TEXT
    FROM Subjects s, Certificates c, Certinstances i
    WHERE
        i.id = $1   AND
        i.certificate = c.id  AND
        s.certificate = c.id  AND
        NOT s.isaltname
"""

ps_load_instance = None
ps_store_instance = None
ps_fqdn_from_serial = None

# ---------------------------- class CertInstance (CI)---------------------------

class CertInstance(object):
    """
    Issued certificate instance class.
    In-memory representation of DB backend CertInstances.
    """

    def __init__(self,
                row_id = None,
                cert_meta = None,
                state = 'reserved',
                ocsp_ms = False,
                not_before = None,
                not_after = None,
                ca_cert = None,
                cert_key_stores = ()):
        """
        Create a certificate meta data instance (CI), which may be incomplete and may be updated later
    
        @param row_id:          id of CertInstances row in DB. If present other args are ignored and CI is loaded from DB
        @type row_id            int
        @param cert_meta:       Cert meta instance, required
        @type cert_meta:        serverPKI.cert.Certificate
        @param state:           State of CI, usually 'issued', required
        @type state:            str
        @param ocsp_ms:         OCSP must staple attribute
        @type ocsp_ms:          bool
        @param not_before:      Cert issue date
        @type not_before:       datetime.datetime
        @param not_after:       Cert expiration date
        @type not_after:        datetime.datetime
        param ca_cert:          Cert meta instance of issuer CA cert
        @type ca_cert:          CI ??
        @param cert_key_stores: List of CKS, holding certs and keys of this CI
        @type cert_key_stores:  dict, with algo as key and CertKeyStore instance as value
        @rtype:                 CertInstance instance
        @exceptions:
        """

        global ps_load_instance, ps_store_instance, ps_fqdn_from_serial

        if not cert_meta:
            AssertionError('CertInstance: Argument cert_meta missing')
        self.cm = cert_meta
        if not ps_load_instance:
            ps_load_instance = self.cm.db.prepare(q_load_instance)
        if not ps_store_instance:
            ps_store_instance = self.cm.db.prepare(q_store_instance)
        if not ps_fqdn_from_serial:
            ps_fqdn_from_serial = self.cm.db.prepare(q_fqdn_from_serial)

        self.state = state
        self.ocsp_ms = ocsp_ms
        self.not_before = not_before
        self.not_after = not_after
        self.ca_cert = ca_cert
        self.cks = cert_key_stores
        if row_id:
            self.row_id = row_id
            rows = ps_load_instance(self.row_id)
            if not rows:
                AssertionError('CertInstance: row_id {} does not exist'.format(self.row_id))

            self.cks = {}
            first = True
            for row in rows:
                if first:
                    self.state = row['state']
                    self.ocsp_ms = row['ocsp_must_staple']
                    self.not_before = row['not_before']
                    self.not_after = row['not_after']
                    self.ca_cert = row['ca_cert']
                    first = False
                cks = CertKeyStore(row_id=row['ckd_id'],
                                   cert_instance=self,
                                   algo=row['encryption_algo'],
                                   cert=row['cert'],
                                   key=row['key'],
                                   hash=row['hash'])
                self.cks[row['encryption_algo']] = cks
                sld('Hash of loaded cert for {} is {}'.format(self.cm, row['hash']))

    def store_cert_key(self,
                       algo=None,
                       cert=None,
                       key=None):
        if algo in cks:
            AssertionError('CertInstance: store_cert_key Attempt to overwrite cert for {} with algo {}'.
                    format(self.cm.name, algo))

        if not self.not_before:
            self.not_before = cert.not_valid_before
        if not self.not_after:
            self.not_after = cert.not_valid_after

        cks = CertKeyStore(
                    cert_instance=self,
                    algo=algo,
                    cert=cert,
                    key=key)
        self.cks[algo] = cks



# ---------------  prepared SQL queries for class CertKeyStore  --------------


q_store_certkeydata = """
    INSERT INTO CertKeyData
            (certinstance, encryption_algo, cert, key, hash)
        VALUES ($1::INTEGER, $2, $3, $4, $5)
        RETURNING id::int
"""

q_hash = """
    SELECT hash
        FROM CertInstances
        WHERE
            id = $1
"""
ps_store_certkeydata = None
ps_hash = None

# ---------------------------- class CertKeyStore (CKS) ---------------------------

class CertKeyStore(object):
    """
    Cert key data store class class.
    In-memory representation of DB backend CertKeyData.
    """
    global ps_load_instance, ps_store_instance, ps_fqdn_from_serial

    def __init__(self,
                 row_id=None,
                 cert_instance=None,
                 algo='rsa',
                 cert=None,
                 key=None,
                 hash=None):

        """
        Create a store for one cert/key pair

        @param row_id:          id in DB, cert and key are in DB storage format (key encrypted)
        @type row_id:           int
        @param cert_instance:   parent CertInstance, required
        @type cert_instance:    serverPKI.cert.CertInstance
        @param algo:            cert encryption algo, one of 'ec' or 'rsa'  **FIXME** could be derived from key type
        @type algo              str
        @param cert:            Certificate data, if row_id present, binary PEM (db storage) format assumed
        @type cert:             bytes or cryptography.x509.Certificate
        @param key:             Key data, if row_id present, (possibly) encrypted binary PEM (db storage) format assumed,
                                else raw format
        @type key:              bytes or
                                either cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey or
                                cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
        @param hash:            TLSA hash of certificate
        @type hash:             str

        @rtype:                 CertKeyStore instance

        @exceptions:
        """

        global ps_store_certkeydata
        
        if not cert_instance:
            AssertionError('CertKeyStore: Argument cert_instance missing')
        self.ci = cert_instance
        self.algo = algo
        self.row_id = row_id
        if self.row_id:             # cert and key come from DB
            self._key = key         # self._key holds (encrypted) binary PEM format (=DB storage format)
            self._cert = cert       # self-_cert holds binary PEM format (=DB storage format)
            self.hash = hash
        else:                       # new cert has been issued
            if not key or ( not isinstance(key, RSAPrivateKey) and not isinstance(key, EllipticCurvePrivateKey)):
                AssertionError('CertKeyStore: Argument row_id is omitted and arument key'
                               'is not a RSAPrivateKey or EllipticCurvePrivateKey instance')
            if not cert or not isinstance(cert, x509.Certificate):
                AssertionError('CertKeyStore: Argument id is omitted and arument cert'
                               'is not a x509.Certificate instance')
            self._cert = cert.public_bytes(Encoding.PEM)
            self._key = self.encrypt_key(key)
            self.hash = binascii.hexlify(
                                    cert.fingerprint(SHA256())).decode('ascii').upper()
            
            if not ps_store_certkeydata:
                ps_store_certkeydata = self.cm.db.prepare(q_store_certkeydata)
            self.row_id = ps_store_certkeydata( self.ci.row_id,
                                                self.algo,
                                                self._cert,
                                                self._key,
                                                self.hash)
            if not self.row_id:
                sle('Could not store new cert in DB')
    
                                                
    @property
    def key(self):
        if self.ci.cm.cert_type == 'CA':
            return None
        else:
            clear_key = self.decrypt_key(self._key)
            return clear_key.decode('ascii')
            
    @property
    def cert(self):
        return self._cert.decode('ascii')
    

    def key_to_PEM(self, key):                      # serialize a key to PEM format
        return key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption())

    def encrypt_key(self, the_binary_cert_key):     # serialize and encrypt a private key
        global db_encryption_key, db_encryption_in_use

        if not db_encryption_in_use:
            return self.key_to_PEM(the_binary_cert_key)
        else:
            encryption_type = BestAvailableEncryption(db_encryption_key)
            key_pem = the_binary_cert_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.TraditionalOpenSSL,
                encryption_type)
        return key_pem

    def decrypt_key(self, encrypted_key_bytes):     # load and decrypt a private key
        global db_encryption_key, db_encryption_in_use

        if not db_encryption_in_use:
            return encrypted_key_bytes
        else:
            decrypted_key = load_pem_private_key(
                encrypted_key_bytes,
                password=db_encryption_key,
                backend=default_backend())
            key_pem = decrypted_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
        return key_pem
