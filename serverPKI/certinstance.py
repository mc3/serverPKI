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
from typing import Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPrivateKeyWithSerialization
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
from serverPKI.cert import Certificate, EncAlgo
from serverPKI.config import Pathes, X509atts, LE_SERVER
from serverPKI.db import DbConnection, DBStoreException
from serverPKI.utils import sld, sli, sln, sle, db_encryption_key, db_encryption_in_use


# ---------------  prepared SQL queries for class CertInstance  --------------

q_load_instance = """
    SELECT ci.id, ci.certificate AS cm_id, ci.state, ci.ocsp_must_staple, ci.not_before, ci.not_after,
                    ca.cert AS ca_cert_ci, d.id AS ckd_id, d.encryption_algo, d.cert, d.key, d.hash
        FROM CertInstances ci, CertInstances ca, CertKeyData d
        WHERE
            ci.id = $1::INT AND
            ci.CAcert = ca.id AND
            d.certinstance = $1::INT
"""

q_delete_instance = """
    DELETE FROM Certinstances
        WHERE id = $1
"""

q_store_instance = """
    INSERT INTO CertInstances
            (certificate, state, ocsp_must_staple, not_before, not_after, cacert)
        VALUES ($1::INTEGER, $2, $3::BOOLEAN, $4::DATE, $5::DATE, $6::INTEGER)
        RETURNING id::int
"""

ps_load_instance = None
ps_delete_instance = None
ps_store_instance = None


# ---------------------------- class CertInstance (CI)---------------------------

@total_ordering
class CertInstance(object):
    """
    Issued certificate instance class.
    In-memory representation of DB backend CertInstances.
    """
    def __init__(self,
                 row_id: int,
                 cert_meta: Certificate,
                 state: str,
                 ocsp_ms: bool,
                 not_before: datetime.datetime,
                 not_after: datetime.datetime,
                 ca_cert_ci: 'CertInstance',
                 cert_key_stores: dict):
        """
        Load or create a certificate meta data instance (CI), which may be incomplete and may be updated later
    
        @param row_id:          id of CertInstances row in DB. If present other args are ignored and
                                CI is loaded from DB
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
        param ca_cert_ci:       Cert meta instance of issuer CA cert
        @type ca_cert_ci:       CertInstance
        @param cert_key_stores: List of CKS, holding certs and keys of this CI
        @type cert_key_stores:  dict, with algo as key and CertKeyStore instance as value
        @rtype:                 CertInstance instance
        @exceptions:
        """

        global ps_load_instance

        if not cert_meta:
            AssertionError('CertInstance: Argument cert_meta missing')
        self.cm = cert_meta
        if not ps_load_instance:
            ps_load_instance = self.cm.db.prepare(q_load_instance)

        self.state = state if state else 'reserved'
        self.ocsp_ms = ocsp_ms if ocsp_ms else cert_meta.ocsp_must_staple
        self.not_before = not_before
        self.not_after = not_after
        self.ca_cert_ci = ca_cert_ci
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
                    self.ca_cert_ci = CertInstance(row['ca_cert']
                    sld('Loading CertInstance row_id={}, state={}, ocsp_ms={}, not_before={}, not_after={}'
                        .format(self.row_id, self.state, self.ocsp_ms,
                                self.not_before.isoformat(), self.not_after.isoformat()))
                    first = False
                cks = CertKeyStore(row_id=row['ckd_id'],
                                   cert_instance=self,
                                   algo=row['encryption_algo'],
                                   cert=row['cert'],
                                   key=row['key'],
                                   hash=row['hash'])
                self.cks[row['encryption_algo']] = cks
                sld('Algo and Hash of loaded CertKeyStore are {} {}'.format(row['algo'], row['hash']))

                    def _save(self):
                        """
                        Store this instance of CertInstance in DB backend (must not exist in DB)
                        :return:
                        """
                        global ps_store_instance

                        if not ps_store_instance:
                            ps_store_instance = self.cm.db.prepare(q_store_instance)
                        self.row_id = ps_store_instance(self.cm.row_id,
                                                        self.state,
                                                        self.ocsp_ms,
                                                        self.not_before,
                                                        self.not_after, self,
                                                        self.ca_cert_ci.row_id)

    def __str__(self):
        return str(self.row_id if self.row_id else self.cm.name + 'instance')

    def __eq__(self, other):
        return self.row_id == other.row_id

    def __lt__(self, other):
        return self.row_id < other.row_id

    def __hash__(self):
        return self.row_id


    def _delete(self) -> int:
        """
        Delete this instance of CertInstance in DB backend and all its CertKeyStores (per cascaded delete)
        :return:    Number of rows deleted
        """
        global ps_delete_instance

        if not ps_delete_instance:
            ps_delete_instance = self.cm.db.prepare(q_delete_instance)
        if self.row_id:
            return ps_delete_instance(self.cm.row_id)

    def _save(self):
        """
        Store this instance of CertInstance in DB backend (must not exist in DB)
        :return:
        """
        global ps_store_instance

        if not ps_store_instance:
            ps_store_instance = self.cm.db.prepare(q_store_instance)
        self.row_id = ps_store_instance(self.cm.row_id,
                                        self.state,
                                        self.ocsp_ms,
                                        self.not_before,
                                        self.not_after,self,
                                        self.ca_cert_ci.row_id)

    def store_cert_key(self,
                       algo: str='rsa',
                       cert: x509.Certificate,
                       key: bytes):
        """
        Store a new certificate in a CertKeyStore instance and in the backend
        :param algo:    encryption algorythm (one of 'rsa' or 'ec'
        :param cert:    certificate, cryptography.x509.Certificate instance
        :param key:     privat key of cert, raw format
        :return:        new instance of CertKeyStore
        """
        if algo in self.cks:
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
        return cks

    @property
    def active(self):
        """
        Return True is this CertKeyStore's certificate is valid today
        :return: bool
        """
        if (self.not_before < datetime.datetime.now(datetime.timezone.utc) and
                self.not_after > datetime.datetime.now(datetime.timezone.utc)):
            return True
        else:
            return False

    @property
    def the_cert_key_store(self):
        """
        Return the CertKeyStore if only one exists, otherwise None
        :return: CertKeyStore instance or None
        """
        ckslist = self.cks.values
        if len(ckslist == 1):
            return ckslist[0]

# ---------------  prepared SQL queries for class CertKeyStore  --------------


q_store_certkeydata = """
    INSERT INTO CertKeyData
            (certinstance, encryption_algo, cert, key, hash, created)
        VALUES ($1::INTEGER, $2, $3, $4, $5, datetime.datetime.now(datetime.timezone.utc))
        RETURNING id::int
"""
q_update_certkeydata = """
    UPDATE CertKeyData
        SET
            certinstance = $2::INT,
            encryption_algo = $3,
            cert = $4,
            key = $5,
            hash = $6
        WHERE id = $1::INT;
"""

q_hash = """
    SELECT hash
        FROM CertInstances
        WHERE
            id = $1
"""
ps_store_certkeydata = None
ps_update_certkeydata = None
ps_hash = None


# ---------------------------- class CertKeyStore (CKS) ---------------------------
cert_key_stores = {}            # ensures that we have only one cert key store per hash

class CertKeyStore(object):
    """
    Cert key data store class class.
    In-memory representation of DB backend CertKeyData.
    """
    @staticmethod
    def hash_from_cert(cls, cert: x509.Certificate):
        """
        return TLSA suitable hash from cryptography.x509.Certificate instance
        :return: the hash as str
        """
        return binascii.hexlify(
            cert.fingerprint(SHA256())).decode('ascii').upper()

    @staticmethod
    def certinstance_from_cert(cls, cert: x509.Certificate):
        """
        return the CertInstance from a (loaded) cert
        :return: CertInstance or None
        """
        hash = CertKeyStore(cert)
        if hash in cert_key_stores:
            return cert_key_stores[hash].ci
        else:
            return None

    def __init__(self,
                 row_id: int,
                 cert_instance: CertInstance,
                 algo: EncAlgo,
                 cert: Union[x509.Certificate, bytes],
                 key: Union[RSAPrivateKeyWithSerialization , bytes],
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
        @param key:             Key data, if row_id present,
                                (possibly) encrypted binary PEM (db storage) format assumed,
                                else raw format
                                (RSAPrivateKeyWithSerialization or bytes)
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
        hash = CertKeyStore.hash_from_cert(cert)
        if hash in cert_key_stores:
            AssertionError('Attempt to create duplicate CertKeyStore for meta {}'.
                           format(cert_key_stores[hash].ci.cm.name))
        self.ci = cert_instance
        self.algo = algo
        self.row_id = row_id
        if self.row_id:  # cert and key come from DB
            self._key = key  # self._key holds (encrypted) binary PEM format (=DB storage format)
            self._cert = cert  # self-_cert holds binary PEM format (=DB storage format)
            self.hash = hash
        else:  # new cert has been issued
            if not key or (not isinstance(key, RSAPrivateKey) and not isinstance(key, EllipticCurvePrivateKey)):
                AssertionError('CertKeyStore: Argument row_id is omitted and arument key'
                               'is not a RSAPrivateKey or EllipticCurvePrivateKey instance')
            if not cert or not isinstance(cert, x509.Certificate):
                AssertionError('CertKeyStore: Argument id is omitted and arument cert'
                               'is not a x509.Certificate instance')
            self._cert = cert.public_bytes(Encoding.PEM)
            self._key = self._encrypt_key(key)
            self.hash = self.hash_from_cert(cert)

            self._save()

    def __del__(self):
        if self.hash in cert_key_stores:
            del cert_key_stores[hash]
        if self.algo in self.ci.cks[algo]:
            del self.ci.cks[algo]

    @property
    def key(self) -> str:
        """
        Return the decrypted key as PEM formated text
        :return: string or None if this CertKeyStore stores a CA cert
        """
        if self.ci.cm.cert_type == 'CA':
            return None
        else:
            clear_key = self._decrypt_key(self._key)
            return clear_key.decode('ascii')

    @property
    def key_for_ca(self) -> bytes:
        """
        Return the decrypted key as PEM formated text
        :return: string or None if this CertKeyStore stores a CA cert
        """
        return self.key

    @property
    def cert(self) -> str:
        """
        Return the certificate as PEM formatted text
        :return: string
        """
        return self._cert.decode('ascii')

    def _save(self) -> None:
        """
        Save this CertKeyStore instance in DB backend
        Creates a new row in certkeydata or updates an existing one (if self.row_id exists)
        :return:
        """
        global ps_store_certkeydata, ps_update_certkeydata

        if self.row_id:
            if not ps_update_certkeydata:
                ps_update_certkeydata = self.ci.cm.db.prepare(q_update_certkeydata)
            (updates) = ps_update_certkeydata(
                self.row_id,
                self.ci.row_id,
                self.algo,
                self.cert,
                self.key,
                self.hash
            )
            if updates != 1:
                raise DBStoreException('?Failed to update CertKeyStore in DB')
        else:
            if not ps_store_certkeydata:
                ps_store_certkeydata = self.ci.cm.db.prepare(q_store_certkeydata)
            self.row_id = ps_store_certkeydata(
                self.ci.row_id,
                self.algo,
                self.cert,
                self.key,
                self.hash
            )
            if not self.row_id:
                raise DBStoreException('?Failed to store CertKeyStore in DB')

    def _key_to_PEM(self, key: RSAPrivateKeyWithSerialization) -> bytes:
        """
        Serialize a key to PEM format
        :param key: Unencrypted binary key
        :return:    key in PEM format as bytes
        """
        return key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption())

    def _encrypt_key(self, the_binary_cert_key) -> bytes:
        """
        Serialize and encrypt a private key to PEM format
        :param the_binary_cert_key: Unencrypted binary key
        :return:                    key in PEM format as bytes
        """
        global db_encryption_key, db_encryption_in_use

        if not db_encryption_in_use:
            return self._key_to_PEM(the_binary_cert_key)
        else:
            encryption_type = BestAvailableEncryption(db_encryption_key)
            key_pem = the_binary_cert_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.TraditionalOpenSSL,
                encryption_type)
        return key_pem

    def _decrypt_key(self, encrypted_key_bytes):
        """
        Load and decrypt a private key
        :param encrypted_key_bytes: encrypted key in binary PEM format
        :return: key as bytes
        """

        if not db_encryption_in_use:
            return encrypted_key_bytes
        else:
            decrypted_key = load_pem_private_key(
                encrypted_key_bytes,
                password=db_encryption_key,
                backend=default_backend())
            key_pem = decrypted_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
        return key_pem
