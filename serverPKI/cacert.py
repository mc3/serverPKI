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

# CA cert creation, storage and presentation module


# --------------- imported modules --------------

import datetime
import getpass
from typing import Optional, Tuple
import sys
from pathlib import Path
from secrets import randbits

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from postgresql import driver as db_conn

# --------------- local imports --------------
from serverPKI.cert import Certificate, CertInstance, CertType, EncAlgoCKS, CertState
from serverPKI.utils import sld, sli, sln, sle,  Pathes, X509atts, Misc


# most recent local CA cert and key, used for issuence of new server/client certs
local_cacert: Optional[x509.Certificate] = None
local_cakey: Optional[rsa.RSAPrivateKeyWithSerialization] = None
local_cacert_instance: Optional[CertInstance] = None


# --------------- classes --------------

class LocalCaCertCache(object):
    cert: Optional[x509.Certificate] = None
    key: Optional[rsa.RSAPrivateKeyWithSerialization] = None
    ci: Optional[CertInstance] = None


class DBStoreException(Exception):
    pass


# --------------- public functions --------------

def cache_cacert(cacert: x509.Certificate,
                 cakey: rsa.RSAPrivateKeyWithSerialization,
                 ci: CertInstance) -> None:
    """
    Should be called (only) in function, where cacert has been created or loaded.
    :param cacert:  New CA cert
    :param cakey:   Corresponding key
    :param ci:      Corresponding Certificate Instance in DB
    :return:
    """
    # Store new CA cert in cache
    LocalCaCertCache.cert = cacert
    LocalCaCertCache.key = cakey
    LocalCaCertCache.ci = ci

    return

def issue_local_CAcert(db: db_conn) -> bool:
    """
    Issue a local CA cert and store it in DB.
    :param db: Opened DB connection
    :return: True, if CA cert created and stored in DB, False otherwise
    """

    sli('Creating local CA certificate.')
    cm = Certificate.create_or_load_cert_meta(db, name=Misc.SUBJECT_LOCAL_CA)
    if not cm.in_db:                            # loaded from DB?
        # CM not in DB, create rows in Subjects and Certificates for it
        cm = create_CAcert_meta(db=db,
                                name=Misc.SUBJECT_LOCAL_CA,
                                cert_type=CertType('local'))
    try:
        create_local_ca_cert(db, cm)
    except Exception as e:
        sle('Failed to create local CA cert, because: {}'.format(str(e)))
        return False
    return True


def get_cacert_and_key(db: db_conn) -> Tuple[x509.Certificate, rsa.RSAPrivateKeyWithSerialization, CertInstance]:
    """
    Return a valid local CA certificate and a loaded private key.
    Use globals local_cacert, local_cakey and local_cacert_instance if available

    If necessary, create a local CAcert or read a historical one from disk.
    Store it in DB, creating necessary rows in Subjects, Certificates
    and Certinstances and store them in LocalCaCertCache
    Does exit(1) if CA key could not be loaded.
    :param db:  Opened DB connection
    :return:    Tuple of cacert, cakey and cacert instance and globals
                local_cacert, local_cakey, local_cacert_instance setup
    """

    if LocalCaCertCache.cert and LocalCaCertCache.key and LocalCaCertCache.ci:
        return (LocalCaCertCache.cert, LocalCaCertCache.key, LocalCaCertCache.ci)

    cacert = None
    cakey = None
    ci = None

    cm = Certificate.create_or_load_cert_meta(db, name=Misc.SUBJECT_LOCAL_CA)
    if cm.in_db:  # loaded from DB?
        ci = cm.most_recent_active_instance  # YES: load its active CI
        if ci:  # one there, which is valid today?
            cks = list(ci.the_cert_key_stores.values())[0]  # expecting only one algorithm
            cacert_pem = cks.cert_for_ca
            cakey_pem = cks.key_for_ca
            algo = cks.algo
            cacert = x509.load_pem_x509_certificate(
                data=cacert_pem,
                backend=default_backend()
            )
            cakey = _load_cakey(cakey_pem)
            if not cakey:  # operator aborted pass phrase input
                sle('Can''t create certificates without passphrase')
                exit(1)
            # CA cert loaded, cache it and return
            cache_cacert (cacert, cakey, ci)
            return (cacert, cakey, ci)

        sln('Missed active cacert instance or store in db, where it should be: {}'.format(cm.name))

    else:           # CM not in DB, create rows in Subjects and Certificates for it
        cm = create_CAcert_meta(db=db,
                                name=Misc.SUBJECT_LOCAL_CA,
                                cert_type=CertType('local'))

        # Try to load active historical CA cert from flat file
        result = load_historical_cert_from_flatfile(cm)
        if result:  # loaded, cached and stored in DB
            return result  # globals already setup
        else:  # none found in flat file - issue a new one
            result = create_local_ca_cert(db, cm)
            if result:  # issued, cached and stored in DB
                return result  # globals already setup
            else:
                sle('Failed to issue CA cert')
                sys.exit(1)

    if not ci:  # no most_recent_active_instance found above, issue one
        result = create_local_ca_cert(db, cm)
        if result:  # issued, cached and stored in DB
            return result
        else:
            sle('Failed to issue CA cert')
            sys.exit(1)

def create_local_ca_cert(db: db_conn, cm: Certificate) -> Tuple[x509.Certificate,
                                               rsa.RSAPrivateKeyWithSerialization,
                                               CertInstance]:
    """
    Create a new local CA cert (use an existing one, if one in db)
    Make it available in globals local_cacert, local_cakey and local_cacert_instance

    :param db:      Opened DB connection
    :param cm:      CA cert Certifcate meta instance
    :return:        Tuple of cacert, cakey and cacert instance and globals
                    local_cacert, local_cakey, local_cacert_instance setup
    """

    global local_cacert, local_cakey, local_cacert_instance

    # Read pass phrase from user
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
        key_size=Misc.LOCAL_CA_BITS,
        backend=default_backend()
    )

    # compose cert

    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    serial = randbits(32)
    name_dict = X509atts.names
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, name_dict['C']),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, name_dict['L']),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, name_dict['O']),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, name_dict['CN']),
    ])

    not_after = datetime.datetime.utcnow() + datetime.timedelta(
        days=Misc.LOCAL_CA_LIFETIME)
    not_before = datetime.datetime.utcnow() - datetime.timedelta(
        days=1)
    ci = cm.create_instance(not_before=not_before,
                            not_after=not_after,
                            state=CertState('issued'))

    ski = x509.SubjectKeyIdentifier.from_public_key(cakey.public_key())

    cacert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        cakey.public_key()
    ).serial_number(serial
                    ).not_valid_before(
        not_before
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        not_after
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
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False),
        critical=True
    ).sign(cakey, hashes.SHA512(), default_backend())

    sli('CA cert serial {} with {} bit key, valid until {} created.'.format(
        serial,
        Misc.LOCAL_CA_BITS,
        not_after.isoformat()
    ))
    ci.store_cert_key(algo='rsa', cert=cacert, key=cakey)
    cm.save_instance(ci)

    # CA cert loaded, cache it and return
    cache_cacert(cacert, cakey, ci)
    return (cacert, cakey, ci)


def load_historical_cert_from_flatfile(cm: Certificate) -> Optional[Tuple[x509.Certificate,
                                                           rsa.RSAPrivateKeyWithSerialization,
                                                           CertInstance]]:
    """
    Load a historical CA cert from flat file
    Make it available in globals local_cacert, local_cakey and local_cacert_instance

    :return:        Tuple of cacert, cakey and cacert instance and globals
                    local_cacert, local_cakey, local_cacert_instance setup
    """

    global local_cacert, local_cakey, local_cacert_instance

    # do we have a historical CA cert on disk?
    if Path(Pathes.ca_cert).exists() and Path(Pathes.ca_key).exists:
        sli('Using CA key at {}'.format(Pathes.ca_key))  # yes
        sli('Will be stored in DB')
        with open(Pathes.ca_cert, 'rb') as f:
            cacert_pem = f.read()
        cacert = x509.load_pem_x509_certificate(cacert_pem, default_backend())

        if not (cacert.not_valid_before < datetime.datetime.now() and
                cacert.not_valid_after > datetime.datetime.now()):

            sli('Historical cert on flatfile is outdated')
            return None
        else:
            with open(Pathes.ca_key, 'rb') as f:
                cakey_pem = f.read()
            cakey = _load_cakey(cakey_pem)
            ci = cm.create_instance(not_before=cacert.not_valid_before,
                                    not_after=cacert.not_valid_after,
                                    state=CertState('issued'))
            ci.store_cert_key(algo='rsa', cert=cacert, key=cakey)
            cm.save_instance(ci)

            # CA cert loaded, cache it and return
            cache_cacert (cacert, cakey, ci)
            return (cacert, cakey, ci)
    else:
        return None


# --------------- load private key and query passphrase --------------

def _load_cakey(cakey_pem: bytes) -> Optional[rsa.RSAPrivateKey]:
    """
    Load private key and query passphrase
    :param cakey_pem: The PEM encoded key data as bytes
    :return:
    :exceptions:    ValueError, TypeError
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
    except (TypeError):  # needing passphrase

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


# --------------- function --------------

def create_CAcert_meta(db: db_conn, name: str, cert_type: Optional[CertType]=None) -> Optional[Certificate]:
    """
    Lookup or create a CA cert meta in rows ceetificates and subjects
    :param db:          opened database connection in read/write transaction
    :param name:        name of CA cert (as configured in config: Misc.SUBJECT_LOCAL_CA or SUBJECT_LE_CA)
    :cert_type:         CertType
    :return:            cert meta or None
    """
    if name not in (Misc.SUBJECT_LOCAL_CA, Misc.SUBJECT_LE_CA):
        raise AssertionError('create_CAcert_meta: argument name "{} invalid"'.format(name))
    cm = Certificate.ca_cert_meta(db, name, cert_type)
    if not cm:
        sle('Failed to create CA cert meta for {}'.format(name))
        sys.exit(1)
    return cm
