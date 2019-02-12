# -*- coding: utf-8 -*-

"""
Copyright (C) 2015-2018  Axel Rau <axel.rau@chaos1.de>

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

# issue Let's Encrypt certificates


#--------------- imported modules --------------
import binascii
import datetime
from hashlib import sha256
import logging
from pathlib import Path
import os
import sys
import time

import iso8601
from cryptography.hazmat.primitives.hashes import SHA256

from manuale.acme import Acme
from manuale import crypto as manuale_crypto
from manuale import issue as manuale_issue
from manuale import cli as manuale_cli
from manuale import errors as manuale_errors

#--------------- local imports --------------
from serverPKI.cacert import create_CAcert_meta
from serverPKI.config import Pathes, X509atts, LE_SERVER, SUBJECT_LE_CA
from serverPKI.utils import sld, sli, sln, sle, options, update_certinstance
from serverPKI.utils import zone_and_FQDN_from_altnames, updateSOAofUpdatedZones
from serverPKI.utils import updateZoneCache, encrypt_key

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
            (certificate, state, cert, key, hash, cacert, not_before, not_after)
        VALUES ($1::INTEGER, 'issued', $2, $3, $4, $5, $6::TIMESTAMP, $7::TIMESTAMP)
        RETURNING id::int
"""
ps_insert_LE_instance = None

        
#--------------- public functions --------------

        
def issue_LE_cert(cert_meta):
    """
    Try to issue a Letsencrypt certificate.
    Does authorization if necessary.
    On success, inserts a row into CertInstances.
    If this is the first Letsencrypt instance, additional rows are inserted
    into Subjects, Certificates and CertInstances for LE intermediate cert.
    Additional Certinstances may also be inserted if the intermediate cert
    from LE  changes.
    
    @param cert_meta:   Cert meta instance to issue an certificate for
    @type cert_meta:    Cert meta instance
    @rtype:             cert instance id in DB of new cert or None
    @exceptions:        manuale_errors.ManualeError
                        May exit(1) if account not valid.
    """

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

    os.chdir(str(Pathes.work)) # remove this ?
    try:
        account = manuale_cli.load_account(str(Pathes.le_account))
    except:
        sle('Problem with Lets Encrypt account data at {}'.format(
                                                str(Pathes.le_account)))
        exit(1)

    if not (cert_meta.authorized_until and
                    cert_meta.authorized_until >= datetime.datetime.now()):
        if not _authorize(cert_meta, account):
            return None
    
    sli('Creating key (%d bits) and cert for %s %s' %
        (int(X509atts.bits), cert_meta.subject_type, cert_meta.name))
    certificate_key = manuale_crypto.generate_rsa_key(X509atts.bits)
    csr = manuale_crypto.create_csr(certificate_key, alt_names)
    acme = Acme(LE_SERVER, account)
    try:
        sli('Requesting certificate issuance from LE...')
        result = acme.issue_certificate(csr)
    except manuale_errors.AcmeError as e:
        if '(type urn:acme:error:unauthorized, HTTP 403)' in str(e):
            sle('LetsEncrypt lost authorization for {}. Trying to renew...'.format(cert_meta.name))
            if not _authorize(cert_meta, account):
                return None
            result = acme.issue_certificate(csr)
        else:    
            sle("Connection or service request failed. Aborting.")
            raise manuale_errors.ManualeError(e)
    except IOError as e:
            sle("Connection or service request failed. Aborting.")
            raise manuale_errors.ManualeError(e)
    
    try:
        certificate = manuale_crypto.load_der_certificate(result.certificate)
    except IOError as e:
        sle("Failed to load new certificate. Aborting.")
        raise manuale_errors.ManualeError(e)

    if result.intermediate:
        intcert = manuale_crypto.load_der_certificate(result.intermediate)
        intcert_instance_id = _get_intermediate_instance(cert_meta.db, intcert)
    else:
        sle('Missing intermediate cert. Can''t store in DB')
        exit(1)

    not_valid_before = certificate.not_valid_before
    not_valid_after = certificate.not_valid_after

    cert_pem = manuale_crypto.export_pem_certificate(certificate)
    
    key_pem = encrypt_key(certificate_key)
    if not key_pem:     # no keyencryption in DB in use
        key_pem = manuale_crypto.export_private_key(certificate_key)
    tlsa_hash = binascii.hexlify(
        certificate.fingerprint(SHA256())).decode('ascii').upper()

    sli('Certificate issued. Valid until {}'.format(not_valid_after.isoformat()))
    sli('Hash is: {}'.format(tlsa_hash))

    if not ps_insert_LE_instance:
        ps_insert_LE_instance = cert_meta.db.prepare(q_insert_LE_instance)
    (instance_id) = ps_insert_LE_instance.first(
            cert_meta.cert_id,
            cert_pem,
            key_pem,
            tlsa_hash,
            intcert_instance_id,
            not_valid_before,
            not_valid_after)
    if instance_id:
        return instance_id
    sle('Failed to store new cert in DB backend')
    return None
    
#---------------  prepared SQL queries for private functions  --------------

q_query_LE_intermediate = """
    SELECT id from CertInstances
        WHERE hash = $1 
"""
ps_query_LE_intermediate = None

        
#--------------- private functions --------------

def _get_intermediate_instance(db, int_cert):
    """
    Return id of intermediate CA cert from DB.
    
    @param db:          opened database connection
    @type db:           serverPKI.db.DbConnection instance
    @param int_cert:    Intermediate CA certificate of letsencrypt cert
    @type int_cert:     instance returned by manuale_crypto.load_der_certificate
    @rtype:             Intermediate CA cert instance id in DB
    @exceptions:        DBStoreException
    """
    
    global ps_query_LE_intermediate
    
    hash = binascii.hexlify(
        int_cert.fingerprint(SHA256())).decode('ascii').upper()
    
    if not ps_query_LE_intermediate:
        ps_query_LE_intermediate = db.prepare(q_query_LE_intermediate)
    (instance_id) = ps_query_LE_intermediate.first(hash)
    if instance_id:
        return instance_id
    
    # new intermediate - put it into DB
    
    instance_id = create_CAcert_meta(db, 'LE', SUBJECT_LE_CA)
    
    not_valid_before = int_cert.not_valid_before
    not_valid_after = int_cert.not_valid_after

    cert_pem = manuale_crypto.export_pem_certificate(int_cert)
    
    (updates) = update_certinstance(db, instance_id, cert_pem, b'', hash,
                                    not_valid_before, not_valid_after, instance_id)
    if updates != 1:
        raise DBStoreException('?Failed to store intermediate certificate in DB')
    return instance_id

def _authorize(cert_meta, account):
    """
    Try to prove the control about a DNS object.
    
    @param cert_meta:   Cert meta instance to issue an certificate for
    @type cert_meta:    Cert meta instance
    @param account:     Our letsencrypt account
    @type account:      manuale_cli.load_account instance
    @rtype:             True if all fqdns could be authorized, False otherwise
    @exceptions:        manuale_errors.ManualeError on Network or other fatal error
    """

    acme = Acme(LE_SERVER, account)
    thumbprint = manuale_crypto.generate_jwk_thumbprint(account.key)

    FQDNs = [cert_meta.name, ]
    if len(cert_meta.altnames) > 0:
        FQDNs.extend(cert_meta.altnames)

    try:
        # Get pending authorizations for each fqdn
        authz = {}
        for fqdn in FQDNs:
            sli("Requesting challenge for {}.".format(fqdn))
            created = acme.new_authorization(fqdn)
            auth = created.contents
            auth['uri'] = created.uri
            
            # Find the DNS challenge
            try:
                auth['challenge'] = [ch for ch in auth.get('challenges', []) if ch.get('type') == 'dns-01'][0]
            except IndexError:
                raise manuale_errors.ManualeError("Manuale only supports the dns-01 challenge. The server did not return one.")
            
            auth['key_authorization'] = "{}.{}".format(auth['challenge'].get('token'), thumbprint)
            digest = sha256()
            digest.update(auth['key_authorization'].encode('ascii'))
            auth['txt_record'] = manuale_crypto.jose_b64(digest.digest())
            
            authz[fqdn] = auth
        
        zones = {}
        
        sld('Calling zone_and_FQDN_from_altnames()')
        for (zone, fqdn) in zone_and_FQDN_from_altnames(cert_meta):
            if zone in zones:
                if fqdn not in zones[zone]: zones[zone].append(fqdn)
            else:
                zones[zone] = [fqdn]
        sld('zones: {}'.format(zones))
        # write one file with TXT RRS into related zone directory:
        for zone in zones.keys():
            dest = str(Pathes.zone_file_root / zone / Pathes.zone_file_include_name)
            lines = []
            for fqdn in zones[zone]:
                sld('fqdn: {}'.format(fqdn))
                auth = authz[fqdn]
                lines.append(str('_acme-challenge.{}.  IN TXT  \"{}\"\n'.format(fqdn, auth['txt_record'])))
            sli('Writing RRs: {}'.format(lines))
            with open(dest, 'w') as file:
                file.writelines(lines)
                ##os.chmod(file.fileno(), Pathes.zone_tlsa_inc_mode)
                ##os.chown(file.fileno(), pathes.zone_tlsa_inc_uid, pathes.zone_tlsa_inc_gid)
            updateZoneCache(zone)
        
        updateSOAofUpdatedZones()
        
        sld("{}: Waiting for DNS propagation. Checking in 60 seconds.".format(fqdn))
        time.sleep(60)
        
        # Verify each fqdn
        done, failed = set(), set()
        authorized_until = None
        
        for fqdn in FQDNs:
            sld('')
            auth = authz[fqdn]
            challenge = auth['challenge']
            acme.validate_authorization(challenge['uri'], 'dns-01', auth['key_authorization'])
    
            for i in range(10):        # try only 10 times
                sld("{}: waiting for verification. Checking in 20 seconds.".format(fqdn))
                time.sleep(20)
    
                response = acme.get_authorization(auth['uri'])
                status = response.get('status')
                if status == 'valid':
                    done.add(fqdn)
                    expires = response.get('expires', '(not provided)')
                    if not authorized_until:
                        authorized_until = iso8601.parse_date(expires)
                        sld('Authorization lasts until {}'.format(authorized_until))
                    sli("{}: OK! Authorization lasts until {}.".format(fqdn, expires))
                    break
                elif status != 'pending':
                    failed.add(fqdn)
    
                    # Failed, dig up details
                    error_type, error_reason = "unknown", "N/A"
                    try:
                        challenge = [ch for ch in response.get('challenges', []) if ch.get('type') == 'dns-01'][0]
                        error_type = challenge.get('error').get('type')
                        error_reason = challenge.get('error').get('detail')
                        if 'NXDOMAIN' in str(error_reason):
                            sln('DNS propagation delay while authorizing {}'.format(fqdn))
                            continue
                    except (ValueError, IndexError, AttributeError, TypeError):
                        pass
    
                    sle("{}: {} ({})".format(fqdn, error_reason, error_type))
                    break
    
        # remember new expiration date in DB
        updates = cert_meta.update_authorized_until(authorized_until)
        if updates != 1:
            sln('Failed to update DB with new authorized_until timestamp')
            
        # make include zone files empty
        for zone in zones.keys():
            dest = str(Pathes.zone_file_root / zone / Pathes.zone_file_include_name)
            with open(dest, 'w') as file:
                file.writelines(('', ))
                ##os.chmod(file.fileno(), Pathes.zone_tlsa_inc_mode)
                ##os.chown(file.fileno(), pathes.zone_tlsa_inc_uid, pathes.zone_tlsa_inc_gid)
            updateZoneCache(zone)
        updateSOAofUpdatedZones()
    
        if failed:
            sle("{} fqdn(s) authorized, {} failed.".format(len(done), len(failed)))
            sli("Authorized: {}".format(' '.join(done) or "N/A"))
            sle("Failed: {}".format(' '.join(failed)))
            return False
        else:
            sli("{} fqdn(s) authorized. Let's Encrypt!".format(len(done)))
            return True
        
    except IOError as e:
        sle('A connection or service error occurred. Aborting.')
        raise manuale_errors.ManualeError(e)
    