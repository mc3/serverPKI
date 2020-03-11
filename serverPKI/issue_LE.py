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

This module uses code from https://github.com/candango/automatoes
"""

# issue Let's Encrypt certificates


#--------------- imported modules --------------
import binascii
import datetime
from hashlib import sha256
import logging
from pathlib import Path
import os
import pprint
import re
import sys
import time

import iso8601
from cryptography.hazmat.primitives.hashes import SHA256

from automatoes.acme import AcmeV2
from automatoes import model
from automatoes import authorize as manuale_authorize
from automatoes import crypto as manuale_crypto
from automatoes import issue as manuale_issue
from automatoes import cli as manuale_cli
from automatoes import errors as manuale_errors

#--------------- local imports --------------
from serverPKI.cacert import create_CAcert_meta
from serverPKI.config import Pathes, X509atts, LE_SERVER, SUBJECT_LE_CA
from serverPKI.utils import sld, sli, sln, sle, options, update_certinstance
from serverPKI.utils import zone_and_FQDN_from_altnames, updateSOAofUpdatedZones
from serverPKI.utils import updateZoneCache, encrypt_key, print_order

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
    @exceptions:        manuale_errors.AutomatoesError
                        May exit(1) if account not valid.
    """

    global ps_insert_LE_instance

    # Set up logging
    root = logging.getLogger('automatoes')
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
        sle('Problem with Lets Encrypt account data at {}'.
                                                format(Pathes.le_account))

    """
    # we need an order!
    if not (cert_meta.authorized_until and
                    cert_meta.authorized_until >= datetime.datetime.now()):
        order = _authorize(cert_meta, account)
        if not order:
            return None
    """
    order = _authorize(cert_meta, account)
    if not order:
        return None

    sli('Creating key (%d bits) and cert for %s %s' %
        (int(X509atts.bits), cert_meta.subject_type, cert_meta.name))
    
    certificate_key = manuale_crypto.generate_rsa_key(X509atts.bits)
    
    # experimental elliptic key 
    if False:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        crypto_backend = default_backend()
        certificate_key = ec.generate_private_key(ec.SECP384R1(), crypto_backend)
    # end experimental elliptic key
    
    order.key = manuale_crypto.export_private_key(certificate_key).decode('ascii')
    csr = manuale_crypto.create_csr(certificate_key, alt_names, must_staple = True)
    
    
    acme = AcmeV2(LE_SERVER, account)
    try:
        sli('Requesting certificate issuance from LE...')
        
        final_order = acme.finalize_order(order, csr)
        order.contents = final_order

        if final_order['status'] in ["processing", "valid"]:
            if options.verbose:
                sld("{}:  Order finalized. Certificate is being issued."
                                                    .format(cert_meta.name))
        else:
            sle("{}:  Order not ready or invalid after finalize. Giving up"
                                                    .format(cert_meta.name))
            return False
        
        if order.certificate_uri is None:
            if options.verbose:
                sld("{}:  Checking order status.".format(cert_meta.name))
            fulfillment = acme.await_for_order_fulfillment(order)
            if fulfillment['status'] == "valid":
                order.contents = fulfillment
            else:
                sle("{}:  Order not valid after fulfillment. Giving up"
                                                        .format(cert_meta.name))
                return False
        else:
            print("  We already know the certificate uri for order {}. "
                  "Downloading certificate.".format(domains_hash))

        result = acme.download_order_certificate(order)

    except manuale_errors.AcmeError as e:
        if '(type urn:acme:error:unauthorized, HTTP 403)' in str(e):
            sle('LetsEncrypt lost authorization for {} [DOWNLOAD]. Giving up'.format(cert_meta.name))
        else:    
            sle("Connection or service request failed [DOWNLOAD]. Aborting.")
            raise manuale_errors.AutomatoesError(e)
        return False
    
    try:
        certificates = manuale_crypto.strip_certificates(result.content)   # DER
        certificate = manuale_crypto.load_pem_certificate(certificates[0])

    except IOError as e:
        sle("Failed to load new certificate. Aborting.")
        raise manuale_errors.AutomatoesError(e)
        return False
        
    intcert = manuale_crypto.load_pem_certificate(certificates[1])
    intcert_instance_id = _get_intermediate_instance(cert_meta.db, intcert)

    not_valid_before = certificate.not_valid_before
    not_valid_after = certificate.not_valid_after

    cert_pem = manuale_crypto.export_pem_certificate(certificate)
    
    key_pem = encrypt_key(certificate_key)
    if not key_pem:     # no keyencryption in DB in use
        key_pem = manuale_crypto.export_private_key(certificate_key)
    tlsa_hash = binascii.hexlify(
        certificate.fingerprint(SHA256())).decode('ascii').upper()

    sli('Certificate issued for {} . Valid until {}'.format(cert_meta.name, not_valid_after.isoformat()))
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
    @exceptions:        manuale_errors.AutomatoesError on Network or other fatal error
    """
    ##import pdb; pdb.set_trace()
    
    acme = AcmeV2(LE_SERVER, account)
    thumbprint = manuale_crypto.generate_jwk_thumbprint(account.key)

    FQDNS = dict()
    FQDNS[cert_meta.name] = 0
    for name in cert_meta.altnames:
        if name not in FQDNS:
            FQDNS[name] = 0
    domains = list(FQDNS.keys())
    
    order = acme.new_order(domains, 'dns')
    returned_order = acme.query_order(order)
    order.contents = returned_order.contents
    sld('new_order for {} returned\n{}'.
        format(cert_meta.name, print_order(returned_order)))
    if order.expired or order.invalid:
        sle("{}: Order is {} {}. Giving up.".
            format(cert_meta.name, 'invalid' if order.invalid else '',
              'expired' if order.expired else ''))
        return None
    
    returned_fqdns = [idf['value'] for idf in order.contents['identifiers']]
    if set(domains) != set(returned_fqdns):
        sle("{}: List of FQDNS returned by order does not match ordered FQDNs:\n{}\n{}".
                                    format(returned_fqdns, domains))
        return None

    if order.contents['status'] != 'pending':
        return order        # all done, if now challenge pending
     
    fqdn_challenges = {}    # key = domain, value = chllenge
    pending_challenges = acme.get_order_challenges(order)
    for challenge in pending_challenges: 
        fqdn_challenges[challenge.domain] = challenge
    
    try:
        # putting challenges into zone include fules for named server
        zones = {}
        sld('Calling zone_and_FQDN_from_altnames()')
        for (zone, fqdn) in zone_and_FQDN_from_altnames(cert_meta):
            if fqdn in fqdn_challenges:
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
                lines.append(str('_acme-challenge.{}.  IN TXT  \"{}\"\n'.
                        format(fqdn,fqdn_challenges[fqdn].key)))
            sli('Writing RRs: {}'.format(lines))
            with open(dest, 'w') as file:
                file.writelines(lines)
                ##os.chmod(file.fileno(), Pathes.zone_tlsa_inc_mode)
                ##os.chown(file.fileno(), pathes.zone_tlsa_inc_uid, pathes.zone_tlsa_inc_gid)
            updateZoneCache(zone)
        
        updateSOAofUpdatedZones()

        # Validate challenges
        authorized_until = None
        done, failed, pending = set(), set(), set()
        for challenge in pending_challenges:
            sld("{}: waiting for verification. Checking in 5 "
                  "seconds.".format(challenge.domain))
            response = acme.verify_order_challenge(challenge, 5, 1)
            if response['status'] == "valid":
                sld("{}: OK! Authorization lasts until {}.".format(
                    challenge.domain, challenge.expires))
                authorized_until = challenge.expires
                done.add(challenge.domain)
            elif response['status'] == 'invalid':
                sle("{}: Challenge failed, because: {} ({})".format(
                    challenge.domain,
                    response['error']['detail'],
                    response['error']['type'])
                )
                failed.add(challenge.domain)
                break
            else:
                sle("{}: Pending!".format(challenge.domain))
                pending.add(challenge.domain)
                break
        
        # remember new expiration date in DB
        if authorized_until:
            updates = cert_meta.update_authorized_until(
                datetime.datetime.fromisoformat(re.sub('Z','',authorized_until)))
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
            return None
        else:
            sli("{} fqdn(s) authorized. Let's Encrypt!".format(len(done)))
            return order
        
    except IOError as e:
        sle('A connection or service error occurred. Aborting.')
        raise manuale_errors.AutomatoesError(e)
    