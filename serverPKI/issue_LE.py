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


# --------------- imported modules --------------
import binascii
import datetime
import logging
import os
import re
import sys
import time

from dns import rdatatype
from dns import query as dns_query
from cryptography.hazmat.primitives.hashes import SHA256

from . import get_version
import automatoes.acme as am

am.__dict__['DEFAULT_HEADERS'] = {
    'User-Agent': "serverPKI {} (https://serverpki.readthedocs.io/en/latest/)".
    format(get_version()),
}

from automatoes.acme import AcmeV2
from automatoes import crypto as manuale_crypto
from automatoes import issue as manuale_issue
from automatoes import cli as manuale_cli
from automatoes import errors as manuale_errors

# --------------- local imports --------------
from serverPKI.cacert import create_CAcert_meta
from serverPKI.config import (Pathes, X509atts, LE_SERVER, SUBJECT_LE_CA,
                              LE_ZONE_UPDATE_METHOD)
from serverPKI.utils import sld, sli, sln, sle, options, update_certinstance
from serverPKI.utils import zone_and_FQDN_from_altnames, updateSOAofUpdatedZones
from serverPKI.utils import updateZoneCache, encrypt_key, print_order, ddns_update

# --------------- manuale logging ----------------

##logger = logging.getLogger(__name__)

# --------------- Places --------------
places = {}


# --------------- classes --------------

class DBStoreException(Exception):
    pass


class KeyCertException(Exception):
    pass


# ---------------  prepared SQL queries for create_LE_instance  --------------

q_insert_LE_instance = """
    INSERT INTO CertInstances 
            (certificate, state, cert, key, hash, cacert, not_before, not_after, encryption_algo, ocsp_must_staple)
        VALUES ($1::INTEGER, 'issued', $2, $3, $4, $5, $6::TIMESTAMP, $7::TIMESTAMP, $8, $9::BOOLEAN)
        RETURNING id::int
"""
ps_insert_LE_instance = None


# --------------- public functions --------------

##import pdb; pdb.set_trace()


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
    @rtype:             list of cert instances ids in DB of new certs or None
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

    os.chdir(str(Pathes.work))  ##FIXME## remove this ?

    sli('Creating certificate for {} and crypto algo {}'.format(cert_meta.name, cert_meta.encryption_algo))

    try:
        account = manuale_cli.load_account(str(Pathes.le_account))
    except:
        sle('Problem with Lets Encrypt account data at {}'.
            format(Pathes.le_account))

    if cert_meta.encryption_algo == 'rsa_plus_ec':
        encryption_algos = ('rsa', 'ec')
    else:
        encryption_algos = (cert_meta.encryption_algo,)

    results = []

    for encryption_algo in encryption_algos:

        result = _issue_cert_for_one_algo(encryption_algo, cert_meta, account)
        if not result:
            return None
        else:
            results.append(result)

    # loop ensures to store either all certs in DB or none:
    certinstances = []
    for result in results:

        intcert_instance_id = _get_intermediate_instance(cert_meta.db, result['Intermediate'])
        certificate = result['Cert']

        not_valid_before = certificate.not_valid_before
        not_valid_after = certificate.not_valid_after

        cert_pem = manuale_crypto.export_pem_certificate(certificate)

        key_pem = encrypt_key(result['Key'])
        if not key_pem:  # no keyencryption in DB in use
            key_pem = manuale_crypto.export_private_key(result['Key'])
        tlsa_hash = binascii.hexlify(
            certificate.fingerprint(SHA256())).decode('ascii').upper()

        sli('Certificate issued for {} . Valid until {}'.format(cert_meta.name, not_valid_after.isoformat()))
        sli('Hash is: {}, algo is {}'.format(tlsa_hash, result['Algo']))

        if not ps_insert_LE_instance:
            ps_insert_LE_instance = cert_meta.db.prepare(q_insert_LE_instance)
        (instance_id) = ps_insert_LE_instance.first(
            cert_meta.cert_id,
            cert_pem,
            key_pem,
            tlsa_hash,
            intcert_instance_id,
            not_valid_before,
            not_valid_after,
            result['Algo'],
            cert_meta.ocsp_must_staple)
        if instance_id:
            certinstances.append(instance_id)
        else:
            sle('Failed to store new cert of {}, algo {} in DB backend'.format(cert_meta.name, result['Algo']))
            return None

    return certinstances


# ---------------  prepared SQL queries for private functions  --------------

q_query_LE_intermediate = """
    SELECT id from CertInstances
        WHERE hash = $1 
"""
ps_query_LE_intermediate = None


# --------------- private functions --------------

def _issue_cert_for_one_algo(encryption_algo, cert_meta, account):

    alt_names = [cert_meta.name, ]
    if len(cert_meta.altnames) > 0:
        alt_names.extend(cert_meta.altnames)

    sli('Creating {} key and {} cert for {}'.format(
        'rsa {} bits'.format(int(X509atts.bits)) if encryption_algo == 'rsa' else 'ec',
        cert_meta.subject_type,
        cert_meta.name))

    order = _authorize(cert_meta, account)
    if not order:
        return None

    if encryption_algo == 'rsa':
        certificate_key = manuale_crypto.generate_rsa_key(X509atts.bits)
    elif encryption_algo == 'ec':
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        crypto_backend = default_backend()
        certificate_key = ec.generate_private_key(ec.SECP384R1(), crypto_backend)
    else:
        raise ValueError('Wrong encryption_algo in _issue_cert_for_one_algo')

    order.key = manuale_crypto.export_private_key(certificate_key).decode('ascii')
    csr = manuale_crypto.create_csr(certificate_key,
                                    alt_names,
                                    must_staple=cert_meta.ocsp_must_staple)

    acme = AcmeV2(LE_SERVER, account)
    try:
        sli('Requesting certificate issuance from LE...')

        if order.contents['status'] == 'ready':
            final_order = acme.finalize_order(order, csr)
            order.contents = final_order

            if final_order['status'] in ["processing", "valid"]:
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
            sli("We already know the certificate uri for order {}. "
                "Downloading certificate.".format(cert_meta.name))

        result = acme.download_order_certificate(order)

    except manuale_errors.AcmeError as e:
        if '(type urn:acme:error:unauthorized, HTTP 403)' in str(e):
            sle('LetsEncrypt lost authorization for {} [DOWNLOAD]. Giving up'.format(cert_meta.name))
        else:
            sle("Connection or service request failed [DOWNLOAD]. Aborting.")
        raise manuale_errors.AutomatoesError(e)

    try:
        certificates = manuale_crypto.strip_certificates(result.content)  # DER
        certificate = manuale_crypto.load_pem_certificate(certificates[0])

    except IOError as e:
        sle("Failed to load new certificate. Aborting.")
        raise manuale_errors.AutomatoesError(e)

    intcert = manuale_crypto.load_pem_certificate(certificates[1])

    return {'Cert': certificate, 'Key': certificate_key, 'Intermediate': intcert, 'Algo': encryption_algo}


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

    the_hash = binascii.hexlify(
        int_cert.fingerprint(SHA256())).decode('ascii').upper()

    if not ps_query_LE_intermediate:
        ps_query_LE_intermediate = db.prepare(q_query_LE_intermediate)
    (instance_id) = ps_query_LE_intermediate.first(the_hash)
    if instance_id:
        return instance_id

    # new intermediate - put it into DB

    instance_id = create_CAcert_meta(db, 'LE', SUBJECT_LE_CA)

    not_valid_before = int_cert.not_valid_before
    not_valid_after = int_cert.not_valid_after

    cert_pem = manuale_crypto.export_pem_certificate(int_cert)

    (updates) = update_certinstance(db, instance_id, cert_pem, b'', the_hash,
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
    acme = AcmeV2(LE_SERVER, account)

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
            format(cert_meta.name, returned_fqdns, domains))
        return None

    if order.contents['status'] != 'pending':
        return order  # all done, if now challenge pending

    fqdn_challenges = {}  # key = domain, value = chllenge
    pending_challenges = acme.get_order_challenges(order)
    for challenge in pending_challenges:
        fqdn_challenges[challenge.domain] = challenge

        # find zones by fqdn
        zones = {}
        sld('Calling zone_and_FQDN_from_altnames()')
        for (zone, fqdn) in zone_and_FQDN_from_altnames(cert_meta):
            if fqdn in fqdn_challenges:
                if zone in zones:
                    if fqdn not in zones[zone]: zones[zone].append(fqdn)
                else:
                    zones[zone] = [fqdn]
        sld('zones: {}'.format(zones))

    create_challenge_responses_in_dns(zones, fqdn_challenges)

    sld('{} completed DNS setup on hidden primary for all pending FQDNs'.
        format(datetime.datetime.utcnow().isoformat()))
    # Validate challenges
    authorized_until = None
    sli('Waiting 60 seconds for dns propagation')
    time.sleep(60)
    for challenge in pending_challenges:

        # wait maximum 2 minutes
        sld('{} starting verification of {}'.
            format(datetime.datetime.utcnow().isoformat(), challenge.domain))
        response = acme.verify_order_challenge(challenge,
                                               timeout=5,
                                               retry_limit=5)
        sld('{} acme.verify_order_challenge returned "{}"'.
            format(datetime.datetime.utcnow().isoformat(), response['status']))
        if response['status'] == "valid":
            sld("{}: OK! Authorization lasts until {}.".format(
                challenge.domain, challenge.expires))
            authorized_until = challenge.expires
        elif response['status'] == 'invalid':
            sle("{}: Challenge failed, because: {} ({})".format(
                challenge.domain,
                response['error']['detail'],
                response['error']['type'])
            )
            # we need either all challenges or none: repeat with next cron cacle
            return None
        else:
            sln("{}: Challenge returned status {}".format(
                challenge.domain,
                response['status']))
            # we need either all challenges or none: repeat with next cron cacle
            return None

    # remember new expiration date in DB
    if authorized_until:
        updates = cert_meta.update_authorized_until(
            datetime.datetime.fromisoformat(re.sub('Z', '', authorized_until)))
        if updates != 1:
            sln('Failed to update DB with new authorized_until timestamp')

    delete_challenge_responses_in_dns(zones)

    sli("FQDNs authorized. Let's Encrypt!")
    return order


def create_challenge_responses_in_dns(zones, fqdn_challenges):
    """
    Create the expected challenge response in dns
    
    @param zones:           dict of zones, where each zone has a list of fqdns
                            as values
    @type zones:            dict()
    @param fqdn_challenges: dict of zones, containing challenge response
                            (key) of zone 
    @type fqdn_challenges:  dict()
    @rtype:                 None
    @exceptions             Can''t parse ddns key or
                            DNS update failed for zone {} with rcode: {}
    """

    if LE_ZONE_UPDATE_METHOD == 'zone_file':

        for zone in zones.keys():
            dest = str(Pathes.zone_file_root / zone / Pathes.zone_file_include_name)
            lines = []
            for fqdn in zones[zone]:
                sld('fqdn: {}'.format(fqdn))
                lines.append(str('_acme-challenge.{}.  IN TXT  \"{}\"\n'.
                                 format(fqdn, fqdn_challenges[fqdn].key)))
            sli('Writing RRs: {}'.format(lines))
            with open(dest, 'w') as file:
                file.writelines(lines)
                ##os.chmod(file.fileno(), Pathes.zone_tlsa_inc_mode)
                ##os.chown(file.fileno(), pathes.zone_tlsa_inc_uid, pathes.zone_tlsa_inc_gid)
            updateZoneCache(zone)
        updateSOAofUpdatedZones()

    elif LE_ZONE_UPDATE_METHOD == 'ddns':

        txt_datatape = rdatatype.from_text('TXT')
        for zone in zones.keys():
            the_update = ddns_update(zone)
            for fqdn in zones[zone]:
                the_update.delete('_acme-challenge.{}.'.format(fqdn),
                                  txt_datatape)
                the_update.add('_acme-challenge.{}.'.format(fqdn),
                               60,
                               txt_datatape,
                               fqdn_challenges[fqdn].key)
                sld('DNS update of RR: {}'.format('_acme-challenge.{}.  60 TXT  \"{}\"'.
                                                  format(fqdn, fqdn_challenges[fqdn].key)))
            response = dns_query.tcp(the_update, '127.0.0.1', timeout=10)
            sld('DNS update delete/add returned response: {}'.format(response))
            rc = response.rcode()
            if rc != 0:
                sle('DNS delete failed for zone {} with rcode: {}:\n{}'.
                    format(zone, rc.to_text(rc), rc))
                raise Exception('DNS update failed for zone {} with rcode: {}'.
                                format(zone, rc.to_text(rc)))


def delete_challenge_responses_in_dns(zones):
    """
    Delete the challenge response in dns, created by
                            create_challenge_responses_in_dns()
    
    @param zones:           dict of zones, where each zone has a list of fqdns
                            as values
    @type zones:            dict()
    @rtype:                 None
    @exceptions             Can''t parse ddns key or
                            DNS update failed for zone {} with rcode: {}
    """

    if LE_ZONE_UPDATE_METHOD == 'zone_file':

        for zone in zones.keys():
            dest = str(Pathes.zone_file_root / zone / Pathes.zone_file_include_name)
            with open(dest, 'w') as file:
                file.writelines(('',))
            updateZoneCache(zone)
        updateSOAofUpdatedZones()

    elif LE_ZONE_UPDATE_METHOD == 'ddns':

        txt_datatape = rdatatype.from_text('TXT')
        for zone in zones.keys():
            the_update = ddns_update(zone)
            for fqdn in zones[zone]:
                the_update.delete(
                    '_acme-challenge.{}.'.format(fqdn),
                    txt_datatape)
            response = dns_query.tcp(the_update, '127.0.0.1', timeout=10)
            sld('DNS update delete/add returned response: {}'.format(response))
            rc = response.rcode()
            if rc != 0:
                sle('DNS update failed for zone {} with rcode: {}:\n{}'.
                    format(zone, rc.to_text(rc), rc))
                raise Exception('DNS update failed for zone {} with rcode: {}'.
                                format(zone, rc.to_text(rc)))
