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
from typing import Optional
import logging
import os
import re
import sys
import time

from dns import rdatatype
from dns import query as dns_query
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from postgresql import driver as db_conn

from . import get_version
import automatoes.acme as am
from automatoes.errors import AcmeError

# set our identity and version

am.__dict__['DEFAULT_HEADERS'] = {
    'User-Agent': "serverPKI {} (https://serverpki.readthedocs.io/en/latest/)".
        format(get_version()),
}

from automatoes.acme import AcmeV2
from automatoes.model import Account, Order
from automatoes import crypto as manuale_crypto
from automatoes import issue as manuale_issue
from automatoes import cli as manuale_cli
from automatoes import errors as manuale_errors

# --------------- local imports --------------
from serverPKI.cacert import create_CAcert_meta
from serverPKI.cert import Certificate, CertInstance, CertKeyStore, EncAlgo, EncAlgoCKS, CertState
from serverPKI.utils import sld, sli, sln, sle, Pathes, X509atts, Misc
from serverPKI.utils import updateSOAofUpdatedZones, get_options
from serverPKI.utils import updateZoneCache, print_order, ddns_update


# --------------- manuale logging ----------------

##logger = logging.getLogger(__name__)  ##FIXME##

# --------------- classes --------------

class DBStoreException(Exception):
    pass


class KeyCertException(Exception):
    pass


# --------------- public functions --------------

def issue_LE_cert(cert_meta: Certificate) -> Optional[CertInstance]:
    """
    Try to issue a Letsencrypt certificate.
    Does authorization if necessary.
    On success, inserts a row into CertInstances.
    If this is the first Letsencrypt instance, additional rows are inserted
    into Subjects, Certificates and CertInstances for LE intermediate cert.
    Additional Certinstances may also be inserted if the intermediate cert
    from LE  changes.
    :param cert_meta: Description of certificate to issue
    :return: Instance of new cert
    """

    # Set up logging
    root = logging.getLogger('automatoes')
    root.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(handler)

    os.chdir(str(Pathes.work))  ##FIXME## remove this ?

    sli('Creating certificate for {} and crypto algo {}'.format(cert_meta.name, cert_meta.encryption_algo))

    try:
        account: Account = manuale_cli.load_account(str(Pathes.le_account))
    except:
        sle('Problem with Lets Encrypt account data at {}'.
            format(Pathes.le_account))
        return None

    if cert_meta.encryption_algo == EncAlgo('rsa plus ec'):
        encryption_algos = (EncAlgoCKS('rsa'), EncAlgoCKS('ec'))
    else:
        encryption_algos = (cert_meta.encryption_algo,)

    results = []

    for encryption_algo in encryption_algos:

        result = _issue_cert_for_one_algo(encryption_algo, cert_meta, account)
        if not result:
            return None
        else:
            results.append(result)

    # loop ensures to store either all cks in DB or none:
    ci = None
    for result in results:

        if not ci:
            cacert_ci = _get_intermediate_instance(db=cert_meta.db, int_cert=result['Intermediate'])
            ci = cert_meta.create_instance(state=CertState('issued'),
                                           not_before=result['Cert'].not_valid_before,
                                           not_after=result['Cert'].not_valid_after,
                                           ca_cert_ci=cacert_ci
                                           )
        cks = ci.store_cert_key(algo=result['Algo'],
                                cert=result['Cert'],
                                key=result['Key'])

        sli('Certificate issued for {} . Valid until {}'.format(
            cert_meta.name, result['Cert'].not_valid_after.isoformat()))
        sli('Hash is: {}, algo is {}'.format(cks.hash, result['Algo']))

    cert_meta.save_instance(ci)
    return ci


# --------------- private functions --------------

def _issue_cert_for_one_algo(encryption_algo: EncAlgoCKS, cert_meta: Certificate, account: Account) -> Optional[dict]:
    """
    Try to issue a Letsencrypt certificate for one encryption algorithm.
    Does authorization if necessary.

    :param encryption_algo: encryption algo to use
    :param cert_meta: description of cert
    :param account: our account at Letsencrypt
    :return: None or dict: dict layout as follows:
             {'Cert': certificate, 'Key': certificate_key, 'Intermediate': intcert, 'Algo': encryption_algo}
    """
    options = get_options()

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

    if encryption_algo == EncAlgoCKS('rsa'):
        certificate_key = manuale_crypto.generate_rsa_key(X509atts.bits)
    elif encryption_algo == EncAlgoCKS('ec'):
        crypto_backend = default_backend()
        certificate_key = ec.generate_private_key(ec.SECP384R1(), crypto_backend)
    else:
        raise ValueError('Wrong encryption_algo {} in _issue_cert_for_one_algo for {}'.format(encryption_algo,
                                                                                              cert_meta.name))

    order.key = manuale_crypto.export_private_key(certificate_key).decode('ascii')
    csr = manuale_crypto.create_csr(certificate_key,
                                    alt_names,
                                    must_staple=cert_meta.ocsp_must_staple)

    acme = AcmeV2(Misc.LE_SERVER, account)
    try:
        sli('Requesting certificate issuance from LE...')

        if not order.contents['status'] == 'valid':
            if order.contents['status'] == 'ready':
                final_order = acme.finalize_order(order, csr)
                order.contents = final_order

                if order.contents['status'] ==  "valid":
                    sld('{}/{}:  Order finalized. Certificate is being issued.'
                        .format(cert_meta.name, encryption_algo))
                else:
                    sld("{}/{}:  Checking order status.".format(cert_meta.name, encryption_algo))
                    fulfillment = acme.await_for_order_fulfillment(order)
                    if fulfillment['status'] == "valid":
                        order.contents = fulfillment
                    else:
                        sle("{}:  Order not ready or invalid after finalize. Status = {}. Giving up. \n Response = {}"
                        .format(cert_meta.name, final_order['status'], final_order))
                    return None

        if not order.certificate_uri:
            sle("{}/{}:  Order not valid after fulfillment: Missing certificate URI"
                .format(cert_meta.name, encryption_algo))
            return None
        else:
            sli("Downloading certificate for {}/{}.".format(cert_meta.name, encryption_algo))

        result = acme.download_order_certificate(order)

    except manuale_errors.AcmeError as e:
        if '(type urn:acme:error:unauthorized, HTTP 403)' in str(e):
            sle('LetsEncrypt lost authorization for {}/{} [DOWNLOAD]. Giving up'.format(cert_meta.name,
                                                                                        encryption_algo))
        else:
            sle("Connection or service request failed for {}/{}[DOWNLOAD]. Aborting.".
                format(cert_meta.name, encryption_algo))
        raise manuale_errors.AutomatoesError(e)

    try:
        certificates = manuale_crypto.strip_certificates(result.content)  # DER
        certificate = manuale_crypto.load_pem_certificate(certificates[0])

    except IOError as e:
        sle("Failed to load new certificate for {}/{}. Aborting.".format(cert_meta.name, encryption_algo))
        raise manuale_errors.AutomatoesError(e)

    intcert = manuale_crypto.load_pem_certificate(certificates[1])

    return {'Cert': certificate, 'Key': certificate_key, 'Intermediate': intcert, 'Algo': encryption_algo}


def _get_intermediate_instance(db: db_conn, int_cert: x509.Certificate) -> CertInstance:
    """
    Return CertInstance of intermediate CA cert or create a new CertInstance if not found
    :param db: Opened DB connection
    :param int_cert: the CA cert to find the ci for
    :return: ci of CA cert
    """
    ci = CertKeyStore.ci_from_cert_and_name(db=db, cert=int_cert, name=Misc.SUBJECT_LE_CA)
    if ci:
        return ci
    sln('Storing new intermediate cert.')
    # intermediate is not in DB - insert it
    # obtain our cert meta - check, if it exists

    if Misc.SUBJECT_LE_CA in Certificate.names(db):
        cm = Certificate.create_or_load_cert_meta(db, Misc.SUBJECT_LE_CA)  # yes: we have meta but no instance
        sln('Cert meta for intermediate cert exists, but no instance.')
    else:  # no: this ist 1st cert with this CA
        sln('Cert meta for intermediate does not exist, creating {}.'.format(Misc.SUBJECT_LE_CA))
        cm = create_CAcert_meta(db=db, name=Misc.SUBJECT_LE_CA, cert_type=CertType('LE'))
    ci = cm.create_instance(state=CertState('issued'),
                            not_before=int_cert.not_valid_before,
                            not_after=int_cert.not_valid_after)
    cm.save_instance(ci)
    ci.store_cert_key(algo=EncAlgoCKS('rsa'), cert=int_cert, key=b'')  ##FIXME## might be ec in the future
    cm.save_instance(ci)

    return ci


def _authorize(cert_meta: Certificate, account: Account) -> Optional[Order]:
    """
    Try to prove the control about a DNS object.

    @param cert_meta:   Cert meta instance to issue an certificate for
    @type cert_meta:    Cert meta instance
    @param account:     Our letsencrypt account
    @type account:      manuale_cli.load_account instance
    @rtype:             True if all fqdns could be authorized, False otherwise
    @exceptions:        manuale_errors.AutomatoesError on Network or other fatal error
    """
    acme = AcmeV2(Misc.LE_SERVER, account)

    FQDNS = dict()
    FQDNS[cert_meta.name] = 0
    for name in cert_meta.altnames:
        if name not in FQDNS:
            FQDNS[name] = 0
    domains = list(FQDNS.keys())

    try:
        order: Order = acme.new_order(domains, 'dns')
    except AcmeError as e:
        print(e)
        return None
    returned_order = acme.query_order(order)
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
        if challenge.status == 'valid':
            sli("    {} is already authorized until {}.".format(
                challenge.domain, challenge.expires))
            continue

        fqdn_challenges[challenge.domain] = challenge

        # find zones by fqdn
        zones = {}
        sld('Calling zone_and_FQDN_from_altnames()')
        for (zone, fqdn) in Certificate.zone_and_FQDN_from_altnames(cert_meta):
            if fqdn in fqdn_challenges:
                if zone in zones:
                    if fqdn not in zones[zone]: zones[zone].append(fqdn)
                else:
                    zones[zone] = [fqdn]
        sld('zones: {}'.format(zones))

    if not fqdn_challenges:
        server_order = acme.query_order(order)
        order.contents = server_order.contents
        sli("All Altnames of {} are already authorized.Order status = {}".
            format(cert_meta.name, order.contents['status']))
        return order

    create_challenge_responses_in_dns(zones, fqdn_challenges)

    sld('{} completed DNS setup on hidden primary for all pending FQDNs'.
        format(datetime.datetime.utcnow().isoformat()))
    # Validate challenges
    authorized_until = None
    sli('Waiting 15 seconds for dns propagation')
    time.sleep(15)
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

    server_order = acme.query_order(order)
    order.contents = server_order.contents
    sld("All Altnames of {} authorized.Order status = {}".
        format(cert_meta.name, order.contents['status']))

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

    if Misc.LE_ZONE_UPDATE_METHOD == 'zone_file':

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

    elif Misc.LE_ZONE_UPDATE_METHOD == 'ddns':

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

    if Misc.LE_ZONE_UPDATE_METHOD == 'zone_file':

        for zone in zones.keys():
            dest = str(Pathes.zone_file_root / zone / Pathes.zone_file_include_name)
            with open(dest, 'w') as file:
                file.writelines(('',))
            updateZoneCache(zone)
        updateSOAofUpdatedZones()

    elif Misc.LE_ZONE_UPDATE_METHOD == 'ddns':

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
