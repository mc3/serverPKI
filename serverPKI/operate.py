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

# commandline interface module

import sys
from typing import List, Dict

from paramiko import util
from postgresql import driver as db_conn

from serverPKI.cacert import issue_local_CAcert
from serverPKI.cert import Certificate, CertType
from serverPKI.certdist import deployCerts, consolidate_TLSA, consolidate_cert, delete_TLSA, export_instance
from serverPKI.config import LE_SERVER, LE_EMAIL, Pathes, SUBJECT_LOCAL_CA, SUBJECT_LE_CA
from serverPKI.db import DbConnection as dbc
from serverPKI.issue_LE import issue_LE_cert
from serverPKI.issue_local import issue_local_cert

from serverPKI.utils import options as opts
from serverPKI.utils import get_name_string, options_set, check_actions
from serverPKI.utils import names_of_local_certs_to_be_renewed, print_certs
from serverPKI.utils import options_set, check_actions, updateSOAofUpdatedZones
from serverPKI.utils import read_db_encryption_key, encrypt_all_keys, decrypt_all_keys
from serverPKI.utils import sld, sli, sln, sle
from serverPKI.schedule import scheduleCerts

from automatoes.register import register


def execute_from_command_line():
    import pydevd_pycharm
    pydevd_pycharm.settrace('axels-imac.in.chaos1.de', port=4711, stdoutToServer=True, stderrToServer=True)

    all_cert_names: List[str, ...] = []
    our_cert_names: List[str, ...] = []
    our_certs: Dict[str, Certificate] = {}

    util.log_to_file('sftp.log')

    sli('operateCA [{}]started with options {}'.format(
        get_name_string(), options_set()))
    check_actions()

    pe = dbc('serverpki')
    db: db_conn = pe.open()

    read_db_encryption_key(db)

    preload_ca_cert_metas(db)

    all_cert_names = Certificate.names(db)

    sli('{} certificates in configuration'.format(len(all_cert_names)))

    if opts.encrypt:
        if encrypt_all_keys(db):
            sys.exit(0)
        sys.exit(1)
    if opts.decrypt:
        if decrypt_all_keys(db):
            sys.exit(0)
        sys.exit(1)
    if opts.issue_local_cacert:
        if issue_local_CAcert(db):
            sys.exit(0)
        sys.exit(1)

    if opts.all:
        our_cert_names = all_cert_names
    elif opts.remaining_days:
        our_cert_names = names_of_local_certs_to_be_renewed(db,
                                                            opts.remaining_days,
                                                            opts.distribute)
        if not opts.create:
            opts.create = not opts.distribute

    cert_name_set: set = set(our_cert_names)

    error = False

    if opts.only_cert:
        error = False
        for i in opts.only_cert:
            if i not in all_cert_names:
                sle("{} not in configuration. Can't be specified with --only".format(i))
                error = True
        if not error:
            cert_name_set = set(opts.only_cert)

    else:
        if opts.cert_to_be_included:
            error = False
            for i in opts.cert_to_be_included:
                if i not in all_cert_names:
                    sle("{} not in configuration. Can't be included".format(i))
                    error = True
            if not error:
                cert_name_set = set(opts.cert_to_be_included)

        if opts.cert_to_be_excluded:
            error = False
            for i in opts.cert_to_be_excluded:
                if i not in all_cert_names:
                    sle("{} not in configuration. Can't be excluded".format(i))
                    error = True
            if not error:
                cert_name_set -= set(opts.cert_to_be_excluded)

    if error:
        sle('Stopped due to command line errors')
        sys.exit(1)

    our_cert_names = sorted(list(cert_name_set))

    for name in our_cert_names:
        c = Certificate(db, name)
        if c: our_certs[name] = c

    if opts.check_only and not opts.schedule:
        sli('No syntax errors found in configuration.')
        ##sli('Selected certificates:\n\r{}'.format(our_cert_names))
        print_certs(db, our_cert_names)
        sys.exit(0)

    sld('Selected certificates:\n\r{}'.format(our_cert_names))

    if opts.schedule:
        sli('Scheduling actions.')
        scheduleCerts(db, our_cert_names)
    else:
        if opts.create:
            sli('Creating certificates.')
            for c in our_certs.values():
                if c.cert_type == CertType('LE'):
                    if issue_LE_cert(c):
                        continue
                elif  c.cert_type == CertType('local'):
                    if issue_local_cert(c):
                        continue
                else:
                    raise AssertionError('Invalid CertType in {}'.format(c.name))
                sle('Stopped due to error')
                sys.exit(1)

        if opts.distribute:
            sli('Distributing certificates.')
            deployCerts(our_certs)

    if opts.sync_disk:
        for c in our_certs.values():
            consolidate_cert(c)

    if opts.sync_tlsas:
        for c in our_certs.values():
            consolidate_TLSA(c)
        updateSOAofUpdatedZones()

    if opts.remove_tlsas:
        for c in our_certs.values():
            delete_TLSA(c)
        updateSOAofUpdatedZones()

    if opts.cert_serial:
        sli('Exporting certificate instance.')
        export_instance(db)

    if opts.register:
        sli('Registering a new Let\'s Encrypt Account.\n With URI:{}\n'
            ' and e-mail {}'.format(LE_SERVER, LE_EMAIL))
        register(LE_SERVER, Pathes.le_account, LE_EMAIL, None)


def preload_ca_cert_metas(db: db_conn) -> None:
    """
    Preload (or create, if required) the CA cert meta data instances,
    to have their CIs handy for referencing them from other CIs
    :param db: Opened DB connection
    :return:
    """
    # make sure cert meta of CAs are loaded (for referencing them from CI).
    for ca_name in (SUBJECT_LOCAL_CA, SUBJECT_LE_CA):
        if not Certificate.ca_cert_meta(db, ca_name):
            sys.exit(1)

def issue(db: db_conn, cert_meta: Certificate) -> bool:
    """
    Issue a new certificate
    :param db: opened database connection
    :param cert_meta: cert meta data instance describing attributes of new certs
    :return: True if success, False otherwise
    :exceptions: May raise assertion error on corrupt DB contents
    """
    """
    Issue a new certificate instance and store it
    in the DB table certinstances.

    @rtype:             bool, true if success
    @exceptions:        AssertionError
    """
    with db.xact(isolation='SERIALIZABLE', mode='READ WRITE'):
        if cert_meta.cert_type == CertType('LE'):
            result = issue_LE_cert(cert_meta)
        elif cert_meta.cert_type == CertType('local'):
            result = issue_local_cert(cert_meta)
        else:
            raise AssertionError
    if result:
        return True
    return False

