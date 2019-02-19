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

# commandline interface module

import sys
from paramiko import util

from serverPKI.certdist import deployCerts, consolidate_TLSA, consolidate_cert, delete_TLSA, export_instance
from serverPKI.utils import options as opts

from serverPKI.utils import options_set, check_actions
from serverPKI.utils import updateSOAofUpdatedZones
from serverPKI.utils import names_of_local_certs_to_be_renewed, print_certs

from serverPKI.utils import options_set, check_actions, updateSOAofUpdatedZones
from serverPKI.utils import read_db_encryption_key,encrypt_all_keys,decrypt_all_keys

from serverPKI.db import DbConnection as dbc
from serverPKI.utils import sld, sli, sln, sle
from serverPKI.cacert import issue_local_CAcert
from serverPKI.cert import Certificate
from serverPKI.schedule import scheduleCerts
            
def execute_from_command_line():

    all_cert_names = []
    our_cert_names = []
    our_certs = {}
    
    
    util.log_to_file('sftp.log')
    
    
    sli('operateCA started with options {}'.format(options_set()))
    check_actions()
     
    pe = dbc('serverpki')
    db = pe.open()
    
    read_db_encryption_key(db)
    
    row_list = db.query("""
        SELECT name from Subjects
            WHERE isAltName = FALSE
            ORDER BY name""",)
    
    
    for (name,) in row_list:
        all_cert_names.append(name)
    
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
    
    cert_name_set = set(our_cert_names)
    
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
                cert_name_set -= set(cert_to_be_excluded)
    
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
                if c.create_instance():
                    continue
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
    
