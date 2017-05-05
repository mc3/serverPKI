#!/usr/bin/env python3

"""
Create server certificates.
"""

import sys
from paramiko import util

from serverPKI.certdist import deployCerts, consolidate_TLSA, consolidate_cert, delete_TLSA
from serverPKI.utils import options as opts
from serverPKI.utils import options_set, check_actions, reloadNameServer, updateSOAofUpdatedZones

from serverPKI.db import DbConnection as dbc
from serverPKI.utils import sld, sli, sln, sle
from serverPKI.cert import Certificate
from serverPKI.schedule import scheduleCerts
            
def execute_from_command_line():

    all_cert_names = []
    our_cert_names = []
    our_certs = {}
    
    
    util.log_to_file('sftp.log')
    
    
    sli('operateCA started with options {}'.format(options_set()))
    check_actions()
     
    pe = dbc('pki_dev')
    db = pe.open()
    
    """
    c = Certificate(db, 'disttest.mailsec.net')
    h = c.TLSA_hash(58)
    sld('Returned value from TLSA_hash: {}'.format(h))
    exit(0)
    """
    
    row_list = db.query("""
        SELECT name from Subjects
            WHERE isAltName = FALSE
            ORDER BY name""",)
    
    
    for (name,) in row_list:
        all_cert_names.append(name)
    
    sli('{} certificates in configuration'.format(len(all_cert_names)))
    
    if opts.all:
        our_cert_names = all_cert_names
    
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
        reloadNameServer()
    
    if opts.remove_tlsas:
        for c in our_certs.values():
            delete_TLSA(c)
        updateSOAofUpdatedZones()
        reloadNameServer()
    
    if opts.extract:
        sli('Extracting certificates.')
        deployCerts(our_certs, allowed_states=('issued', 'prepublished', 'deployed'))
    