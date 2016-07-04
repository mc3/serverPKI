#!/usr/bin/env python3

"""
Create server certificates.
"""

import sys
from paramiko import util

##from pki.config import Subjects
##from pki.certdist import traverseConfigTree
##from pki.certrunner import create_certs
from pki.utils import options as opts

from pki.db import DbConnection as dbc
from pki.utils import sli, sln, sle
from pki.cert import Certificate
            
#--------------- main --------------

all_cert_names = []
our_cert_names = []
our_certs = {}


util.log_to_file('sftp.log')

pe = dbc('pki_dev')
db = pe.open()


row_list = db.query("""
    SELECT name from Subjects
        WHERE isAltName = FALSE
        ORDER BY name""",)


for (name,) in row_list:
    all_cert_names.append(name)

if opts.verbose: print('[{} certificates in configuration]'.format(len(all_cert_names)))

if opts.all:
    our_cert_names = all_cert_names

cert_name_set = set(our_cert_names)

error = False

if opts.only_cert:
    error = False
    for i in opts.only_cert:
        if i not in all_cert_names:
            print("? {} not in configuration. Can't be specified with --only".format(i))
            error = True
    if not error:
        cert_name_set = set(opts.only_cert)

else:
    if opts.cert_to_be_included:
        error = False
        for i in opts.cert_to_be_included:
            if i not in all_cert_names:
                print("? {} not in configuration. Can't be included".format(i))
                error = True
        if not error:
            cert_name_set = set(opts.cert_to_be_included)
    
    if opts.cert_to_be_excluded:
        error = False
        for i in opts.cert_to_be_excluded:
            if i not in all_cert_names:
                print("? {} not in configuration. Can't be excluded".format(i))
                error = True
        if not error:
            cert_name_set -= set(cert_to_be_excluded)

if error:
    print('?Stopped due to command line errors')
    sys.exit(1)

our_cert_names = sorted(list(cert_name_set))

for name in our_cert_names:
    c = Certificate(db, name)
    our_certs[name] = c

if opts.check_only:
    print('[No syntax errors found in configuration.]')
    sys.exit(0)

if opts.debug: print('[Selected certificates:]\n\r{}'.format(our_cert_names))

"""
if opts.create:
    if create_certs(our_cert_names):
        if opts.distribute:
            print()
            traverseConfigTree('dist', our_cert_names)
else:
    if opts.distribute:
        traverseConfigTree('dist', our_cert_names)
"""