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

# adjusted from example configuration for serverPKI


from datetime import timedelta
from pathlib import Path
import stat
import syslog

class Pathes(object):
    """
    Definition of path config variables
    """
    home = (Path(__file__).parent.parent / 'tmpdir').resolve()
    
    # some flat files not in RDBMS
    db = home / 'db'
    
    # local CA cert
    ca_cert = db / 'ca_cert.pem'
    ca_key = db / 'ca_key.pem'
    
    # encryption of keys in db
    db_encryption_key = db / 'db_encryption_key.pem'
    
    # lets encrypt
    le_account = db / 'account.json'    
    
    work = home / 'work'
    work_tlsa = work / 'TLSA'
    
    tlsa_dns_master = ''
    dns_key = db / 'dns'
    
    
    # required convention: zone_file_root/example.com/example.com.zone
    
    zone_file_root = Path('/usr/local/etc/namedb/master/signed')
    
    # mode + owner of *.tlsa and acme_challenges.inc files in zone directory
    zone_tlsa_inc_mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP
    zone_tlsa_inc_uid = 53
    zone_tlsa_inc_gid = 2000
    
    zone_file_include_name = 'acme_challenges.inc'
    
    # adjust
    ddns_key_file = '/usr/local/etc/namedb/dns-keys/ddns-key.conf'
    
    
class X509atts(object):
    """
    Definition of fixed X.509 cert attributes for your organization
    """
    names = {   'C':    'DE',
                'L':    'Some city',
                'O':    'Some Org',
                'CN':   'Some Org internal CA' # used only for cacert
            }
    
    extensions = {
    
                }
    
    lifetime = 375                     # 1 year
    bits = 2048                        # also used for Letsencrypt


# Database accounts
dbAccounts = {'serverpki': {'dbHost':         'localhost',
                            'dbPort':         '5432',
                            'dbUser':         'serverPKI',
                            'dbDbaUser':      '',
                            'dbDatabase':     'serverPKI',
                            'dbSslRequired':  False,
                            'dbSearchPath':   'pki,dd'}}

SSH_CLIENT_USER_NAME = 'root'

# -- Letsencrypt
LE_SERVER = 'https://acme-staging-v02.api.letsencrypt.org'
##LE_SERVER = 'https://acme-v02.api.letsencrypt.org'

# e-mail for registration
LE_EMAIL = 'axel.rau@l.chaos1.de'

# zone update method for challenge ('ddns' or 'zone_file')
LE_ZONE_UPDATE_METHOD = 'ddns'

# -- for certs issued by local CA
# Key size and lifetime of local CA cert
LOCAL_CA_BITS = 4096
LOCAL_CA_LIFETIME = 3680                # 10 years

# subjects in table Subjects for CA certs:
SUBJECT_LOCAL_CA = 'Local CA'
SUBJECT_LE_CA = 'Lets Encrypt CA'

# how many days before cert deployment is new cert together with old cert published in DNS
PRE_PUBLISH_TIMEDELTA = timedelta(days=7)
LOCAL_ISSUE_MAIL_TIMEDELTA = timedelta(days=30)

MAIL_RELAY = 'my.outgoing.relay.do.main'
MAIL_SUBJECT = 'Local certificate issue reminder'
MAIL_SENDER = 'pki_op@some.host'
MAIL_RECIPIENT = 'me@some.host'

SYSLOG_FACILITY = syslog.LOG_LOCAL6