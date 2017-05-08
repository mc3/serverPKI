
from datetime import timedelta
from pathlib import Path

class Pathes(object):
    """
    Definition of path config variables
    """
    
    home = Path('/var/pki_op/productive_CA').resolve()       # adjust
    
    # some flat files not in RDBMS
    db = home / 'db'
    ca_cert = db / 'ca_cert.pem'
    ca_key = db / 'ca_key.pem'
    le_account = db / 'account.json'    
    work = home / 'work'
    work_tlsa = work / 'TLSA'
    
    tlsa_dns_master = ''
    dns_key = db / 'dns'
    
    
    # required convention: zone_file_root/example.com/example.com.zone
    
    zone_file_root = Path('/usr/local/etc/namedb/master/signed')
    zone_file_include_name = 'acme_challenges.inc'
    
    
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
    bits = 2048


# Database accounts
dbAccounts = {  'serverpki':  {'dbHost':       'db-server.my.domain',
                            'dbPort':         '5432',
                            'dbUser':         'pki_op',
                            'dbDatabase':     'serverpki',
                            'dbSearchPath':   'pki,dd'}}

SSH_CLIENT_USER_NAME = 'root'

LE_SERVER = 'https://acme-staging.api.letsencrypt.org'

# subjects in table Subjects:

SUBJECT_LOCAL_CA = 'Local CA'
LOCAL_CA_BITS = 4096
LOCAL_CA_LIFETIME = 3680

SUBJECT_LE_CA = 'Lets Encrypt CA'
PRE_PUBLISH_TIMEDELTA = timedelta(days=7)
LOCAL_ISSUE_MAIL_TIMEDELTA = timedelta(days=30)

MAIL_RELAY = 'my.outgoing.relay.do.main'
MAIL_SUBJECT = 'Local certificate issue reminder'
MAIL_SENDER = 'pki_op@some.host'
MAIL_RECIPIENT = 'me@some.host'
