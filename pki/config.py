
from pathlib import Path

class Pathes(object):
    """
    Definition of path config variables
    """
    
    home = Path('/var/pki_dev/productive_CA').resolve()       # adjust
    
    db = home / 'db'
    ca_cert = db / 'ca_cert.pem'
    ca_key = db / 'ca_key.pem'
    le_account = db / 'account.json'    
    work = home / 'work'
    work_tlsa = work / 'TLSA'
    
    tlsa_dns_master = ''
    ##tlsa_repository_root = Path('/usr/local/etc/namedb/master/signed')
    tlsa_repository_root = Path('/tmp')
    
class X509atts(object):
    """
    Definition of fixed X.509 cert attributes
    """
    names = {   'C':    'DE',
                'L':    'Frankfurt am Main',
                'O':    'LECHNER-RAU',
                'CN':   'Lechner-Rau internal CA'
            }
    
    extensions = {
    
                }
    
    lifetime = 375                         # 1 year
    bits = 2048


# Database accounts
dbAccounts = {  'pki_dev':  {'dbHost':       'db1.in.chaos1.de',
                            'dbPort':         '2222',
                            'dbUser':         'pki_dev',
                            'dbDatabase':     'pki_dev',
                            'dbSearchPath':   'pki,dd,public'}}

SSH_CLIENT_USER_NAME = 'root'

##LE_SERVER = 'https://acme-v01.api.letsencrypt.org'
LE_SERVER = 'https://acme-staging.api.letsencrypt.org'

# subjects in table Subjects:

SUBJECT_LOCAL_CA = 'Local CA'
LOCAL_CA_BITS = 4096
LOCAL_CA_LIFETIME = 3680

SUBJECT_LE_CA = 'Lets Encrypt CA'


# do we need his:  ??
DEBUG = True

def debugging(arg):
    global DEBUG
    DEBUG = arg
