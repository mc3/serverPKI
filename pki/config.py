
from pathlib import Path

class Pathes(object):
    """
    Definition of path config variables
    """
    
    home = Path('/var/pki_dev/productive_CA').resolve()       # adjust
    
    db = home / 'db'
    ca_cert = db / 'ca_cert.pem'
    ca_key = db / 'ca_key.pem'
    ca_serial = db / 'ca_serial.txt'
    
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
                'ST':   'Hessen',
                'L':    'Frankfurt am Main',
                'O':    'LECHNER-RAU',
                'OU':   'Secure Internet Server'
            }
    
    extensions = {
    
                }
    
    lifetime = 60*60*24*370                         # 1 year
    bits = 2048

DEBUG = True

def debugging(arg):
    global DEBUG
    DEBUG = arg

# Database accounts
dbAccounts = {  'pki_dev':  {'dbHost':       'db1.in.chaos1.de',
                            'dbPort':         '2222',
                            'dbUser':         'pki_dev',
                            'dbDatabase':     'pki_dev',
                            'dbSearchPath':   'pki,dd,public'}}

SSH_CLIENT_USER_NAME = 'root'
