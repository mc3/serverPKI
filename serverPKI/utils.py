"""
Copyright (C) 2015-2017  Axel Rau <axel.rau@chaos1.de>

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

# utility module of serverPKI (commandline parsing, logging ...)


#--------------- imported modules --------------
from datetime import datetime, timedelta
import optparse
from pathlib import Path
import subprocess
import re
import sys
import syslog

from prettytable import PrettyTable

from serverPKI.config import Pathes, SSH_CLIENT_USER_NAME, SYSLOG_FACILITY

#--------- globals ***DO WE NEED THIS?*** ----------

global options, db_encryption_key

class MyException(Exception):
    pass

#--------------- command line options --------------

parser = optparse.OptionParser(description='Server PKI Operations')
parser.add_option('--schedule-actions', '-S', dest='schedule', action='store_true',
                   default=False,
                   help='Scan configuration and schedule necessary actions of'
                    ' selected certs/hosts. This may trigger issuence or '
                    ' distribution of certs/TLSA-RRS. With this options "--create-certs" and'
                    ' "--distribute-certs" are ignored. Any state transitions may happen')
                   
parser.add_option('--consolidate-certs', '-K', dest='sync_disk', action='store_true',
                   default=False,
                   help='Consolidate targets to be in sync with DB.'
                   ' This affects certs in state "deployed".')
                   
parser.add_option('--consolidate-TLSAs', '-T', dest='sync_tlsas', action='store_true',
                   default=False,
                   help='Consolidate TLSA-RR to be in sync with DB.'
                   ' This affects certs in state "deployed" or "prepublished".')
                   
parser.add_option('--remove-TLSAs', '-R', dest='remove_tlsas', action='store_true',
                   default=False,
                   help='Remove TLSA-RRs i.e. make them empty.')
                   
parser.add_option('--create-certs', '-C', dest='create', action='store_true',
                   default=False,
                   help='Scan configuration and create all certs, which are not'
                   ' disbled or excluded.'
                   ' State will be "issued" of created certs.')
                   
parser.add_option('--renew-local-certs', '-r', dest='remaining_days', action='store',
                   type=int, default=False,
                   help='Scan configuration for local certs in state deployed'
                   ' which will expire within REMAINING_DAYS days.'
                   ' Include these certs in a --create-certs operation.'
                   ' If combined with "--distribute-certs", do not create certs,'
                   ' but instead distribute certs, which would expire within'
                   ' REMAINING_DAYS days and are issued no longer than'
                   ' REMAINING_DAYS in the past.')
                   
parser.add_option('--distribute-certs', '-D', dest='distribute', action='store_true',
                   default=False,
                   help='Scan configuration and distribute (to their target'
                   ' host) all certs which are in state "issued" and currently'
                   ' valid and not disabled or excluded.'
                   ' Changes state to "deployed".'
                   ' Corresponding TLSA RR are also installed, if not'
                   ' suppressed with --no-TLSA-records-')

parser.add_option('--extract-cert-and-key', '-E', action='store_true', dest='extract',
                   help='Extract certificate and key to work directory.'
                    ' This action may not be combined with other actions.')

parser.add_option('--encrypt-keys', action='store_true', dest='encrypt',
                   help='Encrypt all keys in DB.'
                    'Configuration parameter db_encryption_key must point '
                    'at a file, containing a usable passphrase.')

parser.add_option('--decrypt-keys', action='store_true', dest='decrypt',
                   help='Replace all keys in the DB by their clear text version.'
                    'Configuration parameter db_encryption_key must point '
                    'at a file, containing a usable passphrase.')

parser.add_option('--all', '-a', action='store_true',
                   help='All certs in configuration should be included in operation, even if disabled.')
                   
parser.add_option('--include', '-i', dest='cert_to_be_included', action='append',
                   help='Specify, which cert to be included, even if disabled, in list of certs to be created or distributed. Is cumulative if multiple times provided.')
                   
parser.add_option('--exclude', '-e', dest='cert_to_be_excluded', action='append',
                   help='Specify, which cert to be excluded from list of certs to be created or distributed. Is cumulative if multiple times provided.')
                   
parser.add_option('--only', '-o', dest='only_cert', action='append',
                   help='Specify from which cert(s) the list of certs to be created or distributed. Is cumulative if multiple times provided.')

parser.add_option('--skip-disthost', '-s', dest='skip_host', action='append',
                   help='Specify, which disthosts should not receive distributions. Is cumulative if multiple times provided.')

parser.add_option('--limit-to-disthost', '-l', dest='only_host', action='append',
                   help='Specify, which disthosts should receive distributions only (others are excluded). Is cumulative if multiple times provided.')

parser.add_option('--no-TLSA-records', '-N', dest='no_TLSA', action='store_true',
                   default=False,
                   help='Do not distribute/change TLSA resource records.')

parser.add_option('--check-only', '-n', dest='check_only', action='store_true',
                   default=False,
                   help='Do syntax check of configuration data.'),

parser.add_option('--debug', '-d', action='store_true',
                   default=False,
                   help='Turn on debugging.'),
parser.add_option('--quiet', '-q', action='store_true',
                   default=False,
                   help='Be quiet on command line. Do only logging. (for cron jobs).'),
parser.add_option('--verbose', '-v', dest='verbose', action='store_true',
                   default=False,
                   help='Be more verbose.')

options, args = parser.parse_args()

if options.debug: options.verbose = True



#--------------- logging functions --------------

syslog_initialized = False

LOG_SECURITY = 13 << 3      # FreeBSD  - does not work with python

SLD = syslog.LOG_DEBUG | SYSLOG_FACILITY
SLI = syslog.LOG_INFO | SYSLOG_FACILITY
SLN = syslog.LOG_NOTICE | SYSLOG_FACILITY
SLE = syslog.LOG_ERR | SYSLOG_FACILITY

def sld(msg):
    if not syslog_initialized:
        init_syslog()
    m = '['+msg.expandtabs()+']'
    syslog.syslog(SLD, m)
    if not options.quiet and options.debug: print(m)

def sli(msg):
    if not syslog_initialized:
        init_syslog()
    m = '['+msg.expandtabs()+']'
    syslog.syslog(SLI, m)
    if not options.quiet and options.verbose: print(m)

def sln(msg):
    if not syslog_initialized:
        init_syslog()
    m = '%'+msg.expandtabs()
    syslog.syslog(SLN, m)
    if not options.quiet: print(m)

def sle(msg):
    if not syslog_initialized:
        init_syslog()
    m = '?'+msg.expandtabs()
    syslog.syslog(SLE, m)
    print(m)

def init_syslog():
    global syslog_initialized
    
    syslog.openlog(ident = 'pki', facility = SYSLOG_FACILITY)
    syslog_initialized = True


# --------------- utility functions -------------

def options_set():
    """ 
    options_set - return string of options set on command line
    
    @rtype:      string of option names
    """
    opts_set = ''
    for opt, value in options.__dict__.items():
        if value:
            opts_set += opt
            args = ''
            if isinstance(value,str):
                args += (' ' + value)
            elif isinstance(value,list):
                sep = ''
                for item in value:
                    args += (sep + item)
                    sep = ','
            if len(args) > 1:
                opts_set += ('(' + args + ')')
            
            opts_set += ' '
    return opts_set


def check_actions():
    l = []
    if options.schedule: l.append('schedule')
    if options.distribute: l.append('distribute')
    if options.create: l.append('create')
    if options.sync_disk: l.append('sync_disk')
    if options.sync_tlsas: l.append('sync_tlsas')
    if options.remove_tlsas: l.append('remove_tlsas')
    if options.extract: l.append('extract')
    if options.encrypt: l.append('encrypt-keys')
    if options.decrypt: l.append('decrypt-keys')

    s = set(l)
    
    if len(s) > 2:
        sle('Too many actions. Only 2 actions may be combined')
        sys.exit(1)
    
    if len(s) == 2:
        if 'schedule' in s or 'extract' in s or \
                    'encrypt-keys' in s or 'decrypt-keys' in s:
            sle('"--schedule" or "--extract-cert-and-key" or '
                '"--encrypt-keys" or "--decrypt-keys" may not be combined with'
                ' other actions.')
            sys.exit(1)
        if 'remove_tlsas' in s:
            sle('--remove-TLSAs may not be combined with other actions.')
            sys.exit(1)
        if 'distribute' in s and 'create' in s: return
        elif 'sync_disk' in s and 'sync_tlsas' in s: return       
        else:
            sle('--distribute may only be combined with --create and')
            sle('--consolidate-certs may only be combined with --consolidate-TLSA')
            sys.exit(1)


def shortDateTime(dt):
    return str('{:%Y-%m-%d %H:%M}'.format(dt))

#-------------------------  DNS server functions ----------------------------

zone_cache = {}

def updateZoneCache(zone):
    """
    Remember zone, which was modified for later incrementing of serial
    
    @param zone:        FQDN of zone
    @type zone:         str
    """
    
    global zone_cache
    
    zone_cache[zone] = 1
    

def zone_and_FQDN_from_altnames(cert_meta):
    """
    Retrieve zone and FQDN of TLSA RRs.
    
    @param cert_meta:          certificate meta data
    @type cert_meta:           serverPKI.cert.Certificate
    @rtype:                    List of tuples (may be empty) of strings
    @rtype                     Each tuple contains: zone, FQDN
    @exceptions:
    """
    retval = []
    alt_names = [cert_meta.name, ]
    if len(cert_meta.altnames) > 0:
        alt_names.extend(cert_meta.altnames)
    
    for fqdn in alt_names :
        fqdn_tags = fqdn.split(sep='.')
        for i in range(1, len(fqdn_tags)+1):
            zone = '.'.join(fqdn_tags[-i::])
            if (Pathes.zone_file_root / zone).exists():
                sld('{}'.format(str(Pathes.zone_file_root / zone)))
                retval.append((zone, fqdn))
                break
    return retval

def updateSOAofUpdatedZones():
    """
    Update serial field of SOA of all modified zones.
    serial format must be yyyymmddnn.
    """
    
    global zone_cache
    
    timestamp = datetime.now()
    current_date = timestamp.strftime('%Y%m%d')

    for zone in zone_cache:

        filename = Pathes.zone_file_root / zone / str(zone + '.zone')
        with filename.open('r', encoding="ASCII") as fd:
            try:
                zf = fd.read()
            except:                 # file not found or not readable
                raise MyException("Can't read zone file " + filename)
        old_serial = [line for line in zf.splitlines() if 'Serial number' in line][0]
        sld('Updating SOA: zone file {}'.format(filename))
        sea = re.search('(\d{8})(\d{2})(\s*;\s*)(Serial number)', zf)
        old_date = sea.group(1)
        daily_change = sea.group(2)
        if old_date == current_date:
           daily_change = str('%02d' % (int(daily_change) +1, ))
        else:
            daily_change = '01'
        zf = re.sub('\d{10}', current_date + daily_change, zf, count=1)
        new_serial = [line for line in zf.splitlines() if 'Serial number' in line][0]
        sld('Updating SOA: SOA before and after update:\n{}\n{}'.format(old_serial,new_serial))
        with filename.open('w', encoding="ASCII") as fd:
            try:
                fd.write(zf)
            except:                 # file not found or not readable
                raise MyException("Can't write zone file " + filename)

def reloadNameServer():
    """
    Reload DNS nameserver named, using rndc.
    """

    global zone_cache
    
    if len(zone_cache) > 0:
        try:
             sld('Reloading nameserver')
             subprocess.call(['rndc', '-k', str(Pathes.dns_key),'reload'])
        except subprocess.SubprocessError as e:
             sle('Error while reloading nameserver: \n{}: {}'.format(e.cmd, e.output))
    
    zone_cache = {}
 
 
#---------------  prepared SQL queries for create/update/renew _local_instance  --------------

q_insert_instance = """
    INSERT INTO CertInstances (certificate, state, cert, key, hash, cacert)
        VALUES ($1::INTEGER, 'reserved', '', '', '', 0)
        RETURNING id::int
"""
q_update_instance = """
    UPDATE CertInstances 
        SET state = 'issued',
            cert = $2,
            key = $3, 
            hash = $4,
            cacert = $7,
            not_before = $5::TIMESTAMP,
            not_after = $6::TIMESTAMP
        WHERE id = $1
"""
q_update_state_of_instance = """
    UPDATE CertInstances 
        SET state = $2
        WHERE id = $1
"""


q_names_to_be_renewed = """
    SELECT S.name, I.state, I.not_before, I.not_after
        FROM subjects S, certificates C, certinstances I
        WHERE
            I.state IN ('deployed', 'issued') AND
            I.certificate = c.id AND
            c.type = 'local' AND
            c.disabled = FALSE AND
            S.type != 'CA' AND
            S.certificate = c.id AND
            S.isaltname = FALSE;
"""
q_certs_for_printing_insert = "INSERT INTO print_certs VALUES($1)"

ps_insert_instance = None
ps_update_instance = None
ps_update_state_of_instance = None
ps_names_to_be_renewed = None
ps_certs_for_printing_insert = None

def insert_certinstance(db, certificate_id):
    
    global ps_insert_instance
    
    if not ps_insert_instance:
        db.execute("PREPARE q_insert_instance(integer) AS " + q_insert_instance)
        ps_insert_instance = db.statement_from_id('q_insert_instance')
    certinstance_id = ps_insert_instance.first(
                certificate_id
    )
    return certinstance_id


def update_certinstance(db, certinstance_id, cert_pem, key_pem, TLSA_hash,
                                                    not_before, not_after, cacert_id):
    
    global ps_update_instance

    if not ps_update_instance:
        ps_update_instance = db.prepare(q_update_instance)

    (updates) = ps_update_instance.first(
                certinstance_id,
                cert_pem,
                key_pem,
                TLSA_hash,
                not_before,
                not_after,
                cacert_id
    )
    return updates

def update_state_of_instance(db, certinstance_id, state):
    
    global ps_update_state_of_instance

    if not ps_update_state_of_instance:
        ps_update_state_of_instance = db.prepare(q_update_state_of_instance)

    (updates) = ps_update_state_of_instance.first(
                certinstance_id,
                state,
    )
    return updates


def names_of_local_certs_to_be_renewed(db, days, distribute=False):

    global ps_names_to_be_renewed

    renew_limit = datetime.today() + timedelta(days=days)
    distribute_limit = datetime.today() - timedelta(days=days)
    
    if not ps_names_to_be_renewed:
        ps_names_to_be_renewed = db.prepare(q_names_to_be_renewed)

    deployed_names = {}
    issued_names = {}
    
    rows = ps_names_to_be_renewed.rows()
    for name, state, not_before, not_after in rows:
        if state == 'deployed':
            if name not in deployed_names or deployed_names[name] < not_after:
                deployed_names[name] = not_after
        elif state == 'issued':
            if name not in issued_names or issued_names[name] < not_before:
                issued_names[name] = not_before
    
    names_to_be_issued = []
    for name, not_after in deployed_names.items():
        if not_after < renew_limit:
            names_to_be_issued.append(name)
    if not distribute:
        return names_to_be_issued
    
    names_to_be_deployed = []
    for name in names_to_be_issued:
        if name in issued_names:
            names_to_be_deployed.append(name)
    return names_to_be_deployed
    
    
def print_certs(db, names):

    global ps_certs_for_printing_insert

    pt = PrettyTable()
    pt.field_names = ['Subject', 'Cert Name', 'Type', 'authorized', 'Alt Name', 
                            'TLSA', 'Port', 'Dist Host', 'Jail', 'Place']
    with db.xact('SERIALIZABLE'):
        name_tuple_list = []
        
        pc_create = db.prepare('CREATE TEMP TABLE "print_certs" (name text) ON COMMIT DROP')
        pc_create()
        pc_query = db.prepare('SELECT * FROM certs WHERE "Cert Name" IN (SELECT name FROM "print_certs")')
        
        if not ps_certs_for_printing_insert:
            ps_certs_for_printing_insert = db.prepare(q_certs_for_printing_insert)

        for name in names:
            name_tuple_list.append((name, ))
        ps_certs_for_printing_insert.load_rows(name_tuple_list)
        
        rows = pc_query.rows()
        for row in rows:
            pt.add_row(row)
    
    print(pt) 


 
#---------------  db encrypt/decrypt functions  --------------

db_encryption_key = None
db_encryption_in_use = None

from cryptography.hazmat.primitives.serialization import (
                KeySerializationEncryption, BestAvailableEncryption)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from serverPKI.config import X509atts
from manuale import crypto as manuale_crypto
from pathlib import Path
from cryptography.hazmat.backends import default_backend

def read_db_encryption_key(db):
    """
    Read DB encryption password from disk and checks encryption status of DB
    If password could be read and Revision.keysEncrypted in DB is True, the
    global db_encryption_in_use is set to True and a True is returned.
    
    @param db:          open database connection
    @rtype:             boolean: True if encryption active, False if password
                        file could not be found/read or Revision.keysEncrypted
                        in DB is False
                        
    @exceptions:        none
    """
    global db_encryption_key, db_encryption_in_use
        
    try:
        with Path.open(Pathes.db_encryption_key, 'rb') as f:
            db_encryption_key = f.read()
    except Exception:
        sld('DB Encryption key not available, because {} [{}]'.
            format(
                sys.exc_info()[0].__name__,
                str(sys.exc_info()[1])))
        db_encryption_in_use = False
        return False
    result = get_revision(db)
    (schemaVersion, keysEncrypted) = result
    if keysEncrypted:
        db_encryption_in_use = True
    return True

def encrypt_key(the_binary_cert_key):
    global db_encryption_key, db_encryption_in_use
    
    if not db_encryption_in_use:
        return None
    encryption_type = BestAvailableEncryption(db_encryption_key)
    key_pem = the_binary_cert_key.private_bytes(
                                    Encoding.PEM,
                                    PrivateFormat.TraditionalOpenSSL,
                                    encryption_type)
    return key_pem


def decrypt_key(encrypted_key_bytes):
    global db_encryption_key, db_encryption_in_use
    
    if not db_encryption_in_use:
        return None

    decrypted_key = load_pem_private_key(
                        encrypted_key_bytes,
                        password=db_encryption_key,
                        backend=default_backend())
    key_pem = decrypted_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    return key_pem



q_select_revision = """
SELECT schemaVersion, keysEncrypted FROM Revision WHERE id = 1
"""
q_update_revision = """
UPDATE Revision set schemaVersion=$1, keysEncrypted=$2 WHERE id = 1
"""

q_select_all_keys = """
SELECT id,key FROM CertInstances FOR UPDATE
"""
q_update_key = """
UPDATE CertInstances SET key = $2 WHERE id = $1
"""
q_cacert = """
SELECT s.type
    FROM Subjects s, Certificates c, Certinstances i
    WHERE
        i.id = $1   AND
        i.certificate = c.id  AND
        s.certificate = c.id
"""

ps_select_revision = None
ps_update_revision = None

ps_select_all_keys = None
ps_update_key = None

ps_cacert = None


def get_revision(db):
    global ps_select_revision
    
    if not ps_select_revision:
        ps_select_revision = db.prepare(q_select_revision)
    result = ps_select_revision.first()
    if result:
        (schemaVersion, keysEncrypted) = result
        sld('SchemaVersion of DB is {}; Certkeys are {} encrypted.'.format(
                    schemaVersion, '' if keysEncrypted else 'not'))
        return result
    raise MyException('?Unable to get DB SchemaVersion. Create table revision in DB!')
    return None

def set_revision(db,schemaVersion,keysEncrypted):
    global ps_update_revision
    
    if not ps_update_revision:
        ps_update_revision = db.prepare(q_update_revision)
    (result) = ps_update_revision(schemaVersion,keysEncrypted)
    if result:
        sln('SchemaVersion of DB is now {}; Certkeys are {} encrypted.'.format(
                    schemaVersion, '' if keysEncrypted else 'not'))
    return result

def is_cacert(db,instance_id):
    global ps_cacert
    
    if not ps_cacert:
        ps_cacert = db.prepare(q_cacert)
    (result) = ps_cacert.first(instance_id)
    if result == 'CA':
        sld('Instance {} is CA key: Skipping'.format(instance_id))
        return True
    return False

def encrypt_all_keys(db):
    global db_encryption_in_use, db_encryption_key
    global ps_select_all_keys, ps_update_key

    if not db_encryption_key:
        sle('Needing db_encryption_key to encrypt all keys (see config).')
        return False
    try:
        result = get_revision(db)
    except MyException:
        return False
    (schemaVersion,keysEncrypted) = result
    if keysEncrypted:
        sle('Cert keys are already encrypted.')
        return False
    
    encryption_type = BestAvailableEncryption(db_encryption_key)
        
    with db.xact(isolation='SERIALIZABLE', mode='READ WRITE'):
        if not ps_select_all_keys:
            ps_select_all_keys = db.prepare(q_select_all_keys)
        if not ps_update_key:
            ps_update_key = db.prepare(q_update_key)
            
        for row in ps_select_all_keys():
            id = row['id']
            if is_cacert(db,id):# CA key?
                continue        # yes: do not encrypt it again
            sld('Reading cleartext key from cert instance {}'.format(id))
            key_cleartext = load_pem_private_key(   row['key'],
                                                password=None,
                                                backend=default_backend())
            key_pem = key_cleartext.private_bytes(
                                            Encoding.PEM,
                                            PrivateFormat.TraditionalOpenSSL,
                                            encryption_type)
            (result) = ps_update_key.first(id, key_pem)
            if result != 1:
                raise MyException(
                    '?Failed to write encrypted key into instance {} in DB'.
                                                                    format(id))
        
        db_encryption_in_use = True
        set_revision(db,schemaVersion,True)
    return True
            
def decrypt_all_keys(db):
    global db_encryption_in_use, db_encryption_key
    global ps_select_all_keys, ps_update_key

    if not db_encryption_key:
        sle('Needing db_encryption_key to decrypt all keys (see config).')
        return False
    try:
        result = get_revision(db)
    except MyException:
        return False
    (schemaVersion,keysEncrypted) = result
    if not keysEncrypted:
        sle('Cert keys are already decrypted.')
        return False

    with db.xact(isolation='SERIALIZABLE', mode='READ WRITE'):
        if not ps_select_all_keys:
            ps_select_all_keys = db.prepare(q_select_all_keys)
        if not ps_update_key:
            ps_update_key = db.prepare(q_update_key)
            
        for row in ps_select_all_keys():
            id = row['id']
            if is_cacert(db,id):# CA key?
                continue        # yes: do not try to decrypt it
            sld('Reading encrypted key from cert instance {}'.format(id))
            decrypted_key = load_pem_private_key(
                                row['key'],
                                password=db_encryption_key,
                                backend=default_backend())
            key_pem = decrypted_key.private_bytes(Encoding.PEM,
                                                PrivateFormat.TraditionalOpenSSL,
                                                NoEncryption())
            (result) = ps_update_key.first(id, key_pem)
            if result != 1:
                raise MyException(
                    '?Failed to write decrypted key into instance {} in DB'.
                                                                    format(id))
        
        db_encryption_in_use = False
        set_revision(db,schemaVersion,False)
    return True

