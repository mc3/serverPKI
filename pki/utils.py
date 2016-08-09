"""
utility module of serverPKI
"""
#--------------- imported modules --------------
from datetime import datetime
import optparse
import subprocess
import re
import syslog

from pki.config import Pathes, SSH_CLIENT_USER_NAME

#--------- globals ***DO WE NEED THIS?*** ----------

global options

#--------------- command line options --------------

parser = optparse.OptionParser(description='Certificate Authority operations')
parser.add_option('--schedule-actions', '-S', dest='schedule', action='store_true',
                   default=False,
                   help='Scan configuration and schedule necessary actions of'
                    ' selected certs/hosts. This may trigger issuence or '
                    ' distribution of certs. With this options "--create" and'
                    ' "--distribute" are ignored')
                   
parser.add_option('--create-certs', '-C', dest='create', action='store_true',
                   default=False,
                   help='Scan configuration and create all certs, which are not disbled or excluded.')
                   
parser.add_option('--distribute-certs', '-D', dest='distribute', action='store_true',
                   default=False,
                   help='Scan configuration and distribute (to their target host) all certs which have been created now or in the past, which are not disbled or excluded.')

parser.add_option('--all', '-a', action='store_true',
                   help='All certs in configuration should be included, even if disabled.')
                   
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
                   help='Do not distribute TLSA resource records.')

parser.add_option('--check-configuration-only', '-n', dest='check_only', action='store_true',
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

SLD = syslog.LOG_DEBUG | syslog.LOG_LPR
SLI = syslog.LOG_INFO | syslog.LOG_LPR
SLN = syslog.LOG_NOTICE | syslog.LOG_LPR
SLE = syslog.LOG_ERR | syslog.LOG_LPR

def sld(msg):
    if not syslog_initialized:
        init_syslog()
    m = '['+msg+']'
    syslog.syslog(SLD, m)
    if not options.quiet and options.debug: print(m)

def sli(msg):
    if not syslog_initialized:
        init_syslog()
    m = '['+msg+']'
    syslog.syslog(SLI, m)
    if not options.quiet and options.verbose: print(m)

def sln(msg):
    if not syslog_initialized:
        init_syslog()
    m = '%'+msg
    syslog.syslog(SLN, m)
    if not options.quiet: print(m)

def sle(msg):
    if not syslog_initialized:
        init_syslog()
    m = '?'+msg
    syslog.syslog(SLE, m)
    print(m)

def init_syslog():
    global syslog_initialized
    
    syslog.openlog(ident = 'pki', facility = syslog.LOG_LPR)
    syslog_initialized = True


# --------------- utility functions -------------

def options_set():
    """ options_set - return string of options set on command line
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


def shortDateTime(dt):
    return str('{:%Y-%m-%d %H:%M}'.format(dt))

#-------------------------  DNS server functions ----------------------------

zone_cache = {}

def updateZoneCache(zone):
    
    global zone_cache
    
    zone_cache[zone] = 1
    

def zone_and_FQDN_from_altnames(cert_meta):
    """
    Retrieve zone and FQDN of TLSA RRs.
    
    @param cert_meta:          certificate meta data
    @type cert_meta:           pki.cert.Certificate
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

    global zone_cache
    
    if len(zone_cache) > 0:
        try:
             sld('Reloading nameserver')
             subprocess.call(['rndc', '-k', str(Pathes.dns_key),'reload'])
        except subprocess.SubprocessError as e:
             sle('Error while reloading nameserver: \n{}: {}'.format(e.cmd, e.output))
    
    zone_cache = {}
 
 
#---------------  prepared SQL queries for create/update _local_instance  --------------

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
            cacert = $1,
            not_before = $5::TIMESTAMP,
            not_after = $6::TIMESTAMP
        WHERE id = $1
"""
q_update_state_of_instance = """
    UPDATE CertInstances 
        SET state = $2
        WHERE id = $1
"""

ps_insert_instance = None
ps_update_instance = None
ps_update_state_of_instance = None

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
                                                    not_before, not_after):
    
    global ps_update_instance

    if not ps_update_instance:
        ps_update_instance = db.prepare(q_update_instance)

    (updates) = ps_update_instance.first(
                certinstance_id,
                cert_pem,
                key_pem,
                TLSA_hash,
                not_before,
                not_after
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
