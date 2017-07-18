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
from datetime import datetime
import optparse
import subprocess
import re
import sys
import syslog

from serverPKI.config import Pathes, SSH_CLIENT_USER_NAME, SYSLOG_FACILITY

#--------- globals ***DO WE NEED THIS?*** ----------

global options

#--------------- command line options --------------

parser = optparse.OptionParser(description='Certificate Authority operations')
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

    s = set(l)
    
    if len(s) > 2:
        sle('Too many actions. Only 2 actions may be combined')
        sys.exit(1)
    
    if len(s) == 2:
        if 'schedule' in s or 'extract' in s:
            sle('--schedule or --extract-cert-and-key may not be combined with'
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
