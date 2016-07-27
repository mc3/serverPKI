"""
utility module of CA
"""
#--------------- imported modules --------------
import optparse

global options

#--------------- command line options --------------

parser = optparse.OptionParser(description='Certificate Authority operations')
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


#--------------- imported modules --------------

import syslog

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
    if not options.quiet and (options.debug or options.verbose): print(m)

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


#---------------  prepared SQL queries for create/update _local_instance  --------------

q_insert_instance = """
    INSERT INTO CertInstances (certificate, state, cert, key, TLSA)
        VALUES ($1::INTEGER, 'reserved', '', '', '')
        RETURNING id::int
"""
q_update_instance = """
    UPDATE CertInstances 
        SET state = 'issued',
            cert = $2,
            key = $3, 
            TLSA = $4,
            not_before = CURRENT_DATE::DATE,
            not_after = $5::DATE
        WHERE id = $1
"""
q_update_state_of_instance = """
    UPDATE CertInstances 
        SET state = $2,
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
    (certinstance_id) = ps_insert_instance.first(
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
                tlsa_hash,
                not_before,
                not_after
    )

def update_certinstance(db, certinstance_id, state):
    
    global ps_update_state_of_instance

    if not ps_update_state_of_instance:
        ps_update_state_of_instance = db.prepare(q_update_state_of_instance)

    (updates) = ps_update_state_of_instance.first(
                certinstance_id,
                state,
    )
