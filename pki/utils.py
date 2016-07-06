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
parser.add_option('--verbose', '-v', dest='verbose', action='store_true',
                   default=False,
                   help='Be more verbose.')

options, args = parser.parse_args()

if options.debug: options.verbose = True


#--------------- imported modules --------------

import syslog

#--------------- logging functions --------------

syslog_initialized = False

SLI = syslog.LOG_INFO | syslog.LOG_MAIL
SLN = syslog.LOG_NOTICE | syslog.LOG_MAIL
SLE = syslog.LOG_ERR | syslog.LOG_MAIL

def sli(msg):
    if not syslog_initialized:
        init_syslog()
    syslog.syslog(SLI, '['+msg+']')

def sle(msg):
    if not syslog_initialized:
        init_syslog()
    syslog.syslog(SLE, '?'+msg)

def sln(msg):
    if not syslog_initialized:
        init_syslog()
    syslog.syslog(SLN, '%'+msg)

def init_syslog():
    global syslog_initialized
    
    syslog.openlog(ident = 'pki', facility = syslog.LOG_LOCAL6)
    syslog_initialized = True
