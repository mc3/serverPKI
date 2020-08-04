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

# utility module of serverPKI (commandline parsing, logging ...)


# --------------- imported modules --------------
from datetime import datetime, timedelta
from typing import List, Tuple, Optional
import io
import optparse
import subprocess
import os
import re
import sys
import syslog
from prettytable import PrettyTable

import configobj, validate

from cryptography.hazmat.primitives.serialization import (
    KeySerializationEncryption, BestAvailableEncryption)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.backends import default_backend
from dns import update, tsigkeyring, tsig
from pathlib import Path
from postgresql import driver as db_conn

from serverPKI import get_version, get_schema_version

# -------------- config spec -------------

configspec = """
[Pathes]

    # this path should be customized:
    home = string()
    
    # some flat files not in RDBMS
    db = string()
    
    # local CA cert
    ca_cert = string()
    ca_key = string()
    
    # encryption of keys in db
    db_encryption_key = string()
    
    # lets encrypt
    le_account = string()
    
    work = string()
    work_tlsa = string()
    
    # DNS server for maintaining TLSA RR (empty = on local host)
    tlsa_dns_master = string()
    
    
    
    # Used for maintenance of TLSA RR and ACME challenges by zone file
    # editing (historical)
    # required convention = zone_file_root/example.com/example.com.zone
    
    zone_file_root = string()
    
    # key for rndc command
    dns_key = string()
    
    # mode + owner of *.tlsa and acme_challenges.inc files in zone directory
    # in octal notation
    zone_tlsa_inc_mode = string(default='0660')
    
    # owner and group of files. included by zone files
    zone_tlsa_inc_uid =   integer(default=53)
    zone_tlsa_inc_gid = integer()
    
    # filename for challenges to be included by zone file:
    zone_file_include_name = string()
    
    # location of key for signing dynamic DNS commands
    ddns_key_file = string()
    
    
# Defaults of local X509 certificate standard attributes
[X509atts]
    
    lifetime = integer()
    bits = integer()

    # Definition of fixed X.509 cert attributes
    [[names]]
    
        C = string(min=2,max=2)
        L = string()
        O = string()-RAU
        CN = string()
    
    [[extensions]]
       

[DBAccount]

    dbHost =         string()
    dbPort =         integer(min=1,max=64000)
    dbUser =         string()
    dbDbaUser =      string()
    dbSslRequired =  boolean()
    
    dbDatabase =     string()
    dbSearchPath =   list()
    dbCert =         string()
    dbCertKey =      string()

[Misc]

    SSH_CLIENT_USER_NAME = string()
    
    LE_SERVER = string()
    
    # e-mail for registration
    LE_EMAIL = string()
    
    # zone update method for challenge ('ddns' or 'zone_file')
    LE_ZONE_UPDATE_METHOD = option('ddns', 'zone_file')
    
    # Key size and lifetime of local CA cert
    LOCAL_CA_BITS = integer(min=3096,max=4096)
    LOCAL_CA_LIFETIME = integer(min=365)
    
    # subjects in table Subjects for CA certs
    # to be changed only before creating DB
    SUBJECT_LOCAL_CA = string()
    SUBJECT_LE_CA = string()
    
    # number of days to publish new certs before deploying it
    PRE_PUBLISH_TIMEDELTA = integer(min=7)
    
    # number of days to send remainder before expiration of local certs
    LOCAL_ISSUE_MAIL_TIMEDELTA = integer(min=1)
    
    # details for sending reminder mails
    MAIL_RELAY = string()
    MAIL_SUBJECT = string()
    MAIL_SENDER = string()
    MAIL_RECIPIENT = list()
    
    SYSLOG_FACILITY = string()
"""


# container Classes, filled by parse_config

class Pathes(object):
    pass


class X509atts(object):
    pass


class DBAccount(object):
    pass


class Misc(object):
    SYSLOG_FACILITY = syslog.LOG_LOCAL6  # FIXME: ugly hack to allow logging during config parsing

# --------- init module -----------
def init_module_utils():

    global options
    options = None

    global ps_names_to_be_renewed
    ps_names_to_be_renewed = None
    global ps_certs_for_printing_insert
    ps_certs_for_printing_insert = None


# --------- globals ***DO WE NEED THIS?*** ----------

##global options, db_encryption_key

options = None


class MyException(Exception):
    pass


def get_name_string():
    v = get_version()
    n = DBAccount.dbDatabase  # FIXME not yet initialized
    return '{}-{}'.format(n, v)


def get_version_string():
    return get_version()


# --------------- command line options --------------
##import pdb; pdb.set_trace()

def parse_options():
    """
    Parse commandline options
    :return:
    """
    global options

    parser = optparse.OptionParser(description='Server PKI {}'.format(get_version_string()))
    group = optparse.OptionGroup(parser, "Actions to issue and replace certificates.")

    group.add_option('--create-certs', '-C', dest='create', action='store_true',
                     default=False,
                     help='Scan configuration and create all certs, which are not'
                          ' disabled or excluded.'
                          ' State will be "issued" of created certs.'
                          ' Action modifiers may be used to select a subset of certs to act on.')

    group.add_option('--renew-local-certs', '-r', dest='remaining_days', action='store',
                     type=int, default=False,
                     help='Scan configuration for local certs in state deployed'
                          ' which will expire within REMAINING_DAYS days.'
                          ' Include these certs in a --create-certs operation.'
                          ' If combined with "--distribute-certs", do not create certs,'
                          ' but instead distribute certs, which would expire within'
                          ' REMAINING_DAYS days and are issued no longer than'
                          ' REMAINING_DAYS in the past.')

    group.add_option('--schedule-actions', '-S', dest='schedule', action='store_true',
                     default=False,
                     help='Scan configuration and schedule necessary actions of'
                          ' selected certs/hosts. This may trigger issuence or '
                          ' distribution of certs/TLSA-RRS. With this options "--create-certs" and'
                          ' "--distribute-certs" are ignored. Any state transitions may happen')

    parser.add_option_group(group)

    group = optparse.OptionGroup(parser, 'Actions to deploy or export certificates and'
                                         ' deploy or delete DNS TLSA resource records.')

    group.add_option('--distribute-certs', '-D', dest='distribute', action='store_true',
                     default=False,
                     help='Scan configuration and distribute (to their target'
                          ' host) all certs which are in state "issued" and currently'
                          ' valid and not disabled or excluded.'
                          ' Changes state to "deployed".'
                          ' Corresponding TLSA RR are also installed, if not'
                          ' suppressed with --no-TLSA-records-')

    group.add_option('--consolidate-certs', '-K', dest='sync_disk', action='store_true',
                     default=False,
                     help='Consolidate targets to be in sync with DB.'
                          ' This affects certs in state "deployed" '
                          ' and effectively re-distributes certs.')

    group.add_option('--consolidate-TLSAs', '-T', dest='sync_tlsas', action='store_true',
                     default=False,
                     help='Consolidate TLSA-RR to be in sync with DB.'
                          ' This affects certs in state "deployed" or "prepublished".')

    group.add_option('--remove-TLSAs', '-R', dest='remove_tlsas', action='store_true',
                     default=False,
                     help='Remove TLSA-RRs i.e. make them empty.')

    group.add_option('--export-cert-and-key', '-E', dest='cert_serial',
                     action='store', type=int, default=False,
                     help='Export certificate and key with CERT_SERIAL to work directory.'
                          ' CERT_SERIAL may be obtained from DB (column "id" with command'
                          ' operate_serverPKI -n -v)'
                          ' This action may not be combined with other actions.')

    parser.add_option_group(group)

    group = optparse.OptionGroup(parser, 'Action modifiers, to select certificates or disthosts to act on.')

    group.add_option('--all', '-a', action='store_true',
                     help='All certs in configuration should be included in operation, even if disabled.')

    group.add_option('--include', '-i', dest='cert_to_be_included', action='append',
                     help='Specify, which cert to be included, even if disabled, in list of certs to be created or distributed. Is cumulative if multiple times provided.')

    group.add_option('--exclude', '-e', dest='cert_to_be_excluded', action='append',
                     help='Specify, which cert to be excluded from list of certs to be created or distributed. Is cumulative if multiple times provided.')

    group.add_option('--only', '-o', dest='only_cert', action='append',
                     help='Specify from which cert(s) the list of certs to be created or distributed. Is cumulative if multiple times provided.')

    group.add_option('--skip-disthost', '-s', dest='skip_host', action='append',
                     help='Specify, which disthosts should not receive distributions. Is cumulative if multiple times provided.')

    group.add_option('--limit-to-disthost', '-l', dest='only_host', action='append',
                     help='Specify, which disthosts should receive distributions only (others are excluded). Is cumulative if multiple times provided.')

    group.add_option('--no-TLSA-records', '-N', dest='no_TLSA', action='store_true',
                     default=False,
                     help='Do not distribute/change TLSA resource records.')

    parser.add_option_group(group)

    group = optparse.OptionGroup(parser, 'Maintenance and administrative actions.')

    group.add_option('--encrypt-keys', '-X', action='store_true', dest='encrypt',
                     help='Encrypt all keys in DB.'
                          'Configuration parameter db_encryption_key must point '
                          'at a file, containing a usable passphrase.')

    group.add_option('--decrypt-keys', '-Y', action='store_true', dest='decrypt',
                     help='Replace all keys in the DB by their clear text version.'
                          'Configuration parameter db_encryption_key must point '
                          'at a file, containing a usable passphrase.')

    group.add_option('--issue-local-CAcert', '-I', dest='issue_local_cacert', action='store_true',
                     default=False,
                     help='Issue a new local CA cert, used for issuing future '
                          'local server/client certs.')

    group.add_option('--register', '-Z', dest='register', action='store_true',
                     help='Register a new account at LetsEncrypt,'
                          ' This action may not be combined with other actions.')

    group.add_option('--check-only', '-n', dest='check_only', action='store_true',
                     default=False,
                     help='Do syntax check of configuration data. Produce a '
                          'listing of cert meta and related cert instances if combined '
                          'with  --verbose. Listed certs may be selected with --only.'),

    group.add_option('--debug', '-d', action='store_true',
                     default=False,
                     help='Turn on debugging.'),
    group.add_option('--quiet', '-q', action='store_true',
                     default=False,
                     help='Be quiet on command line. Do only logging. (for cron jobs).'),
    group.add_option('--verbose', '-v', dest='verbose', action='store_true',
                     default=False,
                     help='Be more verbose.')

    group.add_option('--config_file', '-f', dest='config_file', action='store',
                     type='string',
                     help='Path of an alternate configuration file.')

    parser.add_option_group(group)

    (options, args) = parser.parse_args()
    if options.debug:
        options.verbose = True
    return options


def get_options() -> dict:
    """
    Return dict of command line options.
    Importing the global does not always work
    :return: options
    """

    return options


# --------------- logging functions --------------

syslog_initialized = False

LOG_SECURITY = 13 << 3  # FreeBSD  - does not work with python

SLD = syslog.LOG_DEBUG | Misc.SYSLOG_FACILITY
SLI = syslog.LOG_INFO | Misc.SYSLOG_FACILITY
SLN = syslog.LOG_NOTICE | Misc.SYSLOG_FACILITY
SLE = syslog.LOG_ERR | Misc.SYSLOG_FACILITY


def sld(msg: str) -> None:
    """
    Log a debug message
    :param msg: text to log, will be logged as "[text]"
    :return:
    """
    if not syslog_initialized:
        init_syslog()
    m = '[' + msg.expandtabs() + ']'
    syslog.syslog(SLD, m)
    if not options.quiet and options.debug: print(m)


def sli(msg: str) -> None:
    """
    Log an informal message
    :param msg: text to log, will be logged as "[text]"
    :return:
    """
    if not syslog_initialized:
        init_syslog()
    m = '[' + msg.expandtabs() + ']'
    syslog.syslog(SLI, m)
    if not options.quiet and options.verbose: print(m)


def sln(msg: str) -> None:
    """
    Log a warning (=notice) message
    :param msg: text to log, will be logged as "%text"
    :return:
    """
    if not syslog_initialized:
        init_syslog()
    m = '%' + msg.expandtabs()
    syslog.syslog(SLN, m)
    if not options.quiet: print(m)


def sle(msg: str) -> None:
    """
    Log an error message
    :param msg: text to log, will be logged as "?text"
    :return:
    """
    if not syslog_initialized:
        init_syslog()
    m = '?' + msg.expandtabs()
    syslog.syslog(SLE, m)
    print(m)


def init_syslog():
    global syslog_initialized

    syslog.openlog(ident='{}'.format(get_version_string()),
                   facility=Misc.SYSLOG_FACILITY)
    syslog_initialized = True


def re_init_syslog():  # after parsing config, we have DB name
    global syslog_initialized

    syslog.closelog()
    syslog.openlog(ident='{}'.format(get_name_string()),  # FIXME openlog wants int as ident
                   facility=Misc.SYSLOG_FACILITY)
    syslog_initialized = True


# ------------------ configuration file parsing ---------------
def parse_config(test_config=None):
    """
    Parse config file. Exits on error.
    :return:
    """

    def dict_to_class(the_class: str, section: str, list: Tuple):
        """
        Set class attributes from parsed config data
        :param the_class: Name of class
        :param section: Name of config section
        :param list: list of section keywords
        :return:
        """
        for item in list:
            setattr(globals()[the_class], item, config[section][item])

    the_config_spec = configobj.ConfigObj(io.StringIO(initial_value=configspec, newline='\n'),
                                          _inspec=True,
                                          encoding='UTF8')

    config = None
    for config_file in (test_config,
                        options.config_file,
                        sys.prefix + '/etc/serverpki.conf',
                        '/usr/local/etc/serverPKI/serverpki.conf'):
        if not config_file:
            continue
        sld('Trying config file {}'.format(config_file))
        if not os.path.isfile(config_file):
            continue
        sli('Using config file {}'.format(config_file))
        try:
            config = configobj.ConfigObj(config_file,
                                         encoding='UTF8',
                                         interpolation='Template',
                                         configspec=the_config_spec)
        except SyntaxError as e:
            sle('Configuration file errors found. Can''t continue. List of errors:')
            for err in e.errors:
                sle('{}'.format(err))
            sys.exit(1)
        break
    if not config:
        sle('No config file found. Can''t continue.')
        sys.exit(1)

    try:
        vtor = validate.Validator()
        result = config.validate(vtor, preserve_errors=True)
    except configobj.MissingInterpolationOption as e:
        sle('Substitution error: {}. Can''t continue.'.format(e.msg))
        sys.exit(1)
    if result != True:
        sle('Config validation failed:')
        for entry in configobj.flatten_errors(config, result):
            # each entry is a tuple
            section_list, key, error = entry
            if key is not None:
                section_list.append(key)
            else:
                section_list.append('[missing section]')
            section_string = ', '.join(section_list)
            if error == False:
                error = 'Missing value or section.'
            sle(section_string + ' = ' + str(error))

        for sections, name in configobj.get_extra_values(config):

            # this code gets the extra values themselves
            the_section = config
            for section in sections:
                the_section = the_section[section]

            # the_value may be a section or a value
            the_value = the_section[name]

            section_or_value = 'value'
            if isinstance(the_value, dict):
                # Sections are subclasses of dict
                section_or_value = 'section'

            section_string = ', '.join(sections) or "top level"
            print('Extra entry in section: %s. Entry %r is a %s' % (
                section_string, name, section_or_value))

        sld(str(result))

    def test_walk(section, key):
        sld('{}[{}] {} = {}'.format('[' + section.parent.name + ']' if section.parent.name else '',
                                    section.name,
                                    key,
                                    section[key]))

    config.walk(test_walk)

    def add_attribute_to_class(section: configobj, key: str):
        """
        If called by config.walk, filles corresponding container class with class variable
        :param section: The section
        :param key: The key of attribute
        :return:
        """

        def flatten_list(value: List) -> str:
            """
            Make string from list
            :param value: list
            :return:
            """
            result = ''
            first = True
            for e in value:
                if not first:
                    result += ', '
                first = False
                result += e
            return result

        value = section[key]
        if section.name == 'Pathes' and key == 'zone_tlsa_inc_mode':
            value = int(value, 8)  # file permission is octal
        elif (section.name == 'Misc' and key == 'MAIL_RECIPIENT') or (
                section.name == 'DBAccount' and key == 'dbSearchPath'):
            result = ''
            first = True
            for e in value:
                if not first:
                    result += ', '
                first = False
                result += e
            value = result

        if not section.parent.name:
            setattr(globals()[section.name], key, value)
        else:
            try:
                d = getattr(globals()[section.parent.name], section.name)
            except AttributeError:
                d = {}
                setattr(globals()[section.parent.name], section.name, d)
            d[key] = value

    config.walk(add_attribute_to_class)

    ## re_init_syslog() FIXME: openlog works only once

    sld(DBAccount.dbHost + ' ' + str(DBAccount.dbPort) + ' ' + DBAccount.dbUser + ' ' + DBAccount.dbCert)
    return


def get_config() -> Tuple[Pathes, X509atts, DBAccount, Misc]:
    """
    Return tuple of 4 container classes, which contain config parameters
    :return:
    """
    pathes = Pathes()
    x509atts = X509atts()
    dbaccount = DBAccount()
    misc = Misc()

    return (dbaccount, misc, pathes, x509atts)


# --------------- utility functions -------------

def options_set() -> str:
    """
    return string of options set on command line
    :return: string of option names
    """
    opts_set = ''
    for opt, value in options.__dict__.items():
        if value:
            opts_set += opt
            args = ''
            if isinstance(value, str):
                args += (' ' + value)
            elif isinstance(value, list):
                sep = ''
                for item in value:
                    args += (sep + item)
                    sep = ','
            if len(args) > 1:
                opts_set += ('(' + args + ')')

            opts_set += ' '
    return opts_set


def check_actions() -> None:
    """
    Check consistency of command line options.
    May issue error message and terminate program
    :return:
    """
    options = get_options()

    l = []
    if options.create: l.append('create')
    if options.decrypt: l.append('decrypt-keys')
    if options.distribute: l.append('distribute')
    if options.encrypt: l.append('encrypt-keys')
    if options.cert_serial: l.append('extract')
    if options.issue_local_cacert: l.append('issue-local-CAcert')
    if options.register: l.append('register')
    if options.remove_tlsas: l.append('remove_tlsas')
    if options.remaining_days: l.append('renew-local-certs')
    if options.schedule: l.append('schedule')
    if options.sync_disk: l.append('sync_disk')
    if options.sync_tlsas: l.append('sync_tlsas')

    s = set(l)

    if len(s) > 2:
        sle('Too many actions. Only 2 actions may be combined')
        sys.exit(1)

    if len(s) == 2:
        if 'schedule' in s or 'extract' in s or 'issue-local-CAcert' in s or \
                'encrypt-keys' in s or 'decrypt-keys' in s or 'register' in s:
            sle('"--schedule" or "--extract-cert-and-key" or '
                '"--encrypt-keys" or "--decrypt-keys" or '
                '"--issue-local-CAcert" or "--register" may not be combined with'
                ' other actions.')
            sys.exit(1)
        if 'issue-local-CAcert' in s:
            sle('--issue-local-CAcert may not be combined with other actions.')
            sys.exit(1)
        if 'remove_tlsas' in s:
            sle('--remove-TLSAs may not be combined with other actions.')
            sys.exit(1)
        if 'distribute' in s and ('create' in s or 'renew-local-certs' in s):
            return
        elif 'sync_disk' in s and 'sync_tlsas' in s:
            return
        else:
            sle('--distribute may only be combined with --create and')
            sle('--consolidate-certs may only be combined with --consolidate-TLSA')
            sys.exit(1)


def shortDateTime(dt: datetime) -> str:
    """
    Return a string like '2020-05-24 12:15' from a datetime object.
    :param dt: datetime.datetime
    :return: str
    """
    return str('{:%Y-%m-%d %H:%M}'.format(dt))


# -------------------------  DNS server functions (now mostly obsoleted by ddns) ----------------------------

zone_cache: dict = {}


def updateZoneCache(zone: str) -> None:
    """
    Add zone to zone cache for later updating of SOA serial if handling DNS via zone files
    :param zone: name of zone (fqdn of domain)
    :return:
    """

    global zone_cache

    zone_cache[zone] = 1


def updateSOAofUpdatedZones() -> None:
    """
    Update serial field of SOA of all modified zones and reloading them.
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
            except:  # file not found or not readable
                raise MyException("Can't read zone file " + filename)
        old_serial = [line for line in zf.splitlines() if 'Serial number' in line][0]
        sld('Updating SOA: zone file {}'.format(filename))
        sea = re.search('(\d{8})(\d{2})(\s*;\s*)(Serial number)', zf)
        old_date = sea.group(1)
        daily_change = sea.group(2)
        if old_date == current_date:
            daily_change = str('%02d' % (int(daily_change) + 1,))
        else:
            daily_change = '01'
        zf = re.sub('\d{10}', current_date + daily_change, zf, count=1)
        new_serial = [line for line in zf.splitlines() if 'Serial number' in line][0]
        sld('Updating SOA: SOA before and after update:\n{}\n{}'.format(old_serial, new_serial))
        with filename.open('w', encoding="ASCII") as fd:
            try:
                fd.write(zf)
            except:  # file not found or not readable
                raise MyException("Can't write zone file " + filename)
        try:
            sld('Reloading zone {}'.format(zone))
            subprocess.call(['rndc', '-k', str(Pathes.dns_key), 'reload', zone])
        except subprocess.SubprocessError as e:
            sle('Error while reloading zone {}: \n{}: {}'.format(zone, e.cmd, e.output))

    zone_cache = {}


q_certs_for_printing_insert = "INSERT INTO print_certs VALUES($1)"

ps_names_to_be_renewed = None
ps_certs_for_printing_insert = None

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


def names_of_local_certs_to_be_renewed(db: db_conn, days: int, distribute=False):
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


def print_certs(db: db_conn, names) -> None:
    """
    Print list of certificates in nice formatting
    :param db: opened DB connection
    :param names: Names of certificates to print
    :return:
    """
    global ps_certs_for_printing_insert

    pt = PrettyTable()
    pt.field_names = ['Subject', 'Cert Name', 'Type', 'Algo', 'OCSP m st', 'authorized', 'Alt Name',
                      'TLSA', 'Port', 'Dist Host', 'Jail', 'Place']
    with db.xact('SERIALIZABLE'):
        name_tuple_list = []

        pc_create = db.prepare('CREATE TEMP TABLE "print_certs" (name text) ON COMMIT DROP')
        pc_create()
        pc_query = db.prepare('SELECT * FROM certs WHERE "Cert Name" IN (SELECT name FROM "print_certs")')

        if not ps_certs_for_printing_insert:
            ps_certs_for_printing_insert = db.prepare(q_certs_for_printing_insert)

        for name in names:
            name_tuple_list.append((name,))
        ps_certs_for_printing_insert.load_rows(name_tuple_list)

        rows = pc_query.rows()
        for row in rows:
            pt.add_row(row)

        print(pt)
        print()

        pt = PrettyTable()
        pt.field_names = ['Serial', 'Cert Name', 'Type', 'State', 'CI CA', 'OCSP m st', 'not before', 'not after',
                          'ALGO', 'Hash', 'updated']

        pc_query = db.prepare('SELECT * FROM inst WHERE "name" IN (SELECT name FROM "print_certs")')

        rows = pc_query.rows()
        for row in rows:
            pt.add_row(row)

    print(pt)


def print_order(order):
    try:
        return ('\turi: {}\n\ttype: {}\n\tcertificate_uri: {}\n\tcontents: {}'.
            format(order.uri, order.type, order.certificate_uri, order.contents))
    except AttributeError:
        return str(order)



# ----------- dynamic DNS update setup ---------------

ddns_keyring: tsigkeyring = None


def _get_ddns_keyring() -> tsigkeyring:
    """
    Read ddns key and return a key ring for dynamic DNS update
    :return: tsigkeyring
    """
    global ddns_keyring
    if ddns_keyring:
        return ddns_keyring

    key_name = secret = ''
    with open(Pathes.ddns_key_file) as kf:
        for line in kf:
            key_name_match = re.search(r'key\s+"([-a-zA-Z]+)"', line, re.ASCII)
            if key_name_match: key_name = key_name_match.group(1)
            secret_match = re.search(r'secret\s+"([=/a-zA-Z0-9]+)"', line, re.ASCII)
            if secret_match: secret = secret_match.group(1)
    if not (key_name and secret):
        raise Exception('Can''t parse ddns key file: {}{}'.
                        format('Bad key name ' if not key_name_match else '',
                               'Bad secret' if not secret_match else ''))
    else:
        ddns_keyring = tsigkeyring.from_text({key_name: secret})
        return ddns_keyring


def ddns_update(zone: str) -> update.Update:
    """
    Obtain a dynamic DNS update instance
    :param zone: name of to update
    :return: dns.update.Update instance
    """

    ddns_keyring = _get_ddns_keyring()

    return update.Update(zone,
                         keyring=ddns_keyring,
                         keyalgorithm=tsig.HMAC_SHA256)
