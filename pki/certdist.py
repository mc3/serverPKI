# -*- coding: utf-8 -*


"""
Certificate distribution module.
"""

import sys
from datetime import datetime
from io import StringIO
from pathlib import PurePath, Path
from os.path import expanduser
from os import chdir
import subprocess
from shutil import copy2
import re
from time import sleep

from paramiko import SSHClient, HostKeys, AutoAddPolicy

from pki.config import Pathes, SSH_CLIENT_USER_NAME
from pki.utils import options as opts
from pki.utils import sld, sli, sln, sle

TLSA_zone_cache = {}

class MyException(Exception):
    pass

def deployCerts(certs):

    """
    Deploy a list of (certificate. key and TLSA file, using sftp).
    Restart service at target host and reload nameserver.
    
    @param certs:       list of certificate meta data instances
    @type certs:        pki.cert.Certificate instance
    @rtype:             bool, false if error found
    @exceptions:
    Some exceptions (to be replaced by error messages and false return)
    """

    error_found = False
        
    limit_hosts = False
    only_host = []
    if opts.only_host: only_host = opts.only_host
    if len(only_host) > 0: limit_hosts = True
    
    skip_host = []
    if opts.skip_host: skip_host = opts.skip_host
    
    sld('limit_hosts={}, only_host={}, skip_host={}'.format(
                                            limit_hosts, only_host, skip_host))
    
    for cert in certs.values():
         
        if len(cert.disthosts) == 0: continue
        
        (cert_text,key_text,TLSA_text, cacert_text) = cert.instance()
        if not cert_text:
            sle('No valid cerificate for {} in DB - create it first'.format(
                                                                    cert.name))
            raise MyException('No valid cerificate for {} in DB - '
                                            'create it first'.format(cert.name))
        cert_plus_cacert_text = cert_text + cacert_text
        key_plus_cert_text = key_text + cert_text

        for fqdn,dh in cert.disthosts.items():
        
            if fqdn in skip_host: continue
            if limit_hosts and fqdn not in only_host: continue
        
            dest_path = PurePath('/')
            
            sld('{}: {}'.format(cert.name, fqdn))
            
            for jail in ( dh['jails'].keys() or ('',) ):   # jail is empty if no jails
            
                jailroot = dh['jailroot'] if jail != '' else '' # may also be empty
                dest_path = PurePath('/', jailroot, jail)
                sld('{}: {}: {}'.format(cert.name, fqdn, dest_path))                
    
                if not dh['places']:
                    sle('{} subject has no place attribute.'.format(cert.name))
                    error_found = True
                    return False
                    
                for place in dh['places'].values():
                
                    sld('Handling jail "{}" and place {}'.format(jail, place.name))
                                   
                    fd_key = StringIO(key_text)
                    fd_cert = StringIO(cert_text)
                
                    key_file_name = key_name(cert.name, cert.subject_type)
                    cert_file_name = cert_name(cert.name, cert.subject_type)
                    dest_dir = PurePath(dest_path, place.cert_path)
                
                    if place.key_path:
                        dest_dir = PurePath(dest_path, place.key_path)
                        distribute_cert(fd_key, fqdn, dest_dir, key_file_name, place, None)
                    
                    elif place.cert_file_type == 'separate':
                        distribute_cert(fd_key, fqdn, dest_dir, key_file_name, place, None)
                    
                    elif place.cert_file_type == 'combined':
                        cert_file_name = key_cert_name(cert.name, cert.subject_type)
                        fd_cert = StringIO(key_text + cert_text)
                
                    elif place.cert_file_type == 'combined cacert':
                        cert_file_name = cert_cacert_name(cert.name, cert.subject_type)
                        fd_cert = StringIO(key_text + cert_text + cacert_text)
                    
                    distribute_cert(fd_cert, fqdn, dest_dir, cert_file_name, place, jail)
            
        sli('')
        if not opts.no_TLSA:
            distribute_tlsa_rrs(cert, TLSA_text)
        
    updateSOAofUpdatedZones()
    reloadNameServer()
    return not error_found


def ssh_connection(dest_host):

    """
    Open a ssh connection.
    
    @param dest_host:   fqdn of target host
    @type dest_host:    string
    @rtype:             paramiko.SSHClient (connected transport)
    @exceptions:
    If unable to connect
    """

    client = SSHClient()
    client.load_host_keys(expanduser('~/.ssh/known_hosts'))
    sld('Connecting to {}'.format(dest_host))
    try:
        client.connect(dest_host, username=SSH_CLIENT_USER_NAME,
                            key_filename=expanduser('~/.ssh/id_rsa'))
    except Exception:
        sle('Failed to connect to host {}, because: \n   {}'.
            format(dest_host, sys.exc_info()[0].__name__))
        raise
    else:
        sld('Connected to host {}'.format(dest_host))
        return client

def distribute_cert(fd, dest_host, dest_dir, file_name, place, jail):

    """
    Distribute cert and key to a host, jail (if any) and place.
    Optional reload the service.
    
    @param fd:          file descriptor of memory stream
    @type fd:           io.StringIO
    @param dest_host:   fqdn of target host
    @type dest_host:    string
    @param dest_dir:    target directory
    @type dest_dir:     string
    @param file_name:   file name of key or cert file
    @type file_name:    string
    @param place:       place with details about setting mode and uid/gid of file
    @type place:        pki.cert.Place instance
    @param jail:        name of jail for service to reload
    @type jail:         string or None
    @rtype:             not yet any
    @exceptions:        none known
    """

    with ssh_connection(dest_host) as client:
        
        with client.open_sftp() as sftp:
            try:
                sftp.chdir(str(dest_dir))
            except IOError:
                sln('{}:{} does not exist - creating\n\t{}'.format(
                            dest_host, dest_dir, sys.exc_info()[0].__name__))
                try:
                    sftp.mkdir(str(dest_dir))   
                except IOError:
                    sle('Cant create {}:{}: Missing parent?\n\t{}'.format(
                            dest_host, dest_dir, sys.exc_info()[0].__name__))
                    raise
                sftp.chdir(str(dest_dir))
            
            sli('{} => {}:{}'.format(file_name, dest_host, dest_dir))
            fat = sftp.putfo(fd, file_name, confirm=True)
            sld('size={}, uid={}, gid={}, mtime={}'.format(
                        fat.st_size, fat.st_uid, fat.st_gid, fat.st_mtime))

            if 'key' in file_name:
                sld('Setting mode to 0o400 of {}:{}/{}'.format(
                                    dest_host, dest_dir, file_name))
                mode = 0o400
                if place.mode: mode = int(place.mode,8)
                sftp.chmod(file_name, mode)
                if place.pgLink:
                    try:
                        sftp.unlink('postgresql.key')
                    except IOError:
                        pass            # none exists: ignore
                    sftp.symlink(file_name, 'postgresql.key')
                    sld('{} => postgresql.key'.format(file_name))
                 
            if 'key' in file_name or place.chownBoth:
                uid = gid = 0
                if place.uid: uid = place.uid
                if place.gid: gid = place.gid
                if uid != 0 or gid != 0:
                    sld('Setting uid/gid to {}:{} of {}:{}/{}'.format(
                                    uid, gid, dest_host, dest_dir, file_name))
                    sftp.chown(file_name, uid, gid)
            elif place.pgLink:
                try:
                    sftp.unlink('postgresql.crt')
                except IOError:
                    pass            # none exists: ignore
                sftp.symlink(file_name, 'postgresql.crt')
                sld('{} => postgresql.crt'.format(file_name))
        
        if jail and place.reload_command:
            try:
                cmd = str((place.reload_command).format(jail))
            except:             #No "{}" in reload command: means no jail
                cmd = place.reload_command
            sli('Executing "{}" on host {}'.format(cmd, dest_host))

            with client.get_transport().open_session() as chan:
                chan.settimeout(10.0)
                chan.set_combine_stderr(True)
                chan.exec_command(cmd)
                
                remote_result_msg = ''
                while not chan.exit_status_ready():
                     if chan.recv_ready():
                        data = chan.recv(1024)
                        while data:
                            remote_result_msg += (data.decode('ascii'))
                            data = chan.recv(1024)
                es = int(chan.recv_exit_status())
                if es != 0:
                    sle('Remote execution failure of "{}" on host {}\texit={}, because:\n\r{}'
                            .format(cmd, dest_host, es, remote_result_msg))
                else:
                    sli(remote_result_msg)


def key_name(subject, subject_type):
    return str('%s_%s_key.pem' % (subject, subject_type))

def cert_name(subject, subject_type):
    return str('%s_%s_cert.pem' % (subject, subject_type))

def cert_cacert_name(subject, subject_type):
    return str('%s_%s_cert_cacert.pem' % (subject, subject_type))

def key_cert_name(subject, subject_type):
    return str('%s_%s_key_cert.pem' % (subject, subject_type))



# **TODO** Implement TLSA rollover. Keep old TLSA in *.old:tlsa
def distribute_tlsa_rrs(cert, TLSA_text):
    
    sli('Distributing TLSA RRs for DANE.')

    if Pathes.tlsa_dns_master == '':       # DNS master on local host
        for (zone, fqdn) in TLSA_zone_and_FQDN(cert): 
            filename = fqdn + '.tlsa'
            dest = str(Pathes.tlsa_repository_root / zone / filename)
            sli('{} => {}'.format(filename, dest))
            tlsa_lines = []
            for prefix in cert.tlsaprefixes:
                tlsa_lines.append(str(prefix.format(fqdn) + TLSA_text + '\n'))

            with open(dest, 'w') as file:
                file.writelines(tlsa_lines)
            
            TLSA_zone_cache[zone] = 1

    else:                           # remote DNS master ( **INCOMPLETE**)
        with ssh_connection(Pathes.tlsa_dns_master) as client:
            with client.open_sftp() as sftp:
                chdir(str(Pathes.work_tlsa))
                p = Path('.')
                sftp.chdir(str(Pathes.tlsa_repository_root))
                
                for child_dir in p.iterdir():
                    for child in child_dir.iterdir():
                        sli('{} => {}:{}'.format(
                                child, Pathes.tlsa_dns_master, child))
                        fat = sftp.put(str(child), str(child), confirm=True)
                        sld('size={}, uid={}, gid={}, mtime={}'.format(
                                        fat.st_size, fat.st_uid, fat.st_gid, fat.st_mtime))


def TLSA_zone_and_FQDN(theCertificate):
    """
    Retrieve zone and FQDN of TLSA RRs.
    
    @param theCertificate:     cerificate meta data
    @type theCertificate:      pki.cert.Certificate
    @rtype:                    List of tuples (may be empty) of strings
    @rtype                     Each tuple contains: zone, FQDN
    @exceptions:
    """
    retval = []
    
    for fqdn in theCertificate.altnames + [theCertificate.name]:
        fqdn_tags = fqdn.split(sep='.')
        dest_zone = '.'.join(fqdn_tags[-2::])
        retval.append((dest_zone, fqdn))
    return retval

def updateSOAofUpdatedZones():
    
    timestamp = datetime.now()
    current_date = timestamp.strftime('%Y%m%d')

    for zone in TLSA_zone_cache:

        filename = Pathes.tlsa_repository_root / zone / str(zone + '.zone')
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
        if len(TLSA_zone_cache) > 0:
            try:
                 sld('Reloading nameserver')
                 subprocess.call(['rndc', 'reload'])
            except subprocess.SubprocessError as e:
                 sle('Error while reloading nameserver: \n{}: {}'.format(e.cmd, e.output))

 