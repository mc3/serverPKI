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
from time import sleep

from paramiko import SSHClient, HostKeys, AutoAddPolicy

from pki.config import Pathes, SSH_CLIENT_USER_NAME
from pki.utils import options as opts
from pki.utils import sld, sli, sln, sle
from pki.utils import updateZoneCache, zone_and_FQDN_from_altnames
from pki.utils import updateSOAofUpdatedZones, reloadNameServer
from pki.utils import update_state_of_instance

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
        
        result = cert.instance()
        if not result:
            sle('No valid cerificate for {} in DB - create it first'.format(
                                                                    cert.name))
            raise MyException('No valid cerificate for {} in DB - '
                                            'create it first'.format(cert.name))
        instance_id, cert_text, key_text, TLSA_text, cacert_text = result
        
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
                        fd_cert = StringIO(cert_text + cacert_text)
                        distribute_cert(fd_key, fqdn, dest_dir, key_file_name, place, None)
                    
                    distribute_cert(fd_cert, fqdn, dest_dir, cert_file_name, place, jail)
            
        sli('')
        if not opts.no_TLSA:
            distribute_tlsa_rrs(cert, TLSA_text, None)
        
        update_state_of_instance(cert.db, instance_id, 'deployed')
        
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
                # won't work 288(10) gives 400(8)
                if place.mode:
                    mode = place.mode
                    sln('Setting mode of key at target to 0o400 - should be {}'.format(oct(place.mode)))
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




def distribute_tlsa_rrs(cert_meta, active_TLSA, prepublished_TLSA):
    
    """
    Distribute TLSA RR.
    Puts one (ore two) TLSA RR per fqdn in DNS zone directory and updates
    zone cache.
    @param cert_meta:   		Meta instance of certificates(s) being handled
    @type cert_meta:    		cert.Certificate instance
    @param active_TLSA:   		TLSA hash of active TLSA
    @type active_TLSA:    		string
    @param prepublished_TLSA:   TLSA hash of optional pre-published TLSA
    @type prepublished_TLSA:    string
    """

    if len(cert_meta.tlsaprefixes) == 0: return

    sli('Distributing TLSA RRs for DANE.')

    if Pathes.tlsa_dns_master == '':       # DNS master on local host
        for (zone, fqdn) in zone_and_FQDN_from_altnames(cert_meta): 
            filename = fqdn + '.tlsa'
            dest = str(Pathes.zone_file_root / zone / filename)
            sli('{} => {}'.format(filename, dest))
            tlsa_lines = []
            for prefix in cert_meta.tlsaprefixes:
                tlsa_lines.append(str(prefix.format(fqdn) +
                                         ' ' +active_TLSA + '\n'))
                if prepublished_TLSA:
                    tlsa_lines.append(str(prefix.format(fqdn) +
                                         ' ' +prepublished_TLSA + '\n'))
            with open(dest, 'w') as file:
                file.writelines(tlsa_lines)
            updateZoneCache(zone)

    else:                           # remote DNS master ( **INCOMPLETE**)
        sle('Remote DNS master server is currently not supported. Must be on same host as this script.')
        exit(1)
        with ssh_connection(Pathes.tlsa_dns_master) as client:
            with client.open_sftp() as sftp:
                chdir(str(Pathes.work_tlsa))
                p = Path('.')
                sftp.chdir(str(Pathes.zone_file_root))
                
                for child_dir in p.iterdir():
                    for child in child_dir.iterdir():
                        sli('{} => {}:{}'.format(
                                child, Pathes.tlsa_dns_master, child))
                        fat = sftp.put(str(child), str(child), confirm=True)
                        sld('size={}, uid={}, gid={}, mtime={}'.format(
                                        fat.st_size, fat.st_uid, fat.st_gid, fat.st_mtime))


