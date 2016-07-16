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

from pki.certstore import cert_and_key_pathes, TLSA_pathes
from pki.config import Pathes, SSH_CLIENT_USER_NAME
from pki.utils import options as opts
from pki.utils import sld, sli, sln, sle

TLSA_zone_cache = {}

class MyException(Exception):
    pass

def deployCerts(certs):

    error_found = False
        
    limit_hosts = False
    only_host = []
    if opts.only_host: only_host = opts.only_host
    if len(only_host) > 0: limit_hosts = True
    
    skip_host = []
    if opts.skip_host: skip_host = opts.skip_host
    
    sld('limit_hosts={}, only_host={}, skip_host={}'.format(
                                            limit_hosts, only_host, skip_host))
    
    chdir(str(Pathes.work))
    
    for cert in certs.values():
         
        if len(cert.disthosts) == 0: continue
        
        for fqdn,dh in cert.disthosts.items():
        
            if fqdn in skip_host: continue
            if limit_hosts and fqdn not in only_host: continue
        
            dest_path = PurePath('/')
            
            sld('{}: {}'.format(cert.name, fqdn))
            
            if dh['jails']:
                for jail in ( dh['jails'].keys() or '' ):
            
                    jailroot = dh['jailroot'] if dh['jailroot'] else ''
                    dest_path = PurePath('/', jailroot, jail)
                    sld('[{}: {}: {}]'.format(cert.name, fqdn, dest_path))                
    
                    if not dh['places']:
                        sle('{} subject has no place attribute.'.format(cert.name))
                        error_found = True
                        return False
                        
                    for place in dh['places'].values():
                    
                        if place.cert_path:
                            dp = PurePath(dest_path, place.cert_path)
                            sld('{}: {}: {}'.format(
                                                        cert.name, fqdn, dp))
                            distribute_cert(cert.name, cert.subject_type, fqdn,
                                                    dp, place, jail, 'c')
                        else:
                            sle('Missing cert path in place "()" for cert'
                                ' "{}"'.format(place.name, cert.name))
                        if place.key_path:
                            dp = PurePath(dest_path, place.key_path)
                        elif (place.cert_file_type != 'combined' and 
                            place.cert_file_type != 'combined cacert'):
                            sld('{}: {}: {}'.format(
                                                        cert.name, fqdn, dp))
                            distribute_cert(cert.name, cert.subject_type, fqdn,
                                                    dp, place, jail, 'k')
                
        sli('')
        if not opts.no_TLSA:
            sli('')
            distribute_tlsa_rrs(cert)
        
    updateSOAofUpdatedZones()
    reloadNameServer()
    return not error_found


def ssh_connection(dest_host):

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

def distribute_cert(subject, subject_type, dest_host, dest_path, place, jail, what):

    with ssh_connection(dest_host) as client:
        with client.open_sftp() as sftp:
            try:
                sftp.chdir(str(dest_path))
            except IOError:
                sln('{}:{} does not exist - creating\n\t{}'.format(
                            dest_host, dest_path, sys.exc_info()[0].__name__))
                try:
                    sftp.mkdir(str(dest_path))   
                except IOError:
                    sle('Cant create {}:{}: Missing parent?\n\t{}'.format(
                            dest_host, dest_path, sys.exc_info()[0].__name__))
                    raise
                sftp.chdir(str(dest_path))
            pl = cert_and_key_pathes(subject, subject_type, place, what)            
            for ppath in pl:
                path = str(ppath)
                sli('{}/{} => {}:{}'.format(subject, path, dest_host, dest_path))
                fat = sftp.put(subject + '/' + path, path, confirm=True)
                sld('size={}, uid={}, gid={}, mtime={}'.format(
                            fat.st_size, fat.st_uid, fat.st_gid, fat.st_mtime))
                if 'key' in path:
                    sld('Setting mode to 0o400 of {}:{}/{}'.format(
                                                                    dest_host, dest_path, path))
                    mode = 0o400
                    if place.mode: mode = int(place.mode,8)
                    sftp.chmod(path, mode)
                    if place.pgLink:
                        try:
                            sftp.unlink('postgresql.key')
                        except IOError:
                            pass            # none exists: ignore
                        sftp.symlink(path, 'postgresql.key')
                        sld('{} => postgresql.key'.format(path))
                     
                if 'key' in path or place.chownBoth:
                    uid = gid = 0
                    if place.uid: uid = place.uid
                    if place.gid: gid = place.gid
                    if uid != 0 or gid != 0:
                        sld('Setting uid/gid to {}:{} of {}:{}/{}'.format(
                                                            uid, gid, dest_host, dest_path, path))
                        sftp.chown(path, uid, gid)
                elif place.pgLink:
                    try:
                        sftp.unlink('postgresql.crt')
                    except IOError:
                        pass            # none exists: ignore
                    sftp.symlink(path, 'postgresql.crt')
                    sld('{} => postgresql.crt'.format(path))
        if place.reload_command:
            cmd = str((place.reload_command).format(jail))
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

# **TODO** Implement TLSA rollover. Keep old TLSA in *.old:tlsa
def distribute_tlsa_rrs(cert):
    
    sli('Distributing TLSA RRs for DANE.')
    if Pathes.tlsa_dns_master == '':       # DNS master on local host
        for tlsa_source_path, zone in TLSA_pathes(cert): 
            dest = str(Pathes.tlsa_repository_root / zone)
            sli('{} => {}'.format(str(tlsa_source_path), dest))
            copy2(str(tlsa_source_path), dest)
            TLSA_zone_cache[zone] = 1

    else:                           # remote DNS master ( **UNTESTED**)
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
        sld('Updating SOA: SOA before nd after update:\n{}\n{}'.format(old_serial,new_serial))
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

 