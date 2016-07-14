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
    
    if opts.debug: print('[limit_hosts={}, only_host={}, skip_host={}]'.format(
                                            limit_hosts, only_host, skip_host))
    
    chdir(str(Pathes.work))
    
    for cert in certs.values():
         
        if len(cert.disthosts) == 0: continue
        
        for fqdn,dh in cert.disthosts.items():
        
            if fqdn in skip_host: continue
            if limit_hosts and fqdn not in only_host: continue
        
            dest_path = PurePath('/')
            
            if opts.debug: print('[{}: {}]'.format(cert.name, fqdn))
            
            if dh['jails']:
                for jail in ( dh['jails'].keys() or '' ):
            
                    jailroot = dh['jailroot'] if dh['jailroot'] else ''
                    dest_path = PurePath('/', jailroot, jail)
                    if opts.debug:
                        print('[{}: {}: {}]'.format(cert.name, fqdn, dest_path))                
    
                    if not dh['places']:
                        print('?{} subject has no place attribute.'.format(cert.name))
                        error_found = True
                        return False
                        
                    for place in dh['places'].values():
                    
                        if place.cert_path:
                            dp = PurePath(dest_path, place.cert_path)
                            if opts.debug: print('[{}: {}: {}]'.format(
                                                        cert.name, fqdn, dp))
                            distribute_cert(cert.name, cert.subject_type, fqdn,
                                                    dp, place, jail, 'c')
                        else:
                            print('?Missing cert path in place "()" for cert'
                                ' "{}"'.format(place.name, cert.name))
                        if place.key_path:
                            dp = PurePath(dest_path, place.key_path)
                        elif (place.cert_file_type != 'combined' and 
                            place.cert_file_type != 'combined cacert'):
                            if opts.debug: print('[{}: {}: {}]'.format(
                                                        cert.name, fqdn, dp))
                            distribute_cert(cert.name, cert.subject_type, fqdn,
                                                    dp, place, jail, 'k')
                
        print()
        if not opts.no_TLSA:
            print()
            distribute_tlsa_rrs(cert)
        
    updateSOAofUpdatedZones()
    reloadNameServer()
    return not error_found


def ssh_connection(dest_host):

    client = SSHClient()
    client.load_host_keys(expanduser('~/.ssh/known_hosts'))
    if opts.debug: print('[Connecting to {}]'.format(dest_host))
    try:
        client.connect(dest_host, username=SSH_CLIENT_USER_NAME,
                            key_filename=expanduser('~/.ssh/id_rsa'))
    except Exception:
        print('?Failed to connect to host {}, because: \n   {}'.
            format(dest_host, sys.exc_info()[0].__name__))
        raise
    else:
        if opts.debug: print('[Connected to host {}]'.format(dest_host))
        return client

def distribute_cert(subject, subject_type, dest_host, dest_path, place, jail, what):

    with ssh_connection(dest_host) as client:
        with client.open_sftp() as sftp:
            try:
                sftp.chdir(str(dest_path))
            except IOError:
                print('%{}:{} does not exist - creating\n\t{}'.format(
                            dest_host, dest_path, sys.exc_info()[0].__name__))
                try:
                    sftp.mkdir(str(dest_path))   
                except IOError:
                    print('?Cant create {}:{}: Missing parent?\n\t{}'.format(
                            dest_host, dest_path, sys.exc_info()[0].__name__))
                    raise
                sftp.chdir(str(dest_path))
            pl = cert_and_key_pathes(subject, subject_type, place, what)            
            for ppath in pl:
                path = str(ppath)
                print('[{}/{} => {}:{}]'.format(subject, path, dest_host, dest_path))
                fat = sftp.put(subject + '/' + path, path, confirm=True)
                if opts.debug: print('[size={}, uid={}, gid={}, mtime={}]'.format(
                            fat.st_size, fat.st_uid, fat.st_gid, fat.st_mtime))
                if 'key' in path:
                    if opts.debug: print('[Setting mode to 0o400 of {}:{}/{}]'.format(
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
                        if opts.debug: print('[{} => postgresql.key]'.format(path))
                     
                if 'key' in path or place.chownBoth:
                    uid = gid = 0
                    if place.uid: uid = place.uid
                    if place.gid: gid = place.gid
                    if uid != 0 or gid != 0:
                        if opts.debug: print('[Setting uid/gid to {}:{} of {}:{}/{}'.format(
                                                            uid, gid, dest_host, dest_path, path))
                        sftp.chown(path, uid, gid)
                elif place.pgLink:
                    try:
                        sftp.unlink('postgresql.crt')
                    except IOError:
                        pass            # none exists: ignore
                    sftp.symlink(path, 'postgresql.crt')
                    if opts.debug: print('[{} => postgresql.crt]'.format(path))
        if place.reload_command:
            cmd = str((place.reload_command).format(jail))
            print('[Executing "{}" on host {}]'.format(cmd, dest_host))
            with client.get_transport().open_session() as chan:
                chan.settimeout(10.0)
                chan.set_combine_stderr(True)
                chan.exec_command(cmd)
                #stdin = chan.makefile('wb', -1)
                #stdout = chan.makefile('rb', -1)
                ##print('stdout="{}", stderr="{}"'.format(stdout, stderr))
                ##chan.exec_command(cmd)
                
                while not chan.exit_status_ready():
                    
                    if chan.recv_ready():
                        data = chan.recv(1024)
                        while data:
                            print(data.decode('ascii'),end='')
                            data = chan.recv(1024)
                es = int(chan.recv_exit_status())
                if es != 0:
                    print('?Remote execution failure of "{}" on host {}\texit={}'
                            .format(cmd, dest_host, es))


# **TODO** Implement TLSA rollover. Keep old TLSA in *.old:tlsa
def distribute_tlsa_rrs(cert):
    
    if Pathes.tlsa_dns_master == '':       # DNS master on local host
        for tlsa_path in TLSA_pathes(cert): 
            dest = str((Pathes.tlsa_repository_root / tlsa_path.relative_to(Pathes.work_tlsa)).parent)
            print('[{} => {}]'.format(str(tlsa_path), dest))
            copy2(str(tlsa_path), dest)
            TLSA_zone_cache[dest] = 1
    else:                           # remote DNS master ( **UNTESTED**)
        with ssh_connection(Pathes.tlsa_dns_master) as client:
            with client.open_sftp() as sftp:
                chdir(str(Pathes.work_tlsa))
                p = Path('.')
                sftp.chdir(str(Pathes.tlsa_repository_root))
                
                for child_dir in p.iterdir():
                    for child in child_dir.iterdir():
                        print('[{} => {}:{}]'.format(
                                child, Pathes.tlsa_dns_master, child))
                        fat = sftp.put(str(child), str(child), confirm=True)
                        if opts.debug: print('[size={}, uid={}, gid={}, mtime={}]'.format(
                                        fat.st_size, fat.st_uid, fat.st_gid, fat.st_mtime))

def updateSOAofUpdatedZones():
    
    timestamp = datetime.now()
    current_date = timestamp.strftime('%Y%m%d')

    for k in TLSA_zone_cache:

        chdir(k)
        filename = str(Path(k).name) + '.zone'  # **HACK: supports only 2nd level domains**
        zf = ''
        with open(filename, 'r', encoding="ASCII") as fd:
            try:
                zf = fd.read()
            except:                 # file not found or not readable
                raise MyException("?Can't read zone file " + filename)
        if opts.debug: print('[Updating SOA: zone file before update:{}]'.format(zf))
        sea = re.search('(\d{8})(\d{2})(\s*;\s*)(Serial number)', zf)
        old_date = sea.group(1)
        daily_change = sea.group(2)
        if old_date == current_date:
           daily_change = str('%02d' % (int(daily_change) +1, ))
        else:
            daily_change = '01'
        zf = re.sub('\d{10}', current_date + daily_change, zf, count=1)
        if opts.debug: print('[Updating SOA: zone file after update:{}]'.format(zf))
        with open(filename, 'w', encoding="ASCII") as fd:
            try:
                fd.write(zf)
            except:                 # file not found or not readable
                raise MyException("Can't write zone file " + filename)

def reloadNameServer():
        if len(TLSA_zone_cache) > 0:
            try:
                 if opts.debug: print('[Reloading nameserver]')
                 subprocess.call(['rndc', 'reload'])
            except subprocess.SubprocessError as e:
                 print('?Error while reloading nameserver: \n{}: {}'.format(e.cmd, e.output))

 