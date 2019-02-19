# -*- coding: utf-8 -*

"""
Copyright (C) 2015-2018  Axel Rau <axel.rau@chaos1.de>

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


# Certificate distribution module.


import sys
from datetime import datetime
from io import StringIO
from pathlib import PurePath, Path
from os.path import expanduser
from os import chdir
from socket import timeout
import subprocess
from shutil import copy2
from time import sleep

from paramiko import SSHClient, HostKeys, AutoAddPolicy

from serverPKI.cert import Certificate
from serverPKI.config import Pathes, SSH_CLIENT_USER_NAME
from serverPKI.utils import options as opts
from serverPKI.utils import sld, sli, sln, sle
from serverPKI.utils import updateZoneCache, zone_and_FQDN_from_altnames
from serverPKI.utils import updateSOAofUpdatedZones
from serverPKI.utils import update_state_of_instance

class MyException(Exception):
    pass


def export_instance(db):
    """
    Export cert and key whose serial number has been read from command line
    to work area
    
    @param db:      Opened database handle
    @type db:    
    @rtype:         boolean always True (or sys.exit done in cert_meta.inst if
                    serial does not exist.
    @exceptions:
    """

    cert_meta = Certificate(db, '', serial=opts.cert_serial)
    result = cert_meta.instance(instance_id=opts.cert_serial)
    (id, state, cert, key, tlsa, cacert) = result

    cert_path = Pathes.work / 'cert-{}.pem'.format(opts.cert_serial)
    with open(str(cert_path), 'w') as fde:
        fde.write(cert)

    key_path = Pathes.work / 'key-{}.pem'.format(opts.cert_serial)
    with open(str(key_path), 'w') as fde:
        fde.write(key)
    key_path.chmod(0o400)
    
    sli('Cert and key exported to {} and {}'.
                                        format(str(cert_path), str(key_path)))
    return True


def consolidate_cert(cert_meta):
    """
    Consolidate cert targets of one cert meta.
    This means cert and key files of instance in state "deployed"
    are freshly created.
    
    @param cert_meta:   Cert meta
    @type cert_meta:    cert.Certificate instance
    @rtype:             None
    @exceptions:
    """
    deployed_id = None
    
    inst_list = cert_meta.active_instances()
    sld('consolidate_cert: inst_list = {}'.format(inst_list))
    if not inst_list: return
    
    for id, state in inst_list:
        if state == 'deployed':
            deployed_id = id

    if not deployed_id:
        sli('consolidate_cert: No instance of {} in state "deployed"'.format(
                                                                cert_meta.name))
        return
    
    try:
        deployCerts({cert_meta.name: cert_meta},
                    instance_id=deployed_id,
                    consolidate=True,
                    allowed_states=('deployed', ))
    except MyException:
        pass
    return

def deployCerts(certs,
                instance_id=None,
                consolidate=False,
                allowed_states=('issued', )):

    """
    Deploy a list of (certificate. key and TLSA file, using sftp).
    Restart service at target host and reload nameserver.
    
    @param certs:           list of certificate meta data instances
    @type certs:            dict with key = cert name and 
                            value = serverPKI.cert.Certificate instance
    @param instance_id:     optional id of specific instance
    @type instance_id:      int
    @param consolidate      Prevent from distribution of TLSA and updating of state.
    @type consolidate       bool
    @param allowed_states   states, required for ditribution (default=('issued',)).
    @type allowed_states    tuple of strings
    @rtype:                 bool, false if error found
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
        
        result = cert.instance(instance_id)
        if not result:
            sli('No valid cerificate for {} in DB - create it first'.format(
                                                                    cert.name))
            if instance_id: # let caller handle this error, if only one cert
                raise MyException('No valid cerificate for {} in DB - '
                                        'create it first'.format(cert.name))
                
            else: continue
        my_instance_id, state, cert_text, key_text, TLSA_text, cacert_text = result
        
        if state not in allowed_states:
            sli('No recent valid certificate for {} in state'
                    ' "{}" in DB - not distributed or consolidated.'.format(
                                                cert.name, allowed_states))
            if instance_id: # let caller handle this error, if only one cert
                raise MyException('No recent valid certificate for "{}" in state'
                    ' "{}" in DB - not distributed or consolidated.'.format(
                                                cert.name, should_be_state))
            else: continue
            
        host_omitted = False
        
        for fqdn,dh in cert.disthosts.items():
        
            if fqdn in skip_host:
                host_omitted = True
                continue
            if limit_hosts and (fqdn not in only_host):
                host_omitted = True
                continue
            dest_path = PurePath('/')
            
            sld('{}: {}'.format(cert.name, fqdn))
            
            for jail in ( dh['jails'].keys() or ('',) ):   # jail is empty if no jails
            
                if '/' in jail:
                    sle('"/" in jail name "{}" not allowed with subject {}.'.format(jail, cert.name))
                    error_found = True
                    return False

                jailroot = dh['jailroot'] if jail != '' else '' # may also be empty
                dest_path = PurePath('/', jailroot, jail)
                sld('{}: {}: {}'.format(cert.name, fqdn, dest_path))                
    
                the_jail = dh['jails'][jail]
                
                if len(the_jail['places']) == 0:
                    sle('{} subject has no place attribute.'.format(cert.name))
                    error_found = True
                    return False
                    
                for place in the_jail['places'].values():
                
                    sld('Handling jail "{}" and place {}'.format(jail, place.name))
                                   
                    fd_key = StringIO(key_text)
                    fd_cert = StringIO(cert_text)
                
                    key_file_name = key_name(cert.name, cert.subject_type)
                    cert_file_name = cert_name(cert.name, cert.subject_type)
                    
                    pcp = place.cert_path
                    if '{}' in pcp:     # we have a home directory named like the subject
                        pcp = pcp.format(cert.name)
                    # make sure pcb does not start with '/', which would ignore dest_path:
                    if PurePath(pcp).is_absolute():
                        dest_dir = PurePath(dest_path, PurePath(pcp).relative_to('/'))
                    else:
                        dest_dir = PurePath(dest_path, PurePath(pcp))

                    sld('Handling fqdn {} and dest_dir "{}" in deployCerts'.format(
                                                        fqdn, dest_dir))
                
                    if place.key_path:
                        key_dest_dir = PurePath(dest_path, place.key_path)
                        distribute_cert(fd_key, fqdn, key_dest_dir, key_file_name, place, None)
                    
                    elif place.cert_file_type == 'separate':
                        distribute_cert(fd_key, fqdn, dest_dir, key_file_name, place, None)
                        if cert.cert_type == 'LE':
                            chain_file_name = cert_cacert_chain_name(cert.name, cert.subject_type)
                            fd_chain = StringIO(cert_text + cacert_text)
                            distribute_cert(fd_chain, fqdn, dest_dir, chain_file_name, place, jail)
                    
                    elif place.cert_file_type == 'combine key':
                        cert_file_name = key_cert_name(cert.name, cert.subject_type)
                        fd_cert = StringIO(key_text + cert_text)
                        if cert.cert_type == 'LE':
                            chain_file_name = key_cert_cacert_chain_name(cert.name, cert.subject_type)
                            fd_chain = StringIO(key_text + cert_text + cacert_text)
                            distribute_cert(fd_chain, fqdn, dest_dir, chain_file_name, place, jail)
                    
                    elif place.cert_file_type == 'combine both':
                        cert_file_name = key_cert_cacert_name(cert.name, cert.subject_type)
                        fd_cert = StringIO(key_text + cert_text + cacert_text)
                
                    elif place.cert_file_type == 'combine cacert':
                        cert_file_name = cert_cacert_name(cert.name, cert.subject_type)
                        fd_cert = StringIO(cert_text + cacert_text)
                        distribute_cert(fd_key, fqdn, dest_dir, key_file_name, place, None)
                    
                    # this may be redundant in case of LE, where the cert was in chained file
                    distribute_cert(fd_cert, fqdn, dest_dir, cert_file_name, place, jail)
            
        sli('')
        
        if consolidate:
            continue
        
        if not opts.no_TLSA:
            distribute_tlsa_rrs(cert, TLSA_text, None)
        
        if not host_omitted and not cert.subject_type == 'CA':
            update_state_of_instance(cert.db, my_instance_id, 'deployed')
        else:
            sln('State of cert {} not promoted to DEPLOYED, '
                'because hosts where limited or skipped'.format(
                            cert.name))
        # clear mail-sent-time if local cert.
        if cert.cert_type == 'local': cert.update_authorized_until(None)
        
    updateSOAofUpdatedZones()
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
        sln('Failed to connect to host {}, because {} [{}]'.
            format(dest_host,
            sys.exc_info()[0].__name__,
            str(sys.exc_info()[1])))
        raise
    else:
        sld('Connected to host {}'.format(dest_host))
        return client
    
def distribute_cert(fd, dest_host, dest_dir, file_name, place, jail):

    """
    Distribute cert and key to a host, jail (if any) and place.
    Optional reload the service.
    If global opts.extract set, instead of distributing to a host,
    certificat and key are written to the local work directory.
    
    @param fd:          file descriptor of memory stream
    @type fd:           io.StringIO
    @param dest_host:   fqdn of target host
    @type dest_host:    string
    @param dest_dir:    target directory
    @type dest_dir:     string
    @param file_name:   file name of key or cert file
    @type file_name:    string
    @param place:       place with details about setting mode and uid/gid of file
    @type place:        serverPKI.cert.Place instance
    @param jail:        name of jail for service to reload
    @type jail:         string or None
    @rtype:             not yet any
    @exceptions:        IOError
    """

    sld('Handling dest_host {} and dest_dir "{}" in distribute_cert'.format(
                                                        dest_host, dest_dir))
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
                            dest_host,
                            dest_dir,
                            sys.exc_info()[0].__name__,
                            str(sys.exc_info()[1])))
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
                timed_out = False
                while not chan.exit_status_ready():
                     if timed_out: break
                     if chan.recv_ready():
                        try:
                            data = chan.recv(1024)
                        except (timeout):
                            sle('Timeout on remote execution of "{}" on host {}'.format(cmd, dest_host))
                            break
                        while data:
                            remote_result_msg += (data.decode('ascii'))
                            try:
                                data = chan.recv(1024)
                            except (timeout):
                                sle('Timeout on remote execution of "{}" on host {}'.format(cmd, dest_host))
                                tmp = timed_out
                                timed_out = True
                                break
                es = int(chan.recv_exit_status())
                if es != 0:
                    sln('Remote execution failure of "{}" on host {}\texit={}, because:\n\r{}'
                            .format(cmd, dest_host, es, remote_result_msg))
                else:
                    sli(remote_result_msg)


def key_name(subject, subject_type):
    return str('%s_%s_key.pem' % (subject, subject_type))

def cert_name(subject, subject_type):
    return str('%s_%s_cert.pem' % (subject, subject_type))

def cert_cacert_name(subject, subject_type):
    return str('%s_%s_cert_cacert.pem' % (subject, subject_type))

def cert_cacert_chain_name(subject, subject_type):
    return str('%s_%s_cert_cacert_chain.pem' % (subject, subject_type))

def key_cert_cacert_chain_name(subject, subject_type):
    return str('%s_%s_key_cert_cacert_chain.pem' % (subject, subject_type))

def key_cert_name(subject, subject_type):
    return str('%s_%s_key_cert.pem' % (subject, subject_type))

def key_cert_cacert_name(subject, subject_type):
    return str('%s_%s_key_cert_cacert.pem' % (subject, subject_type))


def consolidate_TLSA(cert_meta):
    """
    Consolidate all TLSA RRs for one cert meta.
    This means TLSA include files are freshly created.
    
    @param cert_meta:   Cert meta
    @type cert_meta:    cert.Certificate instance
    @rtype:             None
    @exceptions:
    """
    prepublished_id = None
    deployed_id = None
    
    inst_list = cert_meta.active_instances()
    if not inst_list: return
    
    for id, state in inst_list:
        if state == 'prepublished':
            if not prepublished_id: 
                prepublished_id = id
            else:
                sln('consolidate_TLSA: More than one instance of {} in state'
                                ' "prepublished"'.format(cert_meta.name))
        elif state == 'deployed':
            if not deployed_id: 
                deployed_id = id
            else:
                sln('consolidate_TLSA: More than one instance of {} in state'
                                ' "deployed"'.format(cert_meta.name))
    if not deployed_id:
        sli('consolidate_TLSA: No instance of {} in state "deployed"'
                                                    .format(cert_meta.name))
        return
    
    prepublished_TLSA = None
    if prepublished_id:
        prepublished_TLSA = cert_meta.TLSA_hash(prepublished_id)
    
    deployed_TLSA = cert_meta.TLSA_hash(deployed_id)

    distribute_tlsa_rrs(cert_meta, deployed_TLSA, prepublished_TLSA)

    
def delete_TLSA(cert_meta):
    
    """
    Delete TLSA RR.
    Deletes one TLSA RR per fqdn in DNS zone directory and updates
    zone cache. "Delete" here means make tlsa file in zone directory empty.
    @param cert_meta:   		Meta instance of certificates(s) being handled
    @type cert_meta:    		cert.Certificate instance
    
    """

    if Pathes.tlsa_dns_master == '':       # DNS master on local host
        for (zone, fqdn) in zone_and_FQDN_from_altnames(cert_meta): 
            filename = fqdn + '.tlsa'
            dest = str(Pathes.zone_file_root / zone / filename)

            #just open for write without writing, which makes file empty 
            with open(dest, 'w') as fd: 
                sli('Truncating {}'.format(dest))
            updateZoneCache(zone)

    
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
            for prefix in cert_meta.tlsaprefixes.keys():
                tlsa_lines.append(str(prefix.format(fqdn) +
                                         ' ' +active_TLSA + '\n'))
                if prepublished_TLSA:
                    tlsa_lines.append(str(prefix.format(fqdn) +
                                         ' ' +prepublished_TLSA + '\n'))
            with open(dest, 'w') as fd:
                fd.writelines(tlsa_lines)
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


