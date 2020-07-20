# -*- coding: utf-8 -*

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


# Certificate distribution module.


import sys
from io import StringIO
from pathlib import PurePath, Path
from os.path import expanduser
from os import chdir
from socket import timeout
from typing import Union, List, Dict, Optional, Tuple

from dns import rdatatype
from dns import query as dns_query

from paramiko import SSHClient, HostKeys, AutoAddPolicy
from postgresql import driver as db_conn

from serverPKI.cert import Certificate, CertInstance, EncAlgoCKS, CertState, CertType, PlaceCertFileType, SubjectType
from serverPKI.utils import get_options
from serverPKI.utils import sld, sli, sln, sle,  Pathes, Misc
from serverPKI.utils import updateSOAofUpdatedZones, ddns_update


class MyException(Exception):
    pass


def export_instance(db: db_conn) -> bool:
    """
    Export certs and keys of one CertInstance
    :param db: Opened database handle
    :return: True on success
    """
    opts = get_options()

    name = Certificate.fqdn_from_instance_serial(db, opts.cert_serial)
    cert_meta = Certificate.create_or_load_cert_meta(db, name)
    for ci in cert_meta.cert_instances:
        if ci.row_id == opts.cert_serial:
            for cks in ci.cksd.values():
                algo = cks.algo
                cert = cks.cert
                key = cks.key

                cert_path = Path(Pathes.work) / 'cert-{}-{}.pem'.format(opts.cert_serial, algo)
                with open(str(cert_path), 'w') as fde:
                    fde.write(cert)

                key_path = Path(Pathes.work) / 'key-{}-{}.pem'.format(opts.cert_serial, algo)
                with open(str(key_path), 'w') as fde:
                    fde.write(key)
                    key_path.chmod(0o400)
    
                sli('Cert and {} key for {} exported to {} and {}'.
                                format(algo, cert_meta.name, str(cert_path), str(key_path)))
    return True


def consolidate_cert(cert_meta: Certificate):
    """
    Consolidate cert targets of one cert meta.
    This means cert and key files of instance in state "deployed"
    are redistributed.
    
    @param cert_meta:   Cert meta
    @type cert_meta:    cert.Certificate
    @rtype:             None
    @exceptions:
    """
    deployed_ci = None
    
    inst_dict = cert_meta.active_instances
    sld('consolidate_cert: inst_list = {}'.format(inst_dict))
    if not inst_dict: return
    
    for state, ci in inst_dict.items():
        if state == CertState('deployed'):
            deployed_ci = ci
            break

    if not deployed_ci:
        sli('consolidate_cert: No instance of {} in state "deployed"'.format(
                                                                cert_meta.name))
        return
    
    try:
        deployCerts({cert_meta.name: cert_meta},
            cert_instances=(deployed_ci,),
            allowed_states=(CertState('deployed'), ))
    except MyException:
        pass
    return

def deployCerts(cert_metas: Dict[str, Certificate],
                cert_instances: Optional[Tuple[CertInstance]] = None,
                allowed_states: Tuple[CertState]=(CertState('issued'),)) -> bool:
    """
    Deploy a list of (certificates. keys and TLSA RRs, using paramiko/sftp) and dyn DNS (or zone files).
    Restart service at target host and reload nameserver (if using zone files).
    :param cert_metas: Dict of cert metas, telling which certs to deploy, key is cert subject name
    :param cert_instances: Optional list of CertInstance instances
    :param allowed_states: States describing CertInstance states to act on
    :return: True if successfully deployed certs
    """

    error_found = False
    limit_hosts = False

    opts = get_options()

    only_host = []
    if opts.only_host: only_host = opts.only_host
    if len(only_host) > 0: limit_hosts = True
    
    skip_host = []
    if opts.skip_host: skip_host = opts.skip_host
    
    sld('limit_hosts={}, only_host={}, skip_host={}'.format(
                                            limit_hosts, only_host, skip_host))
    
    for cert_meta in cert_metas.values():
         
        if len(cert_meta.disthosts) == 0: continue

        the_instances = []
        hashes = []

        ##FIXME## highly speculative!
        insts = cert_instances if cert_instances else [y for (x,y) in cert_meta.active_instances.items()]
        for ci in insts:
            if ci.state in allowed_states:
                the_instances.append(ci)

        if len(the_instances) == 0:
            etxt = 'No valid cerificate for {} in DB - create it first\n' \
                   'States being considered are {}'. \
                format(cert_meta.name, [state for state in allowed_states])
            sli(etxt)
            if cert_instances:  # let caller handle this error, if we have explicit inst ids
                raise MyException(etxt)
            else: continue

        # more than 1 member of the_instances only expected with cert.instance(i).encryption_algo == 'both'
        for ci in the_instances:

            state = ci.state
            cacert_text = cert_meta.cacert_PEM(ci)

            host_omitted = False

            cksd = ci.the_cert_key_stores
            for encryption_algo in cksd.keys():
                cks = cksd[encryption_algo]
                cert_text = cks.cert
                key_text = cks.key
                TLSA_text = cks.hash
                hashes.append(TLSA_text)

                for fqdn,dh in cert_meta.disthosts.items():

                    if fqdn in skip_host:
                        host_omitted = True
                        continue
                    if limit_hosts and (fqdn not in only_host):
                        host_omitted = True
                        continue
                    dest_path = PurePath('/')

                    sld('{}: {}'.format(cert_meta.name, fqdn))

                    for jail in ( dh['jails'].keys() or ('',) ):   # jail is empty if no jails

                        if '/' in jail:
                            sle('"/" in jail name "{}" not allowed with subject {}.'.format(jail, cert_meta.name))
                            error_found = True
                            return False

                        jailroot = dh['jailroot'] if jail != '' else '' # may also be empty
                        dest_path = PurePath('/', jailroot, jail)
                        sld('{}: {}: {}'.format(cert_meta.name, fqdn, dest_path))

                        the_jail = dh['jails'][jail]

                        if len(the_jail['places']) == 0:
                            sle('{} subject has no place attribute.'.format(cert_meta.name))
                            error_found = True
                            return False

                        for place in the_jail['places'].values():

                            sld('Handling jail "{}" and place {}'.format(jail, place.name))

                            fd_key = StringIO(key_text)
                            fd_cert = StringIO(cert_text)

                            key_file_name = key_name(cert_meta.name, cert_meta.subject_type, encryption_algo)
                            cert_file_name = cert_name(cert_meta.name, cert_meta.subject_type, encryption_algo)

                            pcp = place.cert_path
                            if '{}' in pcp:     # we have a home directory named like the subject
                                pcp = pcp.format(cert_meta.name)
                            # make sure pcb does not start with '/', which would ignore dest_path:
                            if PurePath(pcp).is_absolute():
                                dest_dir = PurePath(dest_path, PurePath(pcp).relative_to('/'))
                            else:
                                dest_dir = PurePath(dest_path, PurePath(pcp))

                            sld('Handling fqdn {} and dest_dir "{}" in deployCerts'.format(
                                fqdn, dest_dir))

                            try:

                                if place.key_path:
                                    key_dest_dir = PurePath(dest_path, place.key_path)
                                    distribute_cert(fd_key, fqdn, key_dest_dir, key_file_name, place, None)

                                elif place.cert_file_type == 'separate':
                                    distribute_cert(fd_key, fqdn, dest_dir, key_file_name, place, None)
                                    if cert_meta.cert_type == 'LE':
                                        chain_file_name = cert_cacert_chain_name(cert_meta.name, cert_meta.subject_type, encryption_algo)
                                        fd_chain = StringIO(cert_text + cacert_text)
                                        distribute_cert(fd_chain, fqdn, dest_dir, chain_file_name, place, jail)

                                elif place.cert_file_type == 'combine key':
                                    cert_file_name = key_cert_name(cert_meta.name, cert_meta.subject_type, encryption_algo)
                                    fd_cert = StringIO(key_text + cert_text)
                                    if cert_meta.cert_type == 'LE':
                                        chain_file_name = key_cert_cacert_chain_name(cert_meta.name, cert_meta.subject_type, encryption_algo)
                                        fd_chain = StringIO(key_text + cert_text + cacert_text)
                                        distribute_cert(fd_chain, fqdn, dest_dir, chain_file_name, place, jail)

                                elif place.cert_file_type == 'combine both':
                                    cert_file_name = key_cert_cacert_name(cert_meta.name, cert_meta.subject_type, encryption_algo)
                                    fd_cert = StringIO(key_text + cert_text + cacert_text)

                                elif place.cert_file_type == 'combine cacert':
                                    cert_file_name = cert_cacert_name(cert_meta.name, cert_meta.subject_type, encryption_algo)
                                    fd_cert = StringIO(cert_text + cacert_text)
                                    distribute_cert(fd_key, fqdn, dest_dir, key_file_name, place, None)

                                # this may be redundant in case of LE, where the cert was in chained file
                                distribute_cert(fd_cert, fqdn, dest_dir, cert_file_name, place, jail)

                            except IOError:         # distribute_cert may error out
                                error_found = True
                                break               # no cert - no TLSA
            
            sli('')

            if opts.sync_disk:      # skip TLSA stuff if doing consolidate
                continue

            if not opts.no_TLSA:
                distribute_tlsa_rrs(cert_meta, hashes)

            if not host_omitted and not cert_meta.subject_type == 'CA':
                ci.state = CertState('deployed')
                cert_meta.save_instance(ci)
            else:
                sln('State of cert {} not promoted to DEPLOYED, '
                    'because hosts where limited or skipped'.format(
                                cert_meta.name))
            # clear mail-sent-time if local cert.
            if cert_meta.cert_type == CertType('local'): cert_meta.update_authorized_until(None)
        
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
         client.connect(dest_host, username=Misc.SSH_CLIENT_USER_NAME)
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
                if place.mode:
                    mode = place.mode
                    sld('Setting mode of key at target to {}'.format(oct(place.mode)))
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


def key_name(subject, subject_type, encryption_algo):
    return str('%s_%s_%skey.pem' % (subject, subject_type, ('ec_' if encryption_algo and encryption_algo == EncAlgoCKS('ec') else '')))

def cert_name(subject, subject_type, encryption_algo):
    return str('%s_%s_%scert.pem' % (subject, subject_type, ('ec_' if encryption_algo and encryption_algo == EncAlgoCKS('ec') else '')))

def cert_cacert_name(subject, subject_type, encryption_algo):
    return str('%s_%s_%scert_cacert.pem' % (subject, subject_type, ('ec_' if encryption_algo and encryption_algo == EncAlgoCKS('ec') else '')))

def cert_cacert_chain_name(subject, subject_type, encryption_algo):
    return str('%s_%s_%scert_cacert_chain.pem' % (subject, subject_type, ('ec_' if encryption_algo and encryption_algo == EncAlgoCKS('ec') else '')))

def key_cert_cacert_chain_name(subject, subject_type, encryption_algo):
    return str('%s_%s_key_%scert_cacert_chain.pem' % (subject, subject_type, ('ec_' if encryption_algo and encryption_algo == EncAlgoCKS('ec') else '')))

def key_cert_name(subject, subject_type, encryption_algo):
    return str('%s_%s_key_%scert.pem' % (subject, subject_type, ('ec_' if encryption_algo and encryption_algo == EncAlgoCKS('ec') else '')))

def key_cert_cacert_name(subject, subject_type, encryption_algo):
    return str('%s_%s_key_%scert_cacert.pem' % (subject, subject_type, ('ec_' if encryption_algo and encryption_algo == EncAlgoCKS('ec') else '')))


def consolidate_TLSA(cert_meta):
    """
    Consolidate all TLSA RRs for one cert meta.
    This means TLSA include files are freshly created.
    
    @param cert_meta:   Cert meta
    @type cert_meta:    cert.Certificate instance
    @rtype:             None
    @exceptions:
    """
    prepublished_ci = None
    deployed_ci = None
    
    inst_list = cert_meta.active_instances  # returns dict with state as key
    if not inst_list: return
    
    for state, ci in inst_list.items():
        if state == CertState('prepublished'):
            if not prepublished_ci:
                prepublished_ci = ci
            else:
                sln('consolidate_TLSA: More than one instance of {} in state'
                                ' "prepublished"'.format(cert_meta.name))
        elif state == 'deployed':
            if not deployed_ci:
                deployed_ci = ci
            else:
                sln('consolidate_TLSA: More than one instance of {} in state'
                                ' "deployed"'.format(cert_meta.name))
    if not deployed_ci:
        sli('consolidate_TLSA: No instance of {} in state "deployed"'
                                                    .format(cert_meta.name))
        return
    
    prepublished_TLSA = {}
    if prepublished_ci:
        prepublished_TLSA = cert_meta.TLSA_hash(prepublished_ci)
    
    deployed_TLSA = cert_meta.TLSA_hash(deployed_ci)

    distribute_tlsa_rrs(cert_meta, tuple(deployed_TLSA.values()) + tuple(prepublished_TLSA.values()))

    
def delete_TLSA(cert_meta: Certificate) -> None:
    """
    Delete all TLSA RRs per fqdn of all altnames either in flatfile (make include file empty) or in dyn dns
    :param cert_meta:
    :return:
    """

    if Pathes.tlsa_dns_master == '':       # DNS master on local host
        
        if Misc.LE_ZONE_UPDATE_METHOD == 'zone_file':

            for (zone, fqdn) in cert_meta.zone_and_FQDN_from_altnames():
                filename = fqdn + '.tlsa'
                dest = str(Pathes.zone_file_root / zone / filename)
    
                #just open for write without writing, which makes file empty 
                with open(dest, 'w') as fd: 
                    sli('Truncating {}'.format(dest))
                updateZoneCache(zone)
    
        elif Misc.LE_ZONE_UPDATE_METHOD == 'ddns':

            zones = {}
            for (zone, fqdn) in cert_meta.zone_and_FQDN_from_altnames():
                if zone in zones:
                    if fqdn not in zones[zone]: zones[zone].append(fqdn)
                else:
                    zones[zone] = [fqdn] 
            for zone in zones:
                the_update = ddns_update(zone)
                for fqdn in zones[zone]:
                    for prefix in cert_meta.tlsaprefixes.keys():
                        tag = str(prefix.format(fqdn)).split(maxsplit=1)[0]
                        sld('Deleting TLSA with tag {} an fqdn {} in zone {}'.
                            format(tag, fqdn, zone))
                        the_update.delete(tag)
                response = dns_query.tcp(the_update,'127.0.0.1', timeout=10)
                rc = response.rcode()
                if rc != 0:
                    sle('DNS update failed for zone {} with rcode: {}:\n{}'.
                                        format(zone, response.rcode.to_text(rc), response.rcode))
                    raise Exception('DNS update failed for zone {} with rcode: {}'.
                                        format(zone, response.rcode.to_text(rc)))
        

    
def distribute_tlsa_rrs(cert_meta: Certificate, hashes: Union[Tuple[str],List[str]]) -> None:
    """
    Distribute TLSA RR.
    Puts TLSA RR fqdn into DNS zone, by dynamic dns or editing zone file and updating zone cache.
    If cert has altnames, one set of TLSA RRs is inserted per altname and per TLSA prefix.
    :param cert_meta:
    :param hashes: list of hashes, may include active and prepublishes hashes for all algos
    :return:
    """

    if len(cert_meta.tlsaprefixes) == 0: return

    sli('Distributing TLSA RRs for DANE.')

    if Pathes.tlsa_dns_master == '':       # DNS master on local host
        
        if Misc.LE_ZONE_UPDATE_METHOD == 'zone_file':

            for (zone, fqdn) in zone_and_FQDN_from_altnames(cert_meta): 
                filename = fqdn + '.tlsa'
                dest = str(Pathes.zone_file_root / zone / filename)
                sli('{} => {}'.format(filename, dest))
                tlsa_lines = []
                for prefix in cert_meta.tlsaprefixes.keys():
                    for hash in hashes:
                        tlsa_lines.append(str(prefix.format(fqdn) +
                                             ' ' +hash + '\n'))
                with open(dest, 'w') as fd:
                    fd.writelines(tlsa_lines)
                updateZoneCache(zone)
    
        
        elif Misc.LE_ZONE_UPDATE_METHOD == 'ddns':
    
            tlsa_datatype = rdatatype.from_text('TLSA')
            zones = {}
            for (zone, fqdn) in cert_meta.zone_and_FQDN_from_altnames():
                if zone in zones:
                    if fqdn not in zones[zone]: zones[zone].append(fqdn)
                else:
                    zones[zone] = [fqdn] 
            for zone in zones:
                the_update = ddns_update(zone)
                for fqdn in zones[zone]:
                    for prefix in cert_meta.tlsaprefixes.keys():
                        pf_with_fqdn = str(prefix.format(fqdn))
                        fields = pf_with_fqdn.split(maxsplit=4)
                        sld('Deleting possible old TLSAs: {}'.
                            format(fields[0]))
                        the_update.delete(fields[0], tlsa_datatype)
                        
                        for hash in hashes:
                            sld('Adding TLSA: {} {} {} {}'.
                                format(fields[0], int(fields[1]), fields[3],
                                                fields[4] + ' ' +hash ))
                            the_update.add(fields[0], int(fields[1]), fields[3],
                                                fields[4] + ' ' +hash )

                response = dns_query.tcp(the_update,'127.0.0.1', timeout=10)
                rc = response.rcode()
                if rc != 0:
                    sle('DNS update failed for zone {} with rcode: {}:\n{}'.
                                        format(zone, response.rcode.to_text(rc), response.rcode))
                    raise Exception('DNS update add failed for zone {} with rcode: {}'.
                                        format(zone, response.rcode.to_text(rc)))


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


