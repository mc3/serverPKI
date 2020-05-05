# -*- coding: utf-8 -*-

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

# Certificate class module

# --------------- imported modules --------------
import datetime
from hashlib import sha256
import logging
import os
import sys

# --------------- local imports --------------
from serverPKI.config import Pathes, X509atts, LE_SERVER

from serverPKI.utils import sld, sli, sln, sle, options, decrypt_key
from serverPKI.issue_LE import issue_LE_cert
from serverPKI.issue_local import issue_local_cert

# ---------------  prepared SQL queries for class Certificate  --------------

q_all_cert_meta = """
 SELECT s1.type AS subject_type,
    c.id AS c_id,
    c.disabled AS c_disabled,
    c.type AS c_type,
    c.authorized_until AS authorized_until,
    c.encryption_algo AS encryption_algo,
    c.ocsp_must_staple AS ocsp_must_staple,
    s2.name AS alt_name,
    s.tlsaprefix AS tlsaprefix,
    d.fqdn AS dist_host,
    d.jailroot AS jailroot,
    j.name AS jail,
    p.name AS place,
    p.cert_file_type AS cert_file_type,
    p.cert_path AS cert_path,
    p.key_path AS key_path,
    p.uid AS uid,
    p.gid AS gid,
    p.mode AS mode,
    p.chownBoth AS chownboth,
    p.pgLink AS pglink,
    p.reload_command AS reload_command
   FROM subjects s1
     RIGHT JOIN certificates c ON s1.certificate = c.id AND s1.isaltname = false
     LEFT JOIN subjects s2 ON s2.certificate = c.id AND s2.isaltname = true
     LEFT JOIN certificates_services cs ON c.id = cs.certificate
     LEFT JOIN services s ON cs.service = s.id
     LEFT JOIN targets t ON c.id = t.certificate
     LEFT JOIN disthosts d ON t.disthost = d.id
     LEFT JOIN jails j ON t.jail = j.id
     LEFT JOIN places p ON t.place = p.id
  WHERE s1.name = $1
  ORDER BY s1.name, s2.name, d.fqdn;
"""
q_specific_instance = """
    SELECT ci.id, ci.state, ci.ocsp_must_staple, ci.not_before, ci.not_after, ca.cert AS ca_cert, d.encryption_algo, d.cert, d.key, d.hash
        FROM CertInstances ci, CertInstances ca, CertKeyData d
        WHERE
            ci.id = $1::INT AND
            ci.CAcert = ca.id AND
            d.certinstance = $1::INT
"""

q_active_instances = """
    SELECT ci.id, ci.state
        FROM CertInstances ci
        WHERE
            ci.certificate = $1::INT AND
            ci.not_before <= LOCALTIMESTAMP AND
            ci.not_after >= LOCALTIMESTAMP
        ORDER BY ci.id DESC
"""

q_store_instance = """
    INSERT INTO CertInstances 
            (certificate, state, ocsp_must_staple, not_before, not_after, cacert)
        VALUES ($1::INTEGER, $2, $3::BOOLEAN, $4::TIMESTAMP, $5::TIMESTAMP, $6::INTEGER)
        RETURNING id::int
"""

q_store_certkeydata = """
    INSERT INTO CertKeyData 
            (certinstance, encryption_algo, cert, key, hash)
        VALUES ($1::INTEGER, $2, $3, $4, $5)
        RETURNING id::int
"""

q_recent_instance = """
    SELECT ci.id, ci.state, ci.cert, ci.key, ci.hash, ca.cert, ci.encryption_algo
        FROM CertInstances ci, CertInstances ca
        WHERE
            ci.certificate = $1::INT AND
            ci.not_before <= LOCALTIMESTAMP AND
            ci.not_after >= LOCALTIMESTAMP AND
            ci.CAcert = ca.id
        ORDER BY ci.id DESC
        LIMIT 1
"""

q_cert_key_data = """
    SELECT d.encryption_algo,d.cert,d.key,d.hash
        FROM certkeydata union distinct 
        WHERE
            d.certinstance = $1::INT
"""

q_instance_id_from_hash = """
    SELECT ck.certinstance
        FROM certkeydata ck 
        WHERE
            ck.hash = $1
"""

q_tlsa_of_instance = """
    SELECT hash
        FROM CertInstances
        WHERE
            id = $1
"""
q_update_authorized_until = """
    UPDATE Certificates
        SET authorized_until = $2::DATE
        WHERE id = $1
"""
q_fqdn_from_serial = """
SELECT s.name::TEXT
    FROM Subjects s, Certificates c, Certinstances i
    WHERE
        i.id = $1   AND
        i.certificate = c.id  AND
        s.certificate = c.id  AND
        NOT s.isaltname
"""

ps_all_cert_meta = None
ps_specific_instance = None
ps_store_instance = None
ps_store_certkeydata = None
ps_recent_instance = None
ps_tlsa_of_instance = None
ps_active_instances = None
ps_cert_key_data = None
ps_instance_id_from_hash = None
ps_update_authorized_until = None
ps_fqdn_from_serial = None


def fqdn_from_serial(db, serial):
    """
    Obtain cert subject name from instance serial
    
    @param db:      Opened database handle
    @type db:    
    @param serial:  instance serial
    @type serial:   integer
    @rtype:         name as string
    @exceptions:
    """

    global ps_fqdn_from_serial

    if not ps_fqdn_from_serial:
        ps_fqdn_from_serial = db.prepare(q_fqdn_from_serial)

    result = ps_fqdn_from_serial.first(serial)
    if result: return result
    sle('Serial {} not found.'.format(serial))
    sys.exit(1)


# --------------- public class Certificate --------------


class Certificate(object):
    """
    Certificate meta data class.
    In memory representation of DB backed meta information.
    """

    def __init__(self, db, name, serial=None):
        """
        Create a certificate meta data instance
    
        @param db:          opened database connection
        @type db:           serverPKI.db.DbConnection instance
        @param name:        subject name of certificate, ignored, if serial present
        @type name:         string
        @param serial:      serial of instance, whose cert meta we are creating
        @type serial:       integer
        @rtype:             Certificate instance
        @exceptions:
        """

        global ps_all_cert_meta

        self.db = db

        if serial:
            self.name = fqdn_from_serial(db, serial)
        else:
            self.name = name

        self.altnames = []
        self.tlsaprefixes = {}
        self.disthosts = {}

        self.cert_id = None

        with self.db.xact(isolation='SERIALIZABLE', mode='READ ONLY'):
            if not ps_all_cert_meta:
                ps_all_cert_meta = db.prepare(q_all_cert_meta)
            for row in ps_all_cert_meta(self.name):
                if not self.cert_id:
                    self.cert_id = row['c_id']
                    self.cert_type = row['c_type']
                    self.disabled = row['c_disabled']
                    self.authorized_until = row['authorized_until']
                    self.subject_type = row['subject_type']
                    self.encryption_algo = row['encryption_algo']
                    self.ocsp_must_staple = row['ocsp_must_staple']
                    sld('----------- {}\t{}\t{}\t{}\t{}\t{}\t{}'.format(
                        self.cert_id,
                        self.name,
                        self.cert_type,
                        self.disabled,
                        self.authorized_until,
                        self.subject_type,
                        self.encryption_algo,
                        self.ocsp_must_staple)
                    )
                if row['alt_name']: self.altnames.append(row['alt_name'])
                if row['tlsaprefix']: self.tlsaprefixes[row['tlsaprefix']] = 1

                # crate a tree from rows:  dh1... -> jl1... -> pl1..., )

                if row['dist_host']:
                    if row['dist_host'] in self.disthosts:
                        dh = self.disthosts[row['dist_host']]
                    else:
                        dh = {'jails': {}}
                        self.disthosts[row['dist_host']] = dh
                        jr = ''
                        if row['jailroot']: jr = row['jailroot']
                        self.disthosts[row['dist_host']]['jailroot'] = jr

                    if row['jail']:
                        if row['jail'] == '':
                            raise Exception('Empty jail name of disthost {} in DB - '
                                            'Jail names must not be empty'.format(row['dist_host']))
                        jail_name = row['jail']
                    else:
                        jail_name = ''

                    if jail_name in dh['jails']:
                        jl = dh['jails'][jail_name]
                    else:
                        jl = {'places': {}}
                        dh['jails'][jail_name] = jl

                    if row['place']:
                        if row['place'] not in jl['places']:
                            p = Place(
                                name=row['place'],
                                cert_file_type=row['cert_file_type'],
                                cert_path=row['cert_path'],
                                key_path=row['key_path'],
                                uid=row['uid'],
                                gid=row['gid'],
                                mode=row['mode'],
                                chownboth=row['chownboth'],
                                pglink=row['pglink'],
                                reload_command=row['reload_command']
                            )
                            jl['places'][row['place']] = p
                    else:
                        sln('Missing Place in Disthost {}'.format(row['dist_host']))

                sld('altname:{}\tdisthost:{}\tjail:{}\tplace:{}'.format(
                    row['alt_name'] if row['alt_name'] else '',
                    row['dist_host'] if row['dist_host'] else '',
                    row['jail'] if row['jail'] else '',
                    row['place'] if row['place'] else '')
                )
        sld('tlsaprefixes of {}: {}'.format(self.name, self.tlsaprefixes))

    def instance(self, instance_id=None):
        """
        Return instance id, state, ocsp_must_staple, CA certificate plus list of certkeydata with:
        certificate, key, TLSA hash and encryption algo of specific instance

        @param instance_id  id of specific instance
        @type  instance_id  int
        @rtype:             dict with keys id, state, ocsp_ms, ca_cert, certkeydata
                            certkeydata is a list of dicts with the keys: allgo, cert, key and hash
        @exceptions:        AssertionError if instance missing
        """

        global ps_recent_instance, ps_specific_instance

        if instance_id:
            if not ps_specific_instance:
                ps_specific_instance = self.db.prepare(q_specific_instance)
            rows = ps_specific_instance(instance_id)
        else:
            if not ps_recent_instance:
                ps_recent_instance = self.db.prepare(q_recent_instance)
            rows = ps_recent_instance(self.cert_id)

        if not rows:
            AssertionError('Cert.instance: Instance id {} does not exist'.format(instance_id)))

        rd = {}
        rd['certkeydata'] = []
        first = True
        for row in rows
            if first:
                rd['id'] = row['id']
                rd['state'] = row['state']
                rd['ocsp_ms'] = row['ocsp_must_staple']
                rd['ca_cert'] = row['ca_cert']          ####FIXME###
                rd['not_before'] = row['not_before']
                rd['not_after'] = row['not_after']
                first = False
            d['algo'] = row['encryption_algo']
            d['cert'] = row['cert']
            d['key'] = row['key']
            d['hash'] = row['hash']

            rd['certkeydata'].append(d)

        sld('Hashes of selected Certinstance are {}'.format([d['hash'] for d in rd['certkeydata']]))

        if self.subject_type == 'CA':       # do not return key of CA cert
            assert len(rd['certkeydata'] == 1)
            rd['certkeydata'][0]['key'] = None,
        return rd

    def cert_key_data(self, instance_id):
        """
         Return list of dicts of encryption algo, certificate, key, TLSA hash of specific instance

         @param instance_id  id of specific instance
         @type  instance_id  int
         @rtype:             List of dicts with keys: algo, cert, key, hash or None
                             Values are strings
         @exceptions:        none
         """

        global ps_cert_key_data

        if not ps_cert_key_data:
            ps_cert_key_data = self.db.prepare(q_cert_key_data)

        d = {}              # return dict
        rows = ps_cert_key_data(self.instance_id)
        for row in rows:
            d['algo'] = row['encryption_algo']
            d['cert'] = row['cert']
            d['key'] = row['key']
            d['hash'] = row['hash']
        return d


    def store_instance(self, d):

        """
        Store instance and related cert key data in DB backend.

        @param d    data, describing instance to be stored in DB
        @type  d    DICT with keys: state, ocsp_ms, not_before, not_after, ca_cert_id and
                    list of dicts with certkeydata with keys: algo, cert, key, hash

        @rtype:     id of new instance (INTEGER)
        @exceptions:none
        """
        global ps_store_instance, ps_store_certkeydata

        if not ps_store_instance:
            ps_store_instance = self.db.prepare(q_store_instance)
        if not ps_store_certkeydata:
            ps_store_certkeydata = self.db.prepare(q_store_certkeydata)

        (instance_id) = ps_store_instance(
            self.cert_id,
            d['state'],
            d['ocsp_ms'],
            d['not_before'],
            d['not_after'],
            d['ca_cert_id'] )
        if not instance_id:
            AssertionError('Cert.store_instance: INSERT of instance failed')

        for ckd in d['certkeydata']:
            ckd_id = ps_store_certkeydata(
                instance_id,
                ckd['algo'],
                ckd['cert'],
                ckd['key'],
                ckd['hash']
            )
            if not ckd_id:
                AssertionError('Cert.store_instance: INSERT of certkeydata failed')

        return instance_id


    def active_instances(self):

        """
        Return dictionary of active cert instances
        Active means cert is valid now.
    
        @rtype:             List of 2-tupels:
                            (instance id (int), state (string))
                            
        @exceptions:        none
        """

        global ps_active_instances

        if not ps_active_instances:
            ps_active_instances = self.db.prepare(q_active_instances)
        l = []
        rows = ps_active_instances(self.cert_id)
        for row in rows:
            l.append((row['id'], row['state']))
        if len(l) > 2:
            sln('More than 2 active instances for {}'.format(self.name))
        return l

    def TLSA_hash(self, instance_id):
        """
        Return TLSA hash of instance, which is valid today and in prepublish state

        @rtype:             string of TLSA hash
        @exceptions:        none
        """
        global ps_tlsa_of_instance

        if not ps_tlsa_of_instance:
            ps_tlsa_of_instance = self.db.prepare(q_tlsa_of_instance)

        sld('TLSA_hash: Called with {}'.format(instance_id))
        rv = ps_tlsa_of_instance.first(instance_id)
        if not rv:
            sle('cert.TLSA_hash called with noneexistant id'.format(instance_id))
            return None
        sld('TLSA_hash: ps_tlsa_of_instance returned {}'.format(rv))
        if isinstance(rv, str):
            return rv
        else:
            return rv[0]

    def create_instance(self):
        """
        Issue a new certificate instance and store it
        in the DB table certinstances.

        @rtype:             bool, true if success
        @exceptions:        AssertionError
        """

        with self.db.xact(isolation='SERIALIZABLE', mode='READ WRITE'):
            if self.cert_type == 'LE':
                return issue_LE_cert(self)
            elif self.cert_type == 'local':
                return issue_local_cert(self)
            else:
                raise AssertionError

    def update_authorized_until(self, until):
        """
        Update authorized_until of current Certificates instance.

        @param until:       date and time where LE authrization expires
        @type until:        datetime.datetime instance
        @rtype:             string of TLSA hash
        @exceptions:        none
        """
        global ps_update_authorized_until

        # resetting of authorized_until allowd only by local certs
        assert until or self.cert_type == 'local', \
            'update_authorized_until {} called for {}'.format(until, self.name)

        if not ps_update_authorized_until:
            ps_update_authorized_until = self.db.prepare(q_update_authorized_until)

        (updates) = ps_update_authorized_until.first(
            self.cert_id,
            until
        )
        return updates


# --------------- class Place --------------

class Place(object):
    """
    Place is a collection of certificate metadata, describing details of
    deployment place. It is unique per service or server software.
    It may be re-used at multiple target hosts.
    Backed up in DB table Places'
    """

    def __init__(self, name=None,
                 cert_file_type=None,
                 cert_path=None,
                 key_path=None,
                 uid=None,
                 gid=None,
                 mode=None,
                 chownboth=None,
                 pglink=None,
                 reload_command=None):
        self.name = name
        self.cert_file_type = cert_file_type
        self.cert_path = cert_path
        self.key_path = key_path
        self.uid = uid
        self.gid = gid
        self.mode = mode
        self.chownBoth = chownboth
        self.pgLink = pglink
        self.reload_command = reload_command
