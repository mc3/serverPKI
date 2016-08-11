# -*- coding: utf-8 -*-

"""
 Copyright (c) 2006-2014 Axel Rau, axel.rau@chaos1.de
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:

    - Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    - Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

"""

# serverpki Certificate class module
# requires python 3.4.

#--------------- imported modules --------------
import datetime
from hashlib import sha256
import logging
from pathlib import Path
import os
import sys

from OpenSSL import crypto,rand,crypto
from cryptography.hazmat.primitives.hashes import SHA256

TYPE_RSA = crypto.TYPE_RSA
TYPE_DSA = crypto.TYPE_DSA


#--------------- local imports --------------
from pki.config import Pathes, X509atts, LE_SERVER

from pki.utils import sld, sli, sln, sle, options
from pki.issue_LE import issue_LE_cert
from pki.issue_local import issue_local_cert

#--------------- Places --------------
places = {}

#--------------- classes --------------

class DBStoreException(Exception):
    pass

class KeyCertException(Exception):
    pass

#---------------  prepared SQL queries for class Certificate  --------------

q_certificate = """
    SELECT c.id, c.type, c.disabled, c.authorized_until, s.type AS subject_type
        FROM Certificates c, Subjects s
        WHERE s.name = $1 AND s.certificate = c.id
"""
q_altnames = """
    SELECT s.name
        FROM Subjects s
        WHERE s.certificate = $1 AND s.isAltName = TRUE
"""
## How can we distinguish prepublished TLSA RRs from others?
q_tlsaprefixes = """
    SELECT s.tlsaprefix
        FROM Certificates_Services cs, Services s
        WHERE cs.certificate = $1 AND cs.service = s.id
"""
q_disthosts = """
    SELECT  d.fqdn, d.jailroot, j.name AS jail_name, p.name AS place_name
        FROM Targets t
            JOIN Disthosts d ON t.disthost = d.id AND t.certificate = $1
            LEFT JOIN Jails j ON t.jail = j.id
            LEFT JOIN Places p ON t.place = p.id
"""
q_instance = """
    SELECT ci.id, ci.cert, ci.key, ci.hash, ca.cert
        FROM CertInstances ci, CertInstances ca
        WHERE
            ci.certificate = $1::INT AND
            ci.not_before <= LOCALTIMESTAMP AND
            ci.not_after >= LOCALTIMESTAMP AND
            ci.CAcert = ca.id
        ORDER BY ci.id DESC
        LIMIT 1
"""
q_specific_instance = """
    SELECT ci.id, ci.cert, ci.key, ci.hash, ca.cert
        FROM CertInstances ci, CertInstances ca
        WHERE
            ci.id = $1::INT AND
            ci.CAcert = ca.id
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

ps_certificate = None
ps_cacert = None
ps_altnames = None
ps_tlsaprefixes = None
ps_disthosts = None
ps_instance = None
ps_specific_instance = None
ps_tlsa_of_instance = None
ps_update_authorized_until = None

        
#--------------- class Certificate --------------

class Certificate(object):
    """
    Certificate meta data class.
    In memory representation of DB backed meta information.
    """
    
    
    def __init__(self, db, name):
        """
        Create a certificate meta data instance
    
        @param db:          open database connection
        @type db:           pki.db.DbConnection instance
        @param name:        subject name of certificate
        @type name:         string
        @rtype:             Certificate instance
        @exceptions:
        DBStoreException, KeyCertException, AssertionError
        """

        global ps_certificate, ps_altnames, ps_tlsaprefixes, ps_disthosts
        global places
        
        self.db = db
        self.name = name

        self.altnames = []
        self.tlsaprefixes = []
        self.disthosts = {}
        
        with self.db.xact(isolation='SERIALIZABLE', mode='READ ONLY'):
            if not ps_certificate:
                db.execute("PREPARE q_certificate(text) AS " + q_certificate)
                ps_certificate = db.statement_from_id('q_certificate')
            self.cert_id, self.cert_type, self.disabled, self.authorized_until,\
                        self.subject_type = ps_certificate.first(name)
            if not self.cert_id:
                sln('Missing cert {} in DB.'.format(name))
                return None
            sld('------ cert {} {}'.format(self.name, 
                        self.cert_type + ' DISABLED' if self.disabled else ''))
            if not ps_altnames:
                db.execute("PREPARE q_altnames(integer) AS " + q_altnames)
                ps_altnames = db.statement_from_id('q_altnames')
            for (name,) in ps_altnames(self.cert_id):
                self.altnames.append(name)
            sld('Altnames: {}'.format(self.altnames))
            
            if not ps_tlsaprefixes:
                db.execute("PREPARE q_tlsaprefixes(integer) AS " + q_tlsaprefixes)
                ps_tlsaprefixes = db.statement_from_id('q_tlsaprefixes')
            for (name,) in ps_tlsaprefixes(self.cert_id):
                self.tlsaprefixes.append(name)
            sld('TLSA prefixes: {}'.format(self.tlsaprefixes))
            
            if not ps_disthosts:
                db.execute("PREPARE q_disthosts(integer) AS " + q_disthosts)
                ps_disthosts = db.statement_from_id('q_disthosts')
            for row in ps_disthosts(self.cert_id):
                ##sld('Disthost row: {}'.format(row))
                if row['fqdn']:    
                    if row['fqdn'] not in self.disthosts:
                        self.disthosts[row['fqdn']] = {    'jails': {}, 'places': {} }
                        if row['jailroot']:
                            self.disthosts[row['fqdn']]['jailroot'] = row['jailroot']
                    dh = self.disthosts[row['fqdn']]
                    if row['jail_name']:
                        if row['jail_name'] not in dh['jails']:
                            dh['jails'][row['jail_name']] = 0
                    if row['place_name']:
                        if row['place_name'] not in dh['places']:
                            if row['place_name'] not in places:
                                p = Place(db,row['place_name'])
                                places[row['place_name']] = p
                            dh['places'][row['place_name']] = places[row['place_name']]
            sld('Disthosts: {}'.format(self.disthosts))
    
    def instance(self, instance_id=None):
        """
        Return certificate, key, TLSA hash and CA certificate of specific
        instance or most recent instance, which is valid today
    
        @param instance_id  id of specific instance id
        @type  instance_id  int
        @rtype:             Tuple of strings
                            (cert, key, TLSA hash and CA cert)
        @exceptions:        none
        """
        
        global ps_instance, ps_specific_instance
        
        if instance_id:
            if not ps_specific_instance:
                ps_specific_instance = self.db.prepare(q_specific_instance)
            result = ps_specific_instance.first(instance_id)
        else:
            if not ps_instance:
                ps_instance = self.db.prepare(q_instance)
            result = ps_instance.first(self.cert_id)
        if result:
            (instance_id, cert_pem, key_pem, TLSA, cacert_pem) = result
            sld('Hash of selected Certinstance is {}'.format(TLSA))

            return (
                instance_id,
                cert_pem.decode('ascii'),
                key_pem.decode('ascii'),
                TLSA,
                cacert_pem.decode('ascii'))
    
    def TLSA_hash(self):
        """
        Return TLSA hash of instance, which is valid today and in prepublish state

        @rtype:             string of TLSA hash
        @exceptions:        none
        """
        global ps_tlsa_of_instance
        
        if not ps_tlsa_of_instance:
            ps_tlsa_of_instance = self.db.prepare(q_tlsa_of_instance)

        (TLSA,) = ps_tlsa_of_instance.first(self.cert_id)
        return TLSA
        
    def create_instance(self):
        """
        Issue a new certificate instance and store it
        in the DB table certinstances.

        @rtype:             bool, true if success
        @exceptions:        none
        """
        
        with self.db.xact(isolation='SERIALIZABLE', mode='READ WRITE'):
            if self.cert_type == 'LE': return issue_LE_cert(self)
            elif self.cert_type == 'local': return issue_local_cert(self)
            else: raise AssertionError
        
    
    def update_authorized_until(self, until):
        """
        Update authorized_until of current Certificates instance.

        @param until:       date and time where LE authrization expires
        @type until:        datetime.datetime instance
        @rtype:             string of TLSA hash
        @exceptions:        none
        """
        global ps_update_authorized_until
        
        if not ps_update_authorized_until:
            ps_update_authorized_until = self.db.prepare(q_update_authorized_until)
    
        (updates) = ps_update_authorized_until.first(
                    self.cert_id,
                    until
        )
        return updates

#---------------  prepared SQL queries for class Place  --------------

q_Place = """
    SELECT  p.cert_file_type, p.cert_path,
                p.key_path, p.uid, p.gid, p.mode, p.chownBoth, p.pgLink, p.reload_command
        FROM Places p
        WHERE p.name = $1
"""

ps_place = None

        
#--------------- class Place --------------

class Place(object):
    """
    Place is a collection of certificate metadata, describing details of
    deployment place. It is unique per service or server software.
    It may be re-used at multiple target hosts.
    Backed up in DB table Places'
    """
    
    def __init__(self, db, name):
        
        global ps_place
        
        self.name = name
        
        if not ps_place:
            ##db.execute("PREPARE q_Place(text) AS " + q_Place)
            ##ps_place = db.statement_from_id('q_Place')
            ps_place = db.prepare(q_Place)
        self.cert_file_type, self.cert_path, self.key_path, self.uid, self.gid,\
            self.mode, self.chownBoth, self.pgLink, self.reload_command = \
            ps_place.first(name)
