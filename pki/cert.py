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

#--------------- local imports --------------
from pki.utils import sli, sln, sle, options

#--------------- Places --------------
places = {}

#--------------- classes --------------

class MyException(Exception):
    pass

#---------------  prepared SQL queries for class Certificate  --------------

q_certificate = """
    SELECT c.id, c.type, c.disabled, s.type AS subject_type
        FROM Certificates c, Subjects s
        WHERE s.name = $1 AND s.certificate = c.id
"""
q_altnames = """
    SELECT s.name
        FROM Subjects s
        WHERE s.certificate = $1 AND s.isAltName = TRUE
"""
## Needing one TLSA RR per altname
## relationship of altname to zone directory **TBD**
## certstore.store_TLSAs currently assumes all hosted domains have 2 tags
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

ps_certificate = None
ps_altnames = None
ps_tlsaprefixes = None
ps_disthosts = None

        
#--------------- class Certificate --------------

class Certificate(object):
    'Certificate'
    
    
    def __init__(self, db, name):
        
        global ps_certificate, ps_altnames, ps_tlsaprefixes, ps_disthosts
        global places
        
        self.altnames = []
        self.tlsaprefixes = []
        self.disthosts = {}
        
        if not ps_certificate:
            db.execute("PREPARE q_certificate(text) AS " + q_certificate)
            ps_certificate = db.statement_from_id('q_certificate')
        self.cert_id, self.cert_type, self.disabled, self.subject_type = \
            ps_certificate.first(name)
        self.name = name
        if options.debug: print('------ cert {} {}'.format(self.name, 
                    self.cert_type + ' DISABLED' if self.disabled else ''))
        if not ps_altnames:
            db.execute("PREPARE q_altnames(integer) AS " + q_altnames)
            ps_altnames = db.statement_from_id('q_altnames')
        for (name,) in ps_altnames(self.cert_id):
            self.altnames.append(name)
        if options.debug: print('Altnames: '.format(self.altnames))
        
        if not ps_tlsaprefixes:
            db.execute("PREPARE q_tlsaprefixes(integer) AS " + q_tlsaprefixes)
            ps_tlsaprefixes = db.statement_from_id('q_tlsaprefixes')
        for (name,) in ps_tlsaprefixes(self.cert_id):
            self.tlsaprefixes.append(name)
        if options.debug: print('TLSA prefixes: '.format(self.tlsaprefixes))
        
        if not ps_disthosts:
            db.execute("PREPARE q_disthosts(integer) AS " + q_disthosts)
            ps_disthosts = db.statement_from_id('q_disthosts')
        for row in ps_disthosts(self.cert_id):
            ##if options.debug: print('Disthost row: {}'.format(row))
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
        if options.debug: print('Disthosts: {}'.format(self.disthosts))



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
    'Place'
    
    
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
        if not self.cert_file_type:
            MyException('Place {} does not exist'.format(name))
