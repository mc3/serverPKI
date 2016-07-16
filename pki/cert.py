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
import sys
from pathlib import Path
from OpenSSL import crypto,rand,crypto

#--------------- local imports --------------
from pki.config import Pathes, X509atts
from pki.certgen import *
##from pki.certdist import deployCerts
from pki.certstore import store

from pki.utils import sld, sli, sln, sle, options

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
    
    cakey = None
    cacert = None
    cacert_text = ''
    
    
    def __init__(self, db, name):
        
        global ps_certificate, ps_altnames, ps_tlsaprefixes, ps_disthosts
        global places
        
        self.db = db
        self.name = name

        self.altnames = []
        self.tlsaprefixes = []
        self.disthosts = {}
        
        if not ps_certificate:
            db.execute("PREPARE q_certificate(text) AS " + q_certificate)
            ps_certificate = db.statement_from_id('q_certificate')
        self.cert_id, self.cert_type, self.disabled, self.subject_type = \
            ps_certificate.first(name)
        sld('------ cert {} {}'.format(self.name, 
                    self.cert_type + ' DISABLED' if self.disabled else ''))
        if not ps_altnames:
            db.execute("PREPARE q_altnames(integer) AS " + q_altnames)
            ps_altnames = db.statement_from_id('q_altnames')
        for (name,) in ps_altnames(self.cert_id):
            self.altnames.append(name)
        sld('Altnames: '.format(self.altnames))
        
        if not ps_tlsaprefixes:
            db.execute("PREPARE q_tlsaprefixes(integer) AS " + q_tlsaprefixes)
            ps_tlsaprefixes = db.statement_from_id('q_tlsaprefixes')
        for (name,) in ps_tlsaprefixes(self.cert_id):
            self.tlsaprefixes.append(name)
        sld('TLSA prefixes: '.format(self.tlsaprefixes))
        
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
    
    def create_instance(self):
        if self.cert_type == 'LE': return self.create_LE_instance()
        elif self.cert_type == 'local': return self.create_local_instance()
        else: raise AssertionError
        
    def create_LE_instance(self):
        sle('LE type certificates not yet implemented: {}'.format(self.name))
        sys.exit(1)
        
    def create_local_instance(self):
        if not self.get_cacert(): return False
        
        sli('Creating key (%d bits) and cert for %s %s and loading %d bytes of random data...' %
                (int(X509atts.bits), self.subject_type, self.name, int(X509atts.bits)))
        rand.load_file(b'/dev/urandom', X509atts.bits)
        if not rand.status:
            sle('Random device failed to produce enough entropy')
            return False
        pkey = createKeyPair(TYPE_RSA, X509atts.bits)
        name_dict = X509atts.names
        name_dict['CN'] = self.name
        req = createCertRequest(pkey, 'SHA256', name_dict)
        
        serial = Serial()
        my_serial = serial.next()
        alt_names = [self.name, ]
        if len(self.altnames) > 0:
            alt_names.extend(self.altnames)
        cert = createCertificate(req, self.subject_type, self.cacert, self.cakey, my_serial,
                                    0, X509atts.lifetime, alt_names, digest='SHA256')
        
        hostname = self.name[2:] if self.name.startswith('*.') else self.name
        store(hostname, self.subject_type, self.cacert_text, cert, pkey, self)
        
        sli('Cert for %s, serial %d/%x created' % (hostname, my_serial, my_serial))
        return True
        
    def get_cacert(self):
        if not Pathes.ca_cert.exists() or not Pathes.ca_key.exists:

            sln('No CA cert found. Creating one (just for testing - NOT FOR PRODUCTION). . .')
            if not Pathes.ca_serial.exists():
                try:
                    fd = Path.open(Pathes.ca_serial, "w")
                    fd.write(str(0)+'\n')
                except IOError:
                    sle('Could not create serial in db: ' + str(Pathes.ca_serial))
                    sys.exit(1)
                    
            rand.load_file('/dev/urandom', 4096)
            if not rand.status:
                sle('Random device failed to produce enough entropy')
                return False

            self.cakey = createKeyPair(TYPE_RSA, 4096)
            try:
                self.cakey.check()
            except MyException("Couln't create key"):
                sys.exit(1)
                
            self.cacert = crypto.X509()
            self.cacert.set_version(2)         # X509.v3
            
            serial = Serial()
            my_serial = serial.next()
            self.cacert.set_serial_number(my_serial)

            self.cacert.get_subject().commonName = "Authority Certificate for Testing serverPKI"
            self.cacert.set_issuer(self.cacert.get_subject())
            self.cacert.set_pubkey(self.cakey)
            
            self.cacert.gmtime_adj_notBefore(0)
            self.cacert.gmtime_adj_notAfter(60*60*24*365*10) # 10 years

            caext = crypto.X509Extension((b'basicConstraints'), False, (b'CA:true'))
            self.cacert.add_extensions([caext])
            self.cacert.sign(self.cakey, "SHA256")
            
            p = Path(Pathes.ca_key)
            with p.open('wb') as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, self.cakey))
            p.chmod(0o600)
            
            p = Path(Pathes.ca_cert)
            with p.open('wb') as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, self.cacert))
            
            sln('CA cert created for testing.')
            
        try:
            sli('Using CA key at {}'.format(Pathes.ca_key))
            self.cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, Path.open(Pathes.ca_key, 'r').read())
        except Exception:
            sle('Wrong pass phrase')
            return False 
        
        self.cacert = crypto.load_certificate(crypto.FILETYPE_PEM, Path.open(Pathes.ca_cert, 'r').read())
        self.cacert_text = Path.open(Pathes.ca_cert, 'rb').read()
        return True

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
