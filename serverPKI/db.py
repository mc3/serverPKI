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

# serverpki db primitives module
# requires python 3.4.

#--------------- imported modules --------------

import sys

##import postgresql as pg
from postgresql import open as pg_open
from postgresql import alock
from postgresql import exceptions

#--------------- local imports --------------
import pki.config as conf
from pki.utils import sld, sli, sln, sle

#--------------- db classes --------------
class DbConnection(object):
    'dbConnection'
    def __init__(self, service):
        """
        Create a DbConnection instance
    
        @param service:     service name
        @type service:      string
        @rtype:             DbConnection instance
        @exceptions:        None, but does a exit(1) if connection can't be
                            established
        """
        if service not in ('pki_dev'):
            sle('Config error: dbAccounts must be "pki"')
            sys.exit(0)
        
        self.conn = None
        self.sslcrtfile = None
        try:
            self.host           = conf.dbAccounts[service]['dbHost']
            self.port           = conf.dbAccounts[service]['dbPort']
            self.user           = conf.dbAccounts[service]['dbUser']
            self.database       = conf.dbAccounts[service]['dbDatabase']
            self.search_path    = conf.dbAccounts[service]['dbSearchPath']
            
            self.dsn = str('host='+self.host+', port='+self.port+
                ', user='+self.user+', database='+self.database+', sslmode='+'"require"')
            
            if 'dbCert' in conf.dbAccounts[service]:            
                self.sslcrtfile = conf.dbAccounts[service]['dbCert']
                self.sslkeyfile = conf.dbAccounts[service]['dbCertKey']
                self.dsn = self.dsn + str(', sslcrtfile={}, sslkeyfile={}'.format(self.sslcrtfile, self.sslkeyfile))
        except:
            sle('Config error: Missing or wrong keyword in dbAccounts.\n' +
                                    'Must be dbHost, dbPort, dbUser, dbDatabase and dbSearchPath.')
            sys.exit(1)
    
    def open(self):
        """
        Open the connection to the DB server
    
        @rtype:             DbConnection instance with state 'opened'
        @exceptions:        None, but does a exit(1) if connection can't be
                            established
        """
        if not self.conn:
            try:
                if self.sslcrtfile == None:
                    self.conn = pg_open(host=self.host, port=self.port, user=self.user, database=self.database,
                        sslmode="require")
                else:
                    self.conn = pg_open(host=self.host, port=self.port, user=self.user, database=self.database,
                        sslmode="require", sslcrtfile=self.sslcrtfile, sslkeyfile=self.sslkeyfile)
                self.conn.settings['search_path']=self.search_path
                
            except:
                sle('Unable to connect to database %s' % ( self.dsn ))
                sys.exit(1)
        
        return self.conn
    
    def acquire_lock(self, locking_code):
        """
        Try to obtain an advisory lock in the DB, but do not block if lock
        can't be acquired.
    
        @param locking_code:    name of the lock
        @type locking_code:     string
        @rtype:                 True if lock acquired, False otherwise
        """
        if not self.conn:
            self.open()
        self.lock = alock.ExclusiveLock(self.conn, (0, locking_code))
        if not self.lock.acquire(blocking = False):
            return False
        return True
    
    def unlock(self):
        """
        Release an advisary lock, if one there.
    
        @rtype:                 None
        """
        self.lock.release()

