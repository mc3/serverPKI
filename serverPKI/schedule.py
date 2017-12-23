"""
Copyright (C) 2015-2017  Axel Rau <axel.rau@chaos1.de>

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

# schedule module of serverPKI

#--------------- imported modules --------------
from datetime import datetime, timedelta, date
from email.mime.text import MIMEText
import optparse
import subprocess
import re
import syslog
import smtplib
import sys

from functools import total_ordering

from serverPKI.config import Pathes, SSH_CLIENT_USER_NAME, PRE_PUBLISH_TIMEDELTA
from serverPKI.config import LOCAL_ISSUE_MAIL_TIMEDELTA
from serverPKI.config import MAIL_RELAY, MAIL_SENDER, MAIL_RECIPIENT
from serverPKI.cert import Certificate
from serverPKI.certdist import deployCerts, distribute_tlsa_rrs
from serverPKI.issue_LE import issue_LE_cert
from serverPKI.utils import sld, sli, sln, sle
from serverPKI.utils import shortDateTime, update_state_of_instance
from serverPKI.utils import options as opts

#---------------  prepared SQL queries for query instances  --------------

q_query_state_and_dates = """
    SELECT id, state, not_before, not_after
        FROM Certinstances
        WHERE certificate = $1
        ORDER BY id
"""

ps_query_state_and_dates = None

q_delete = """
    DELETE FROM Certinstances
        WHERE id = $1
"""

ps_delete = None

to_be_deleted = set()
to_be_mailed = []

#---------------  public functions  --------------

def scheduleCerts(db, cert_names):

    """
    Schedule and perform actions dependant on state and validity.
    
    @param db:          open database connection in readwrite transaction
    @type db:           serverPKI.db.DbConnection instance
    @param cert_names:  list of certificate subject names
    @type cert_names:   list of str
    @rtype:             None
    @exceptions:
    """

    global ps_delete, to_be_deleted

    def issue(cert_meta):
        if cert_meta.cert_type == 'local':
            return None
        if opts.check_only:
            sld('Would issue {}.'.format(cert_meta.name))
            return
        if not cert_meta.disabled:
            sli('Requesting issue from LE for {}'.format(cert_meta.name))
            return issue_LE_cert(cert_meta)
            
    def prepublish(cert_meta, active_i, new_i):
        if opts.check_only:
            sld('Would prepublish {} {}.'.format(active_i.id, new_i.id))
            return
        active_TLSA = cert_meta.TLSA_hash(active_i.id)
        prepublishing_TLSA = cert_meta.TLSA_hash(new_i.id)
        sli('Prepublishing {}:{}:{}'.
                                format(cert_meta.name, active_i.id, new_i.id))
        distribute_tlsa_rrs(cert_meta, active_TLSA, prepublishing_TLSA)
        update_state_of_instance(cert_meta.db, new_i.id, 'prepublished')
            
    def distribute(cert_meta, id, state):
        if opts.check_only:
            sld('Would distribute {}.'.format(id))
            return
        sli('Distributing {}:{}'.
                                format(cert_meta.name, id))
        cm_dict = {cert_meta.name: cert_meta}
        try:
            deployCerts(cm_dict, id, allowed_states=(state, ))
        except Exception:
            sln('Skipping distribution of cert {} because {} [{}]'.format(
                                            cert_meta.name,
                                            sys.exc_info()[0].__name__,
                                            str(sys.exc_info()[1])))
               
    def expire(cert_meta, i):
        if opts.check_only:
            sld('Would expire {}.'.format(i.id))
            return
        sli('State transition from {} to EXPIRED of {}:{}'.
                                format(i.state, cert_meta.name, i.id))
        update_state_of_instance(cert_meta.db, i.id, 'expired')
        
    def archive(cert_meta, i):
        if opts.check_only:
            sld('Would archive {}.'.format(i.id))
            return
        sli('State transition from {} to ARCHIVED of {}:{}'.
                                format(i.state, cert_meta.name, i.id))
        update_state_of_instance(cert_meta.db, i.id, 'archived')
        
    
    for name in cert_names:

        cert_meta = Certificate(db, name)
        sld('{} {} ------------------------------'.format(
                                        name,
                                        'DISABLED' if cert_meta.disabled else ''))
        if cert_meta.subject_type == 'CA': continue

        issued_i = None
        prepublished_i = None
        deployed_i = None
        
        surviving = _find_to_be_deleted(cert_meta)

        if not surviving:
            id = issue(cert_meta)
            if id: distribute(cert_meta, id, 'issued')
            continue
        
        for i in surviving:
            if i.state == 'expired':
                archive(cert_meta, i)
                continue
            if datetime.utcnow() >= (i.not_after + timedelta(days=1)):
                if i.state != 'deployed':
                    expire(cert_meta, i)
                continue
            elif i.state == 'issued': issued_i = i
            elif i.state == 'prepublished': prepublished_i = i
            elif i.state == 'deployed': deployed_i = i
            else: assert(i.state in ('issued', 'prepublished', 'deployed', ))
            
        if deployed_i and issued_i: # issued too old to replace deployed in future?
            if issued_i.not_after < ( deployed_i.not_after +
                                        LOCAL_ISSUE_MAIL_TIMEDELTA):
                to_be_deleted |= set((issued_i,))   # yes: mark for delete
                issued_i = None
                                    # request issue_mail if near to expiration
        if (deployed_i
            and cert_meta.cert_type == 'local' 
            and not cert_meta.authorized_until
            and datetime.utcnow() >= (deployed_i.not_after - 
                                            LOCAL_ISSUE_MAIL_TIMEDELTA)):
            to_be_mailed.append(cert_meta)
            sld('schedule.to_be_mailed: ' + str(cert_meta))

        if cert_meta.disabled:
            continue
            
                                    # deployed cert expired or no cert deployed?
        if (not deployed_i) or \
                (datetime.utcnow() >= deployed_i.not_after - timedelta(days=1)):
            distributed = False
            sld('scheduleCerts: no deployed cert or deployed cert '
                            'expired {}'.format(str(deployed_i)))
            if prepublished_i:      # yes - distribute prepublished
                distribute(cert_meta, prepublished_i.id, 'prepublished')
                distributed = True
            elif issued_i:          # or issued cert?
                distribute(cert_meta, issued_i.id, 'issued') # yes - distribute it
                distributed = True
            if deployed_i:
                expire(cert_meta, deployed_i)  # and expire deployed cert
            if not distributed:
                id = issue(cert_meta)
                if id: distribute(cert_meta, id, 'issued')
            continue
        
        if cert_meta.cert_type == 'local':
            continue                # no TLSAs with local certs
                                    # We have an active LE cert deployed
        if datetime.utcnow() >= \
            (deployed_i.not_after - PRE_PUBLISH_TIMEDELTA):
                                    # pre-publishtime reached?
            i = issued_i
            if prepublished_i:      # yes: TLSA already pre-published?
                continue            # yes
            elif not issued_i:      # do we have a cert handy?
                id = issue(cert_meta) # no: create one
                if not id:
                    sln('Failed to issue cert for prepublishing of {}'.format(cert_meta.name))
                    continue
                i = CertInstance(id, None, None, None)
            sld('scheduleCerts will call prepublish with deployed_i={}, i={}'.format(
                                str(deployed_i), str(i)))
            prepublish(cert_meta, deployed_i, i) # and prepublish it                
    
    # end for name in cert_names
    
    if opts.check_only:
        sld('Would delete and mail..')
        return
    if not ps_delete:
        ps_delete = db.prepare(q_delete)
    for i in to_be_deleted:
        sld('Deleting {}'.format(i.id))
        result = ps_delete.first(i.id)
        if result != 1:
            sln('Failed to delete cert instance {}'.format(i.id))

    if to_be_mailed:
        
        body = str('Following local Certificates must be issued prior to {}:\n'.
            format(date.today()+LOCAL_ISSUE_MAIL_TIMEDELTA))
            
        for cert_meta in to_be_mailed:
            body += str('\t{} \t{}'.format(cert_meta.name,
                                '[DISABLED]' if cert_meta.disabled else ''))
            cert_meta.update_authorized_until(datetime.utcnow())
        
        msg = MIMEText(body)
        msg['Subject'] = 'Local certificate issue reminder'
        msg['From'] = MAIL_SENDER
        msg['To'] = MAIL_RECIPIENT
        s = smtplib.SMTP(MAIL_RELAY)
        s.send_message(msg)
        s.quit()

        
#---------------  private functions  --------------

def _find_to_be_deleted(cert_meta):
    """
    Find out which rows in relation CertInstances should be deleted.
    
    @param cert_meta:       Cert meta instance to issue an certificate for
    @type cert_meta:        Cert meta instance
    @global to_be_deleted   List of cert instance row ids to be deleted
    @rtype:                 set of int (to_be_deleted): ids of rows to be deleted
    @exceptions:            DBStoreException
    """

    global ps_query_state_and_dates, to_be_deleted
    
    if not ps_query_state_and_dates:
        ps_query_state_and_dates = cert_meta.db.prepare(q_query_state_and_dates)
    
    surviving = set()
    rows = ps_query_state_and_dates(cert_meta.cert_id)
    
    if len(rows) == 0: return None
    for row in rows:
 
        id, state, not_before, not_after = row
        sld('{:04} Issued {}, expires: {}, state {}\t{}'.format(
                                                id,
                                                shortDateTime(not_before),
                                                shortDateTime(not_after),
                                                state,
                                                cert_meta.name)
        )
        
        i = CertInstance(id, state, not_before, not_after)
        
        if state in ('reserved', 'archived'):
            to_be_deleted.add(i)
        else:
            surviving.add(i)
        
    sld('Before state loop: ' + str([i.__str__() for i in surviving]))
    for state in ('issued', 'prepublished', 'deployed', 'expired',):
        i_list = []
        for i in surviving:
            if i.state == state:
                i_list.append(i)
        i_list.sort()
        s = set(i_list[:-1])    # most recent instance survives
        surviving -= s          # remove other instances from surviving set
        to_be_deleted |= s      # add other instances to to_be_deleted set
        sld('{}: {}'.format(state, str([i.__str__() for i in i_list])))
     
    sld('to_be_deleted : {}'.format(str([i.__str__() for i in to_be_deleted])))
    sld('surviving : {}'.format(str([i.__str__() for i in surviving])))
    sld('---------------------------------------------------------------')
    
    return surviving

    

#---------------  private classes  --------------

@total_ordering
class CertInstance(object):
    """
    Little container for cert instance attributes
    
    """
    
    def __init__(self, id, state, not_before, not_after):
    
        self.id = id
        self.state = state
        self.not_before = not_before
        self.not_after = not_after

    def __str__(self):
        return str(self.id)

    def __eq__(self, other):
        return self.id == other.id

    def __lt__(self, other):
        return self.id < other.id
        
    def __hash__(self):
        return self.id
    
    