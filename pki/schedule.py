"""
schedule module of serverPKI
"""
#--------------- imported modules --------------
from datetime import datetime
import optparse
import subprocess
import re
import syslog
from functools import total_ordering

from pki.config import Pathes, SSH_CLIENT_USER_NAME
from pki.cert import Certificate
from pki.utils import sld, sli, sln, sle, options
from pki.utils import shortDateTime
 
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


#---------------  public functions  --------------

def scheduleCerts(db, cert_names):

    global ps_delete, to_be_deleted

    if not ps_delete:
        ps_delete = db.prepare(q_delete)


    for name in cert_names:
        cert_meta = Certificate(db, name)
        
        issued_i = None
        deployed_i = None
        
        surviving = find_to_be_deleted(cert_meta)

        if not surviving:
            if cert_meta.cert_type == 'local':
                sli('Would mail to request local issue for {}'.format(name))
            elif not cert_meta.disabled:
                sli('Would request issue from LE for {}'.format(name))
            continue
        
        for i in surviving:
            if i.state == 'expired':
                sli('Would transition from expired to archived: {}'.format(name))
                continue
            elif i.state == 'issued': issued_i = i
            elif i.state == 'deployed': deployed_i = i
            else: assert(i.state in ('issued', 'deployed', ))
         
                
#---------------  private functions  --------------

def find_to_be_deleted(cert_meta):

    global ps_query_state_and_dates, to_be_deleted
    
    if not ps_query_state_and_dates:
        ps_query_state_and_dates = cert_meta.db.prepare(q_query_state_and_dates)
    
    all = set()
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
            all.add(i)
        
    sld('Before state loop: ' + str([i.__str__() for i in all]))
    for state in ('issued', 'deployed', 'expired',):
        i_list = []
        for i in all:
            if i.state == state:
                i_list.append(i)
        i_list.sort()
        s = set(i_list[:-1])
        all -= s
        to_be_deleted |= s
        sld('{}: {}'.format(state, str([i.__str__() for i in i_list])))
     
    sld('to_be_deleted : {}'.format(str([i.__str__() for i in to_be_deleted])))
    sld('all : {}'.format(str([i.__str__() for i in all])))
    sld('---------------------------------------------------------------')
    
    return all

#---------------  private classes  --------------

@total_ordering
class CertInstance(object):
    """
    
    
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
    
    