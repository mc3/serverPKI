"""
schedule module of serverPKI
"""
#--------------- imported modules --------------
from datetime import datetime, timedelta
import optparse
import subprocess
import re
import syslog
from functools import total_ordering

from pki.config import Pathes, SSH_CLIENT_USER_NAME, PRE_PUBLISH_TIMEDELTA
from pki.cert import Certificate
from pki.certdist import deployCerts
from pki.issue_LE import issue_LE_cert
from pki.utils import sld, sli, sln, sle, options
from pki.utils import shortDateTime, update_state_of_instance
 
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

    def issue(cert_meta):
        if cert_meta.cert_type == 'local':
            sli('Would mail to request local issue for {}'.format(name))
        elif not cert_meta.disabled:
            sli('Would request issue from LE for {}'.format(name))
            return
            return issue_LE_cert(cert_meta)
            
    def prepublish(cert_meta, active_i, new_i):
        active_TLSA = TLSA_hash(active_i.id)
        prepublishing_TLSA = TLSA_hash(new_i.id)
        sli('{}:{}:{} would prepublish'.
                                format(active_i.id, new_i.id, cert_meta.name))
        return
        distribute_tlsa_rrs(cert_meta, active_TLSA, prepublishing_TLSA)
        update_state_of_instance(cert_meta.db, new_i.id, 'prepublished')
            
    def distribute(cert_meta, id):
        sli('{}:{} would distribute'.
                                format(id, cert_meta.name))
        return
        cm_dict = {cert_meta.name: cert_meta}
        deployCerts(cm_dict, id)
            
    def expire(cert_meta, i):
        sli('{}:{} would transition from {} to EXPIRED'.
                                format(i.id, cert_meta.name, i.state))
        return
        update_state_of_instance(cert_meta.db, i.id, 'expired')
        
    
    for name in cert_names:
        cert_meta = Certificate(db, name)
        
        issued_i = None
        prepublished_i = None
        deployed_i = None
        
        surviving = find_to_be_deleted(cert_meta)

        if not surviving:
            id = issue(cert_meta)
            distribute(cert_meta, id)
            continue
        
        for i in surviving:
            if i.state == 'expired':
                sli('Would transition from EXPIRED to ARCHIVED: {}'.
                                                        format(i.id, name))
                i.state = 'archived'
                continue
            if datetime.utcnow() - timedelta(days=1) >= i.not_after:
                if i.state != 'deployed':
                    expire(i)
                continue
            elif i.state == 'issued': issued_i = i
            elif i.state == 'prepublished': prepublished_i = i
            elif i.state == 'deployed': deployed_i = i
            else: assert(i.state in ('issued', 'prepublished', 'deployed', ))
                                    # deployed cert expired or no cert deployed?
        if not deployed_i or \
                (datetime.utcnow() - timedelta(days=1)) >= \
                                                        deployed_i.not_after:
            if prepublished_i:      # yes - distribute prepublished
                distribute(cert_meta, prepublished_i.id)
            elif issued_i:          # or issued cert
                distribute(cert_meta, issued_i.id)
            if deployed_i:
                expire(deployed_i)  # and expire deployed cert
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
                i = issue(cert_meta) # no: create one
            prepublish(cert_meta, deployed_i, i) # and prepublish it                
    
    if not ps_delete:
        ps_delete = db.prepare(q_delete)
    for i in to_be_deleted:
        sli('Would delete {}'.format(i.id))
        continue
        result = ps_delete(i.id)
        if result != 1:
            sln('Failed to delete cert instance {}'.format(i.id))

                
#---------------  private functions  --------------

def find_to_be_deleted(cert_meta):

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
    
    