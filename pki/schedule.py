"""
utility module of serverPKI
"""
#--------------- imported modules --------------
from datetime import datetime
import optparse
import subprocess
import re
import syslog

from pki.config import Pathes, SSH_CLIENT_USER_NAME


 
#---------------  prepared SQL queries for create/update _local_instance  --------------

q_query_state_and_dates = """
    SELECT id, state, not_before, not_after
        FROM Certinstances
        WHERE certificate = $1
        ORDER BY id
"""

ps_query_state_and_dates = None

def insert_certinstance(db, certificate_id):
    
    global ps_insert_instance
    
    if not ps_insert_instance:
        db.execute("PREPARE q_insert_instance(integer) AS " + q_insert_instance)
        ps_insert_instance = db.statement_from_id('q_insert_instance')
    certinstance_id = ps_insert_instance.first(
                certificate_id
    )
    return certinstance_id


def update_certinstance(db, certinstance_id, cert_pem, key_pem, TLSA_hash,
                                                    not_before, not_after):
    
    global ps_update_instance

    if not ps_update_instance:
        ps_update_instance = db.prepare(q_update_instance)

    (updates) = ps_update_instance.first(
                certinstance_id,
                cert_pem,
                key_pem,
                TLSA_hash,
                not_before,
                not_after
    )
    return updates

def update_state_of_instance(db, certinstance_id, state):
    
    global ps_update_state_of_instance

    if not ps_update_state_of_instance:
        ps_update_state_of_instance = db.prepare(q_update_state_of_instance)

    (updates) = ps_update_state_of_instance.first(
                certinstance_id,
                state,
    )
    return updates
