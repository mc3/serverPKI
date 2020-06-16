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

# schedule module of serverPKI

# --------------- imported modules --------------
from datetime import datetime, timedelta, date
from email.mime.text import MIMEText
import smtplib
import sys
from typing import Optional, Dict

from postgresql import driver as db_conn

import serverPKI.cert as cert

from serverPKI.certdist import deployCerts, distribute_tlsa_rrs
from serverPKI.issue_LE import issue_LE_cert
from serverPKI.utils import sld, sli, sln, sle, get_config
from serverPKI.utils import shortDateTime, get_options

to_be_deleted = set()
to_be_mailed = []

# ------------------- public ENUMS ------------------
from enum import Enum, unique, auto


@unique
class Action(Enum):
    issue = auto()
    prepublish = auto()
    distribute = auto()
    expire = auto()
    archive = auto()
    delete = auto()


ma = Action.distribute


# ---------------  public functions  --------------

def scheduleCerts(db: db_conn, cert_metas: Dict[str, cert.Certificate]) -> None:
    """
    Schedule state transitions and do related actions of CertInstances
    :param db: Open Database connection
    :param cert_metas: list of Cerificate instances to act on
    :return:
    """

    global ps_delete, to_be_deleted

    (DBAccount, Misc, Pathes, X509atts) = get_config()
    opts = get_options()

    def issue(cm: cert.Certificate) -> Optional[cert.CertInstance]:
        """
        If cert type is 'LE', issue a Letsencrypt cert
        :param cm: cert meta
        :return: ci of new cert or None
        """
        if cm.cert_type == cert.CertType('local'):
            return None
        if opts.check_only:
            sld('Would issue {}.'.format(cm.name))
            return
        if not cm.disabled:
            sli('Requesting issue from LE for {}'.format(cm.name))
            return issue_LE_cert(cm)

    def prepublish(cm: cert.Certificate, active_ci: cert.CertInstance, new_ci: cert.CertInstance) -> None:
        """
        Prepublish cert hashes per TLSA RRs in DNS
        :param cm: Our cert meta data instance
        :param active_ci: CertInstance currently in use
        :param new_ci: CertInstance just created but not yet deployed
        :return:
        """
        if opts.check_only:
            sld('Would prepublish {} {}.'.format(active_ci.row_id, new_ci.row_id))
            return
        # collect hashes for all certs in all algos
        hashes = tuple(cm.TLSA_hashes(active_ci).values()) + tuple(cm.TLSA_hashes(new_ci).values())
        sli('Prepublishing {}:{}:{}'.
            format(cm.name, active_ci.row_id, new_ci.row_id))
        distribute_tlsa_rrs(cm, hashes)
        new_ci.state = cert.CertState('prepublished')
        cm.save_instance(new_ci)

    def distribute(cm: cert.Certificate, ci: cert.CertInstance, state: cert.CertState):
        if opts.check_only:
            sld('Would distribute {}.'.format(ci.row_id))
            return
        sli('Distributing {}:{}'.
            format(cm.name, ci.row_id))
        cm_dict = {cm.name: cm}
        try:
            deployCerts(cm_dict, (ci,), allowed_states=(state,))
        except Exception:
            sln('Skipping distribution of cert {} because {} [{}]'.format(
                cm.name,
                sys.exc_info()[0].__name__,
                str(sys.exc_info()[1])))

    def expire(cm, ci):
        if opts.check_only:
            sld('Would expire {}.'.format(ci.row_id))
            return
        sli('State transition from {} to EXPIRED of {}:{}'.
            format(ci.state, cm.name, ci.row_id))
        ci.state = cert.CertState('expired')
        cm.save_instance(ci)

    def archive(cm, ci):
        if opts.check_only:
            sld('Would archive {}.'.format(ci.row_id))
            return
        sli('State transition from {} to ARCHIVED of {}:{}'.
            format(ci.state, cm.name, ci.row_id))
        ci.state = cert.CertState('archived')
        cm.save_instance(ci)

    for cm in cert_metas.values():

        sld('{} {} ------------------------------'.format(
            cm.name,
            'DISABLED' if cm.disabled else ''))
        if cm.subject_type in (cert.SubjectType('CA'),cert.SubjectType('reserved')): continue

        issued_ci = None
        prepublished_ci = None
        deployed_ci = None

        surviving = _find_to_be_deleted(cm)

        if not surviving:
            ci = issue(cm)
            if ci: distribute(cm, ci, cert.CertState('issued'))
            continue

        for ci in surviving:
            if ci.state == cert.CertState('expired'):
                archive(cm, ci)
                continue
            if datetime.utcnow() >= (ci.not_after + timedelta(days=1)):
                if ci.state != cert.CertState('deployed'):
                    expire(cm, ci)
                continue
            elif ci.state == cert.CertState('issued'):
                issued_ci = ci
            elif ci.state == cert.CertState('prepublished'):
                prepublished_ci = ci
            elif ci.state == cert.CertState('deployed'):
                deployed_ci = ci
            else:
                assert (ci.state in (cert.CertState('issued'), cert.CertState('prepublished'), cert.CertState('deployed'),))

        if deployed_ci and issued_ci:  # issued too old to replace deployed in future?
            if issued_ci.not_after < (deployed_ci.not_after +
                                      timedelta(days=Misc.LOCAL_ISSUE_MAIL_TIMEDELTA)):
                to_be_deleted |= set((issued_ci,))  # yes: mark for delete
                issued_ci = None
                # request issue_mail if near to expiration
        if (deployed_ci
                and cm.cert_type == 'local'
                and not cm.authorized_until
                and datetime.utcnow() >= (deployed_ci.not_after -
                                          timedelta(days=Misc.LOCAL_ISSUE_MAIL_TIMEDELTA))):
            to_be_mailed.append(cm)
            sld('schedule.to_be_mailed: ' + str(cm))

        if cm.disabled:
            continue

        # deployed cert expired or no cert deployed?
        if (not deployed_ci) or \
                (datetime.utcnow() >= deployed_ci.not_after - timedelta(days=1)):
            distributed = False
            sld('scheduleCerts: no deployed cert or deployed cert'
                'expired {}'.format(str(deployed_ci)))
            if prepublished_ci:  # yes - distribute prepublished
                distribute(cm, prepublished_ci, cert.CertState('prepublished'))
                distributed = True
            elif issued_ci:  # or issued cert?
                distribute(cm, issued_ci, cert.CertState('issued'))  # yes - distribute it
                distributed = True
            if deployed_ci:
                expire(cm, deployed_ci)  # and expire deployed cert
            if not distributed:
                ci = issue(cm)
                if ci: distribute(cm, ci, cert.CertState('issued'))
            continue

        if cm.cert_type == 'local':
            continue  # no TLSAs with local certs
            # We have an active LE cert deployed
        if datetime.utcnow() >= \
                (deployed_ci.not_after - timedelta(days=Misc.PRE_PUBLISH_TIMEDELTA)):
            # pre-publishtime reached?
            ci = issued_ci
            if prepublished_ci:  # yes: TLSA already pre-published?
                continue  # yes
            elif not issued_ci:  # do we have a cert handy?
                ci = issue(cm)  # no: create one
                if not ci:
                    sln('Failed to issue cert for prepublishing of {}'.format(cm.name))
                    continue
            sld('scheduleCerts will call prepublish with deployed_ci={}, ci={}'.format(
                str(deployed_ci), str(ci)))
            prepublish(cm, deployed_ci, ci)  # and prepublish it

    # end for name in cert_names

    if opts.check_only:
        sld('Would delete and mail..')
        return
    for ci in to_be_deleted:
        sld('Deleting {}'.format(ci.row_id))
        result = ci.cm.delete_instance(ci)
        if result != 1:
            sln('Failed to delete cert instance {}'.format(ci.row_id))

    if to_be_mailed:

        body = str('Following local Certificates must be issued prior to {}:\n'.
                   format(date.today() + timedelta(days=Misc.LOCAL_ISSUE_MAIL_TIMEDELTA)))

        for cert_meta in to_be_mailed:
            body += str('\t{} \t{}'.format(cert_meta.name,
                                           '[DISABLED]' if cert_meta.disabled else ''))
            cert_meta.update_authorized_until(datetime.utcnow())

        msg = MIMEText(body)
        msg['Subject'] = 'Local certificate issue reminder'
        msg['From'] = Misc.MAIL_SENDER
        msg['To'] = Misc.MAIL_RECIPIENT
        s = smtplib.SMTP(Misc.MAIL_RELAY)
        s.send_message(msg)
        s.quit()


# ---------------  private functions  --------------

def _find_to_be_deleted(cm: cert.Certificate) -> Optional[set]:
    """
    Create set of CertInstances to be deleted.
    Keep most recent active Certinstance in state prepublished and deployed.
    If only active in state issued and expired, keep theese.
    :param cm: Certificate to act on
    :return: Set of Certinstances to be deleted
    """
    global to_be_deleted
    surviving = set()

    if not cm.cert_instances: return None
    for ci in cm.cert_instances:
        sld('{:04} Issued {}, expires: {}, state {}\t{}'.format(
            ci.row_id,
            shortDateTime(ci.not_before),
            shortDateTime(ci.not_after),
            ci.state,
            cm.name)
        )

        if ci.state in (cert.CertState('reserved'), cert.CertState('archived')):
            to_be_deleted.add(ci)
        else:
            surviving.add(ci)

    sld('Before state loop: ' + str([i.__str__() for i in surviving]))
    for state in (cert.CertState('issued'), cert.CertState('prepublished'), cert.CertState('deployed'), cert.CertState('expired')):
        ci_list = []
        for ci in surviving:
            if ci.state == state:
                ci_list.append(ci)
        if not ci_list:
            continue
        # only the most recent (with highest row_id) survives from current state set
        sorted_list = sorted(ci_list, key=lambda ci: ci.row_id)
        to_be_added_to_be_deleted = set(sorted_list[:-1])   # all but last to be deleted
        to_be_deleted.update(to_be_added_to_be_deleted)     # add to to_be_deleted set
        surviving = surviving - to_be_added_to_be_deleted   # remove from surviving set
        sld('{} surviving in state {}'.format(sorted_list[-1].row_id, state))
        sld('to_be_deleted now: {}'.format(str([i.__str__() for i in to_be_deleted])))
        sld('surviving now: {}'.format(str([i.__str__() for i in surviving])))

    sld('---------------------------------------------------------------')

    return surviving
