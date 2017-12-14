"""
.. module: security_monkey.auditors.custom.cis.iam_user
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor::  Patrick Kelley <pkelley@netflix.com> @monkeysecurity

"""
import datetime

from dateutil import parser
from dateutil import tz
from security_monkey.auditor import Categories
from security_monkey.watchers.iam.iam_user import IAMUser
from security_monkey.auditors.iam.iam_policy import IAMPolicyAuditor
from security_monkey.watchers.iam.managed_policy import ManagedPolicy


class CISIAMUserAuditor(IAMPolicyAuditor):
    index = IAMUser.index
    i_am_singular = IAMUser.i_am_singular
    i_am_plural = IAMUser.i_am_plural
    support_auditor_indexes = [ManagedPolicy.index]

    def __init__(self, accounts=None, debug=False):
        super(CISIAMUserAuditor, self).__init__(accounts=accounts, debug=debug)
        self.iam_policy_keys = ['InlinePolicies$*']

    def check_1_1_root_user(self, item):
        """
        CIS Rule 1.1 - Avoid the use of the "root" account [scored]

        alert when root user has been used within last 24 hours
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-iam-cis-1.1 - ',
            specific='Root Account used in past 24hrs.'
        )
        one_day_ago = datetime.datetime.now() - datetime.timedelta(hours=24)
        one_day_ago = one_day_ago.replace(tzinfo=tz.gettz('UTC'))

        date_format = "%Y-%m-%d %H:%M:%S+00:00"

        if item.config.get('Arn', '').split(':')[-1] == 'root':

            last_used_date = \
                item.config.get('PasswordLastUsed') or item.config.get('CreateDate')
            last_used_date = parser.parse(last_used_date)

            if last_used_date > one_day_ago:
                self.add_issue(1, issue, item, notes=notes)
                return

            for akey in item.config.get('AccessKeys', []):
                last_used_date = akey.get('LastUsedDate') or akey.get('CreateDate')
                last_used_date = parser.parse(last_used_date)

                if last_used_date > one_day_ago:
                    self.add_issue(10, issue, item, notes=notes)
                    return
