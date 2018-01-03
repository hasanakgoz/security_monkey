"""
.. module: security_monkey.auditors.custom.cis.iam_user
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor::  Hammad Hai <hammad.a.hai@gmail.com>

"""
import datetime

from dateutil import parser
from dateutil import tz
from security_monkey.auditor import Categories, Auditor
from security_monkey.watchers.custom.iam_cred_report import CredentialReportWatcher
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


class IAMUserCredsAuditor(Auditor):
    index = CredentialReportWatcher.index
    i_am_singular = CredentialReportWatcher.i_am_singular
    i_am_plural = CredentialReportWatcher.i_am_plural

    DATE_FORMAT = '%Y-%m-%dT%H:%M:%S+00:00'

    def _parse_date(self, datestring):
        epoch = datetime.datetime.fromtimestamp(0)
        return (epoch if (datestring.lower() == 'n/a' or datestring.lower() == 'no_information')
            else datetime.datetime.strptime(datestring, self.DATE_FORMAT))

    def _parse_bool(self, boolstring):
        if boolstring.lower() == 'true':
            return True
        else:
            return False

    def _is_root(self, report):
        return report['arn'].split(':')[-1] == 'root'

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

        report = item.config
        now = datetime.datetime.now()

        if self._is_root(report):

            last_used_date = self._parse_date(report['password_last_used'])
            if (now - last_used_date).days < 1:
                self.add_issue(1, issue, item, notes=notes)
                return

            last_used_date = self._parse_date(report['access_key_1_last_used_date'])
            if (now - last_used_date).days < 1:
                self.add_issue(1, issue, item, notes=notes)
                return

            last_used_date = self._parse_date(report['access_key_2_last_used_date'])
            if (now - last_used_date).days < 1:
                self.add_issue(1, issue, item, notes=notes)
                return

    def check_1_3_unused_credentials(self, item):
        """
        CIS Rule 1.3 - Ensure credentials unused for 90 days or greater are
        disabled [scored]
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-iam-cis-1.3 - ',
            specific='Detected active {} unused for over 90 days.'
        )

        report = item.config
        now = datetime.datetime.now()

        if self._parse_bool(report['password_enabled']):
            pw_last_used = self._parse_date(report['password_last_used'])
            if (now - pw_last_used).days > 90:
                self.add_issue(
                    10,
                    issue,
                    item,
                    notes=notes.format('password')
                )

        if self._parse_bool(report['access_key_1_active']):
            akey1_last_used = self._parse_date(report['access_key_1_last_used_date'])
            if (now - akey1_last_used).days > 90:
                self.add_issue(
                    10,
                    issue,
                    item,
                    notes=notes.format('access key 1')
                )

        if self._parse_bool(report['access_key_2_active']):
            akey2_last_used = self._parse_date(report['access_key_2_last_used_date'])
            if (now - akey2_last_used).days > 90:
                self.add_issue(
                    10,
                    issue,
                    item,
                    notes=notes.format('access key 2')
                )

    def check_1_12_root_key_exists(self, item):
        """
        CIS Rule 1.12 - Ensure no root account access key exists (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-iam-cis-1.12 - ',
            specific='Root account has active access keys.'
        )

        report = item.config

        if self._is_root(report):
            if self._parse_bool(report['access_key_1_active']) or self._parse_bool(report['access_key_2_active']):
                self.add_issue(
                    10,
                    issue,
                    item,
                    notes=notes
                )

    def check_1_13_mfa_root_account(self, item):
        """
        CIS Rule 1.13 - Ensure MFA is enabled on the root account [scored]
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-iam-cis-1.13 - ',
            specific='Root account does not have MFA enabled.'
        )

        report = item.config

        if self._is_root(report):
            if not self._parse_bool(report['mfa_active']):
                self.add_issue(
                    10,
                    issue,
                    item,
                    notes=notes
                )
