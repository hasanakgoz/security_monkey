"""
.. module: security_monkey.auditors.custom.cis.iam_user
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor::  Hammad Hai <hammad.a.hai@gmail.com>
.. @pritam update CIS v1.2.0 compliance
"""
import datetime
import re

from dateutil import parser
from dateutil import tz

from security_monkey.auditor import Categories, Auditor
from security_monkey.auditors.iam.iam_policy import IAMPolicyAuditor
from security_monkey.watchers.custom.iam_cred_report import CredentialReportWatcher
from security_monkey.watchers.iam.iam_user import IAMUser
from security_monkey.watchers.iam.managed_policy import ManagedPolicy


class CISIAMUserAuditor(IAMPolicyAuditor):
    index = IAMUser.index
    i_am_singular = IAMUser.i_am_singular
    i_am_plural = IAMUser.i_am_plural
    support_auditor_indexes = [ManagedPolicy.index]

    def __init__(self, accounts=None, debug=False):
        super(CISIAMUserAuditor, self).__init__(accounts=accounts, debug=debug)
        self.iam_policy_keys = ['InlinePolicies$*']

    def check_1_14_root_hardware_mfa_enabled(self, item):
        """
        CIS Rule 1.14 - Ensure hardware MFA is enabled on the root account [scored]
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-iam-cis-1.14 - ',
            specific='Root account not using hardware MFA.'
        )

        report = item.config

        if item.config.get('Arn', '').split(':')[-1] == 'root':
            user_mfas = item.config.get('MfaDevices', {})

            for key, value in user_mfas.iteritems():
                serial = value.get('SerialNumber', '')
                if "mfa/root-account-mfa-device" in serial:
                    self.add_issue(10, issue, item, notes=notes)
                    return

    def check_1_16_no_inline_policies(self, item):
        """
        CIS Rule 1.16 - Ensure IAM policies are attached only to groups or roles [scored]
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-iam-cis-1.16 - ',
            specific='IAM user has inline policy attached.'
        )

        report = item.config
        if report['InlinePolicies']:
            self.add_issue(10, issue, item, notes=notes)


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
        issue = "root Account Access"
        notes = 'sa-iam-cis-1.1 - root account using {method} has been used in last 24 hours. The "root" account ' \
                'is the most privileged AWS account. Minimizing the use of this account and ' \ 
                'adopting the principle of least privilege for access management will reduce the risk of accidental ' \
                'changes and unintended disclosure of highly privileged credentials. '
        action_instructions = 'There are a few conditions under which the use of the root account is required, ' \
                              'such as requesting a penetration test or creating a CloudFront private key. root ' \
                              'account should not be used for all other purposes. '

        report = item.config
        now = datetime.datetime.now()

        if self._is_root(report):

            last_used_date = self._parse_date(report['password_last_used'])
            if (now - last_used_date).days < 1:
                self.add_issue(10, issue.format(method="password"), item, notes=notes,
                               action_instructions=action_instructions)
                return

            last_used_date = self._parse_date(report['access_key_1_last_used_date'])
            if (now - last_used_date).days < 1:
                self.add_issue(10, issue.format(method="ACCESS_KEY_1"), item, notes=notes,
                               action_instructions=action_instructions)
                return

            last_used_date = self._parse_date(report['access_key_2_last_used_date'])
            if (now - last_used_date).days < 1:
                self.add_issue(10, issue.format(method="ACCESS_KEY_2"), item, notes=notes,
                               action_instructions=action_instructions)
                return

    def check_1_3_unused_credentials(self, item):
        """
        CIS Rule 1.3 - Ensure credentials unused for 90 days or greater are
        disabled [scored]
        """
        issue = 'sa-iam-cis-1.3 - AWS root account using {method} has been used in last 24 hours'
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

    def check_1_21_no_active_initial_access_keys_with_iam_user(self, item):
        """
        CIS Rule 1.23 (v1.1.0) / 1.21 (v1.2.0) - Do not setup access keys during initial user setup for
        all IAM users that have a console password (Not Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-iam-cis-1.21 - ',
            specific='Users with keys created at user creation time found.'
        )

        report = item.config

        # ignore root
        if not self._is_root(report):
            for meta in report.get('access_key_metadata', []):
                if self._parse_date(meta['create_date']) == self._parse_date(report['user_creation_time']):
                    self.add_issue(10, issue, item, notes=notes)
