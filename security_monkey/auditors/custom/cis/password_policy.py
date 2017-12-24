"""
.. module: security_monkey.auditors.custom.cis.iam_user
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor::  Patrick Kelley <pkelley@netflix.com> @monkeysecurity

"""

from security_monkey.auditor import Categories, Auditor
from security_monkey.watchers.custom.password_policy import PasswordPolicy


class PasswordPolicyAuditor(Auditor):
    index = PasswordPolicy.index
    i_am_singular = PasswordPolicy.i_am_singular
    i_am_plural = PasswordPolicy.i_am_plural

    def check_1_5_uppercase_letters(self, item):
        """
        CIS Rule 1.5 - Ensure IAM password policy requires at least one
        uppercase letter
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-iam-cis-1.5 - ',
            specific='Password Policy should require uppercase letters.'
        )
        if item.config == {}:
            self.add_issue(
                10,
                issue,
                item,
                notes=Categories.INFORMATIONAL_NOTES.format(
                    description='sa-iam-cis-1.5 - ',
                    specific='Account has no password policy.'
                )
            )

        elif not item.config.get('RequireUppercaseCharacters'):
            self.add_issue(
                10,
                issue,
                item,
                notes=notes
            )

    def check_1_6_lowercase_letters(self, item):
        """
        CIS Rule 1.6 - Ensure IAM password policy requires at least one
        lowercase letter
        """
        rule_description = 'sa-iam-cis-1.6 - '
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description=rule_description,
            specific='Password Policy should require lowercase letters.'
        )
        if item.config == {}:
            self.add_issue(
                10,
                issue,
                item,
                notes=Categories.INFORMATIONAL_NOTES.format(
                    description=rule_description,
                    specific='Account has no password policy.'
                )
            )

        elif not item.config.get('RequireLowercaseCharacters'):
            self.add_issue(
                10,
                issue,
                item,
                notes=notes
            )

    def check_1_7_require_symbols(self, item):
        """
        CIS Rule 1.7 - Ensure IAM password policy requires at least one symbol
        """
        rule_description = 'sa-iam-cis-1.7 - '
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description=rule_description,
            specific='Password Policy should require a symbol.'
        )
        if item.config == {}:
            self.add_issue(
                10,
                issue,
                item,
                notes=Categories.INFORMATIONAL_NOTES.format(
                    description=rule_description,
                    specific='Account has no password policy.'
                )
            )

        elif not item.config.get('RequireSymbols'):
            self.add_issue(
                10,
                issue,
                item,
                notes=notes
            )

    def check_1_8_require_numbers(self, item):
        """
        CIS Rule 1.8 - Ensure IAM password policy requires at least one number
        """
        rule_description = 'sa-iam-cis-1.8 - '
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description=rule_description,
            specific='Password Policy should require a number.'
        )
        if item.config == {}:
            self.add_issue(
                10,
                issue,
                item,
                notes=Categories.INFORMATIONAL_NOTES.format(
                    description=rule_description,
                    specific='Account has no password policy.'
                )
            )

        elif not item.config.get('RequireNumbers'):
            self.add_issue(
                10,
                issue,
                item,
                notes=notes
            )

    def check_1_9_password_policy_length(self, item):
        """
        CIS Rule 1.9 - Ensure IAM password policy requires minimum length of 14
        or greater
        """
        rule_description = 'sa-iam-cis-1.9 - '
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description=rule_description,
            specific='Password Policy should require at least 14 characters.'
        )
        if item.config == {}:
            self.add_issue(
                10,
                issue,
                item,
                notes=Categories.INFORMATIONAL_NOTES.format(
                    description=rule_description,
                    specific='Account has no password policy.'
                )
            )

        elif item.config.get('MinimumPasswordLength') < 14:
            self.add_issue(
                10,
                issue,
                item,
                notes=notes
            )

    def check_1_10_password_policy_reuse(self, item):
        """
        CIS Rule 1.10 - Ensure IAM password policy prevents password reuse
        """
        rule_description = 'sa-iam-cis-1.10 - '
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description=rule_description,
            specific='Password Policy should prevent password reuse.'
        )
        if item.config == {}:
            self.add_issue(
                10,
                issue,
                item,
                notes=Categories.INFORMATIONAL_NOTES.format(
                    description=rule_description,
                    specific='Account has no password policy.'
                )
            )

        elif not item.config.get('PasswordReusePrevention') == 24:
            self.add_issue(
                10,
                issue,
                item,
                notes=notes
            )

    def check_1_11_password_policy_expires(self, item):
        """
        CIS Rule 1.10 - Ensure IAM password policy expires passwords within 90
        days or less
        """
        rule_description = 'sa-iam-cis-1.11 - '
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description=rule_description,
            specific='Password Policy should expire passwords within 90 days.'
        )
        if item.config == {}:
            self.add_issue(
                10,
                issue,
                item,
                notes=Categories.INFORMATIONAL_NOTES.format(
                    description=rule_description,
                    specific='Account has no password policy.'
                )
            )

        elif not item.config['ExpirePasswords'] or item.config['MaxPasswordAge'] > 90:
            self.add_issue(
                10,
                issue,
                item,
                notes=notes
            )
