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
        if not item.config.get('RequireUppercaseCharacters'):
            self.add_issue(
                10,
                issue,
                item,
                notes=notes
            )
