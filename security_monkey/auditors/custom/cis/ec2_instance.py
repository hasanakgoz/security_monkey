"""
.. module: security_monkey.auditors.custom.cis.ec2_instance
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor::  Hammad Hai <hammad.a.hai@gmail.com>

"""

from security_monkey.auditor import Categories, Auditor
from security_monkey.watchers.ec2.ec2_instance import EC2Instance


class EC2InstanceAuditor(Auditor):
    index = EC2Instance.index
    i_am_singular = EC2Instance.i_am_singular
    i_am_plural = EC2Instance.i_am_plural

    def check_1_21_ensure_iam_instance_roles_used(self, item):
        """
        CIS Rule 1.21 - Ensure IAM instance roles are used for AWS resource
        access from instances (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-iam-cis-1.21 - ',
            specific='Instance not assigned IAM role for EC2.'
        )
        if not item.config.get('iam_instance_profile'):
            self.add_issue(10, issue, item, notes=notes)

