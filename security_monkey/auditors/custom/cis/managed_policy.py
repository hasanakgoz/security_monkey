#     Copyright 2015 Netflix, Inc.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
"""
.. module: security_monkey.auditors.custom.cis.managed_policy
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor::  Hammad Hai <hammad.a.hai@gmail.com>

"""
from security_monkey.auditor import Categories
from security_monkey.watchers.iam.managed_policy import ManagedPolicy
from security_monkey.auditors.iam.iam_policy import IAMPolicyAuditor


class ManagedPolicyAuditor(IAMPolicyAuditor):
    index = ManagedPolicy.index
    i_am_singular = ManagedPolicy.i_am_singular
    i_am_plural = ManagedPolicy.i_am_plural

    def check_1_22_ensure_incident_management_roles(self, item):
        """
        CIS Rule 1.22 - Ensure a support role has been created to manage
        incidents with AWS Support (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-iam-cis-1.22 - ',
            specific='AWSSupportAccess policy not created.'
        )
        if '/AWSSupportAccess' in item.config['arn']:
            if not any([item.config.get('attached_groups'),
                        item.config.get('attached_roles'),
                        item.config.get('attached_users')]):
                self.add_issue(10, issue, item, notes=notes)
