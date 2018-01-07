# Copyright 2014 Netflix, Inc.
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
.. module: security_monkey.auditors.security_group
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Patrick Kelley <pkelley@netflix.com> @monkeysecurity

"""

from security_monkey.auditor import Categories
from security_monkey.auditors.security_group import SecurityGroupAuditor
from security_monkey.watchers.security_group import SecurityGroup
from security_monkey import app


class CISSecurityGroupAuditor(SecurityGroupAuditor):

    def __init__(self, accounts=None, debug=False):
        super(CISSecurityGroupAuditor, self).__init__(accounts=accounts, debug=debug)

    def check_4_1_ssh_not_open_to_world(self, item):
        """
        CIS Rule 4.1 - Ensure no security groups allow ingress from 0.0.0.0/0
        to port 22 (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-cis-4.1 - ',
            specific='Found Security Group [{}] with port 22 open to the world (0.0.0.0/0).'.format(
                item.config['id']
            )
        )

        for rule in item.config.get('rules', []):
            try:
                if int(rule['from_port']) <= 22 <= int(rule['to_port']) and \
                        '0.0.0.0/0' in str(rule['cidr_ip']):
                    self.add_issue(
                        10,
                        issue,
                        item,
                        notes=notes
                    )
            except:
                if rule['ip_protocol'] == '-1' and '0.0.0.0/0' in str(rule['cidr_ip']):
                    self.add_issue(
                        10,
                        issue,
                        item,
                        notes=notes
                    )

    def check_4_2_rdp_not_open_to_world(self, item):
        """
        CIS Rule 4.2 - Ensure no security groups allow ingress from 0.0.0.0/0
        to port 3389 (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-cis-4.2 - ',
            specific='Found Security Group [{}] with port 3389 open to the world (0.0.0.0/0).'.format(
                item.config['id']
            )
        )

        for rule in item.config.get('rules', []):
            try:
                if int(rule['from_port']) <= 3389 <= int(rule['to_port']) and \
                        '0.0.0.0/0' in str(rule['cidr_ip']):
                    self.add_issue(
                        10,
                        issue,
                        item,
                        notes=notes
                    )
            except:
                if rule['ip_protocol'] == '-1' and '0.0.0.0/0' in str(rule['cidr_ip']):
                    self.add_issue(
                        10,
                        issue,
                        item,
                        notes=notes
                    )

    def check_4_4_default_security_groups_restricts_traffic(self, item):
        """
        CIS Rule 4.4 - Ensure the default security group of every VPC restricts
        all traffic (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-cis-4.4 - ',
            specific='Default security group with ingress or egress rules discovered.'
        )

        if item.config['name'] == 'default':
            if item.config.get('rules'):
                self.add_issue(
                    10,
                    issue,
                    item,
                    notes=notes
                )
