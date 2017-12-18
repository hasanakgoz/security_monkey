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
.. module: security_monkey.watchers.custom.password_policy
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Hammad Hai <hammad.a.hai@gmail.com>

"""

from security_monkey.watcher import Watcher
from security_monkey.watcher import ChangeItem
from security_monkey.exceptions import (
    BotoConnectionIssue,
    PasswordPolicyException,
)
from security_monkey import app, ARN_PREFIX


class PasswordPolicy(Watcher):
    index = 'passwordpolicy'
    i_am_singular = 'Password Policy'
    i_am_plural = 'Password Policies'

    def __init__(self, accounts=None, debug=False):
        super(PasswordPolicy, self).__init__(accounts=accounts, debug=debug)

    def slurp(self):
        """
        :returns: item_list - list of Password Policies.
        :returns: exception_map - A dict where the keys are a tuple containing the
            location of the exception and the value is the actual exception
        """
        self.prep_for_slurp()
        item_list = []
        exception_map = {}

        from security_monkey.common.sts_connect import connect
        for account in self.accounts:
            try:
                iam = connect(account, 'boto3.iam.client')
            except Exception as e:
                exc = BotoConnectionIssue(str(e), 'passwordpolicy', account, None)
                self.slurp_exception((self.index, account, 'universal'), exc, exception_map,
                                     source="{}-watcher".format(self.index))
                continue

            try:
                app.logger.debug('Getting password policy for account {}'.format(account))
                response = iam.get_account_password_policy()
                policy_config = response['PasswordPolicy']
            except Exception as e:
                if "cannot be found" in str(e):
                    policy_config = {}
                else:
                    exc = PasswordPolicyException(str(e), 'passwordpolicy', account, None)
                    self.slurp_exception((self.index, account, 'universal'), exc, exception_map,
                                         source="{}-watcher".format(self.index))
                    continue

            item_list.append(
                PasswordPolicyItem(
                    account=account,
                    config=policy_config
                )
            )

        return item_list, exception_map


class PasswordPolicyItem(ChangeItem):
    def __init__(self, account=None, name=None, arn=None, config={}):
        super(PasswordPolicyItem, self).__init__(
            index=PasswordPolicy.index,
            region='universal',
            account=account,
            name=name,
            arn=arn,
            new_config=config)
