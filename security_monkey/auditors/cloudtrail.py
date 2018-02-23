#     Copyright 2016 Netflix, Inc.
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
.. module: security_monkey.auditors.cloudtrail
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor::  Nag Medida <nmedida@netflix.com>

"""
from security_monkey.auditor import Auditor, Categories
from security_monkey.watchers.cloud_trail import CloudTrail


class CloudTrailAuditor(Auditor):
    index = CloudTrail.index
    i_am_singular = CloudTrail.i_am_singular
    i_am_plural = CloudTrail.i_am_plural

    def __init__(self, accounts=None, debug=False):
        super(CloudTrailAuditor, self).__init__(accounts=accounts, debug=debug)

    def check_if_cloudtrail_in_all_regions(self, cloud_trail):
        if not cloud_trail.config.get('is_multi_region_trail'):
            message = "POLICY - CloudTrail is not enabled for multi-region"
            self.add_issue(10, message, cloud_trail)
        return False

    def check_if_cloudtrail_is_enabled(self, cloud_trail):
        if not cloud_trail.config.get('trail_status'):
            message = "POLICY - CloudTrail is disabled"
            self.add_issue(10, message, cloud_trail)
        return False

    def check_2_4_cloudwatch_logs_integration(self, cloud_trail):
        """
        CIS Rule 2.4 - Ensure CloudTrail trails are integrated with CloudWatch
        Logs (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-log-cis-2.4 - ',
            specific='CloudTrails without CloudWatch Logs discovered.'
        )

        logs_arn = cloud_trail.config.get('cloudwatch_logs_log_group_arn')
        if not logs_arn or 'arn:aws:logs' not in logs_arn:
            self.add_issue(10, issue, cloud_trail, notes=notes)

    def check_2_7_logs_encrypted(self, cloud_trail):
        """
        CIS Rule 2.7 - Ensure CloudTrail logs are encrypted at rest using KMS
        CMKs (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-log-cis-2.7 - ',
            specific='CloudTrail not using KMS CMK for encryption discovered.'
        )
        if not cloud_trail.config.get('kms_key_id'):
            self.add_issue(10, issue, cloud_trail, notes=notes)
