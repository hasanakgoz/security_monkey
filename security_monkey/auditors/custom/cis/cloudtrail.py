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
.. moduleauthor::  Hammad Hai <hammad.a.hai@gmail.com>

"""
import re
from security_monkey.auditor import Auditor, Categories
from security_monkey.watchers.cloud_trail import CloudTrail
from security_monkey.common.sts_connect import connect


class CISCloudTrailAuditor(Auditor):
    index = CloudTrail.index
    i_am_singular = CloudTrail.i_am_singular
    i_am_plural = CloudTrail.i_am_plural

    def __init__(self, accounts=None, debug=False):
        super(CISCloudTrailAuditor, self).__init__(accounts=accounts, debug=debug)

    def _find_in_string(pattern, target):
        result = True
        for n in pattern:
            if not re.search(n, target):
                result = False
                break
        return result

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

    def check_3_1_log_metric_filter_unauthorized_api_calls(self, cloud_trail):
        """
        CIS Rule 3.1 - Ensure a log metric filter and alarm exist for
        unauthorized API calls (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-mon-cis-3.1 - ',
            specific='Incorrect log metric alerts for unauthorized_api_calls.'
        )
        log_group = cloud_trail.config.get('cloud_watch_logs_log_group_arn')
        if not log_group:
            self.add_issue(10, issue, cloud_trail, notes=notes)
        else:
            for mf in cloud_trail.config['cloudwatch_metric_filters']:
                patterns = [
                    "\$\.errorCode\s*=\s*\"?\*UnauthorizedOperation(\"|\)|\s)",
                    "\$\.errorCode\s*=\s*\"?AccessDenied\*(\"|\)|\s)"
                ]
                if self._find_in_string(patterns, str(mf['filter']['filterPattern'])):
                    if len(mf['subscribers']) == 0:
                        self.add_issue(10, issue, cloud_trail, notes=notes)

    def check_3_2_ensure_log_metric_filter_console_signin_no_mfa(self, cloud_trail):
        """
        CIS Rule 3.2 - Ensure a log metric filter and alarm exist for Management
        Console sign-in without MFA (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-mon-cis-3.2 - ',
            specific='Incorrect log metric alerts for management console signin without MFA.'
        )
        log_group = cloud_trail.config.get('cloud_watch_logs_log_group_arn')
        if not log_group:
            self.add_issue(10, issue, cloud_trail, notes=notes)
        else:
            for mf in cloud_trail.config['cloudwatch_metric_filters']:
                patterns = [
                    "\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)",
                    "\$\.additionalEventData\.MFAUsed\s*\!=\s*\"?Yes"
                ]
                if self._find_in_string(patterns, str(mf['filter']['filterPattern'])):
                    if len(mf['subscribers']) == 0:
                        self.add_issue(10, issue, cloud_trail, notes=notes)

    def check_3_3_ensure_log_metric_filter_root_usage(self, cloud_trail):
        """
        CIS Rule 3.3 - Ensure a log metric filter and alarm exist for usage of
        "root" account (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-mon-cis-3.3 - ',
            specific='Incorrect log metric alerts for root usage.'
        )
        log_group = cloud_trail.config.get('cloud_watch_logs_log_group_arn')
        if not log_group:
            self.add_issue(10, issue, cloud_trail, notes=notes)
        else:
            for mf in cloud_trail.config['cloudwatch_metric_filters']:
                patterns = [
                    "\$\.userIdentity\.type\s*=\s*\"?Root",
                    "\$\.userIdentity\.invokedBy\s*NOT\s*EXISTS",
                    "\$\.eventType\s*\!=\s*\"?AwsServiceEvent(\"|\)|\s)"
                ]
                if self._find_in_string(patterns, str(mf['filter']['filterPattern'])):
                    if len(mf['subscribers']) == 0:
                        self.add_issue(10, issue, cloud_trail, notes=notes)

    def check_3_4_ensure_log_metric_iam_policy_change(self, cloud_trail):
        """
        CIS Rule 3.4 - Ensure a log metric filter and alarm exist for IAM policy
        changes (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-mon-cis-3.4 - ',
            specific='Incorrect log metric alerts for IAM policy changes.'
        )
        log_group = cloud_trail.config.get('cloud_watch_logs_log_group_arn')
        if not log_group:
            self.add_issue(10, issue, cloud_trail, notes=notes)
        else:
            for mf in cloud_trail.config['cloudwatch_metric_filters']:
                patterns = [
                    "\$\.eventName\s*=\s*\"?DeleteGroupPolicy(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteRolePolicy(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteUserPolicy(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?PutGroupPolicy(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?PutRolePolicy(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?PutUserPolicy(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?CreatePolicy(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeletePolicy(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?CreatePolicyVersion(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeletePolicyVersion(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?AttachRolePolicy(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DetachRolePolicy(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?AttachUserPolicy(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DetachUserPolicy(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?AttachGroupPolicy(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DetachGroupPolicy(\"|\)|\s)"
                ]
                if self._find_in_string(patterns, str(mf['filter']['filterPattern'])):
                    if len(mf['subscribers']) == 0:
                        self.add_issue(10, issue, cloud_trail, notes=notes)

    def check_3_5_ensure_log_metric_cloudtrail_configuration_changes(self, cloud_trail):
        """
        CIS Rule 3.5 - Ensure a log metric filter and alarm exist for CloudTrail
        configuration changes (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-mon-cis-3.5 - ',
            specific='Incorrect log metric alerts for CloudTrail configuration changes.'
        )
        log_group = cloud_trail.config.get('cloud_watch_logs_log_group_arn')
        if not log_group:
            self.add_issue(10, issue, cloud_trail, notes=notes)
        else:
            for mf in cloud_trail.config['cloudwatch_metric_filters']:
                patterns = [
                    "\$\.eventName\s*=\s*\"?CreateTrail(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?UpdateTrail(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteTrail(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?StartLogging(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?StopLogging(\"|\)|\s)"
                ]
                if self._find_in_string(patterns, str(mf['filter']['filterPattern'])):
                    if len(mf['subscribers']) == 0:
                        self.add_issue(10, issue, cloud_trail, notes=notes)

    def check_3_6_ensure_log_metric_console_auth_failures(self, cloud_trail):
        """
        CIS Rule 3.6 - Ensure a log metric filter and alarm exist for AWS Management
        Console authentication failures (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-mon-cis-3.6 - ',
            specific='Ensure a log metric filter and alarm exist for console auth failures.'
        )
        log_group = cloud_trail.config.get('cloud_watch_logs_log_group_arn')
        if not log_group:
            self.add_issue(10, issue, cloud_trail, notes=notes)
        else:
            for mf in cloud_trail.config['cloudwatch_metric_filters']:
                patterns = [
                    "\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)",
                    "\$\.errorMessage\s*=\s*\"?Failed authentication(\"|\)|\s)"
                ]
                if self._find_in_string(patterns, str(mf['filter']['filterPattern'])):
                    if len(mf['subscribers']) == 0:
                        self.add_issue(10, issue, cloud_trail, notes=notes)

    def check_3_7_ensure_log_metric_disabling_scheduled_delete_of_kms_cmk(self, cloud_trail):
        """
        CIS Rule 3.7 - Ensure a log metric filter and alarm exist for disabling
        or scheduled deletion of customer created CMKs (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-mon-cis-3.7 - ',
            specific='Ensure a log metric filter and alarm exist for disabling or scheduling deletion of KMS CMK.'
        )
        log_group = cloud_trail.config.get('cloud_watch_logs_log_group_arn')
        if not log_group:
            self.add_issue(10, issue, cloud_trail, notes=notes)
        else:
            for mf in cloud_trail.config['cloudwatch_metric_filters']:
                patterns = [
                    "\$\.eventSource\s*=\s*\"?kms\.amazonaws\.com(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DisableKey(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?ScheduleKeyDeletion(\"|\)|\s)"
                ]
                if self._find_in_string(patterns, str(mf['filter']['filterPattern'])):
                    if len(mf['subscribers']) == 0:
                        self.add_issue(10, issue, cloud_trail, notes=notes)

    def check_3_8_ensure_log_metric_s3_bucket_policy_changes(self, cloud_trail):
        """
        CIS Rule 3.8 - Ensure a log metric filter and alarm exist for S3 bucket
        policy changes (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-mon-cis-3.8 - ',
            specific='Ensure a log metric filter and alarm exist for S3 bucket policy changes.'
        )
        log_group = cloud_trail.config.get('cloud_watch_logs_log_group_arn')
        if not log_group:
            self.add_issue(10, issue, cloud_trail, notes=notes)
        else:
            for mf in cloud_trail.config['cloudwatch_metric_filters']:
                patterns = [
                    "\$\.eventSource\s*=\s*\"?s3\.amazonaws\.com(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?PutBucketAcl(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?PutBucketPolicy(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?PutBucketCors(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?PutBucketLifecycle(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?PutBucketReplication(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteBucketPolicy(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteBucketCors(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteBucketLifecycle(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteBucketReplication(\"|\)|\s)"
                ]
                if self._find_in_string(patterns, str(mf['filter']['filterPattern'])):
                    if len(mf['subscribers']) == 0:
                        self.add_issue(10, issue, cloud_trail, notes=notes)

    def check_3_9_ensure_log_metric_config_configuration_changes(self, cloud_trail):
        """
        CIS Rule 3.9 - Ensure a log metric filter and alarm exist for AWS Config
        configuration changes (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-mon-cis-3.9 - ',
            specific='Ensure a log metric filter and alarm exist for for AWS Config configuration changes.'
        )
        log_group = cloud_trail.config.get('cloud_watch_logs_log_group_arn')
        if not log_group:
            self.add_issue(10, issue, cloud_trail, notes=notes)
        else:
            for mf in cloud_trail.config['cloudwatch_metric_filters']:
                patterns = [
                    "\$\.eventSource\s*=\s*\"?config\.amazonaws\.com(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?StopConfigurationRecorder(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteDeliveryChannel(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?PutDeliveryChannel(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?PutConfigurationRecorder(\"|\)|\s)"
                ]
                if self._find_in_string(patterns, str(mf['filter']['filterPattern'])):
                    if len(mf['subscribers']) == 0:
                        self.add_issue(10, issue, cloud_trail, notes=notes)

    def check_3_10_ensure_log_metric_security_group_changes(self, cloud_trail):
        """
        CIS Rule 3.10 - Ensure a log metric filter and alarm exist for security
        group changes (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-mon-cis-3.10 - ',
            specific='Ensure a log metric filter and alarm exist for security group changes.'
        )
        log_group = cloud_trail.config.get('cloud_watch_logs_log_group_arn')
        if not log_group:
            self.add_issue(10, issue, cloud_trail, notes=notes)
        else:
            for mf in cloud_trail.config['cloudwatch_metric_filters']:
                patterns = [
                    "\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupIngress(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupEgress(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?RevokeSecurityGroupIngress(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?RevokeSecurityGroupEgress(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?CreateSecurityGroup(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteSecurityGroup(\"|\)|\s)"
                ]
                if self._find_in_string(patterns, str(mf['filter']['filterPattern'])):
                    if len(mf['subscribers']) == 0:
                        self.add_issue(10, issue, cloud_trail, notes=notes)

    def check_3_11_ensure_log_metric_nacl(self, cloud_trail):
        """
        CIS Rule 3.11 - Ensure a log metric filter and alarm exist for changes
        to Network Access Control Lists (NACL) (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-mon-cis-3.11 - ',
            specific='Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL).'
        )
        log_group = cloud_trail.config.get('cloud_watch_logs_log_group_arn')
        if not log_group:
            self.add_issue(10, issue, cloud_trail, notes=notes)
        else:
            for mf in cloud_trail.config['cloudwatch_metric_filters']:
                patterns = [
                    "\$\.eventName\s*=\s*\"?CreateNetworkAcl(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?CreateNetworkAclEntry(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteNetworkAcl(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteNetworkAclEntry(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?ReplaceNetworkAclEntry(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?ReplaceNetworkAclAssociation(\"|\)|\s)"
                ]

                if self._find_in_string(patterns, str(mf['filter']['filterPattern'])):
                    if len(mf['subscribers']) == 0:
                        self.add_issue(10, issue, cloud_trail, notes=notes)

    def check_3_12_ensure_log_metric_changes_to_network_gateways(self, cloud_trail):
        """
        CIS Rule 3.12 - Ensure a log metric filter and alarm exist for changes
        to network gateways (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-mon-cis-3.12 - ',
            specific='Ensure a log metric filter and alarm exist for changes to network gateways.'
        )
        log_group = cloud_trail.config.get('cloud_watch_logs_log_group_arn')
        if not log_group:
            self.add_issue(10, issue, cloud_trail, notes=notes)
        else:
            for mf in cloud_trail.config['cloudwatch_metric_filters']:
                patterns = [
                    "\$\.eventName\s*=\s*\"?CreateCustomerGateway(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteCustomerGateway(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?AttachInternetGateway(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?CreateInternetGateway(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteInternetGateway(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DetachInternetGateway(\"|\)|\s)"
                ]

                if self._find_in_string(patterns, str(mf['filter']['filterPattern'])):
                    if len(mf['subscribers']) == 0:
                        self.add_issue(10, issue, cloud_trail, notes=notes)

    def check_3_13_ensure_log_metric_changes_to_route_tables(self, cloud_trail):
        """
        CIS Rule 3.13 - Ensure a log metric filter and alarm exist for route
        table changes (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-mon-cis-3.13 - ',
            specific='Ensure a log metric filter and alarm exist for route table changes.'
        )
        log_group = cloud_trail.config.get('cloud_watch_logs_log_group_arn')
        if not log_group:
            self.add_issue(10, issue, cloud_trail, notes=notes)
        else:
            for mf in cloud_trail.config['cloudwatch_metric_filters']:
                patterns = [
                    "\$\.eventName\s*=\s*\"?CreateRoute(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?CreateRouteTable(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?ReplaceRoute(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?ReplaceRouteTableAssociation(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteRouteTable(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteRoute(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DisassociateRouteTable(\"|\)|\s)"
                ]

                if self._find_in_string(patterns, str(mf['filter']['filterPattern'])):
                    if len(mf['subscribers']) == 0:
                        self.add_issue(10, issue, cloud_trail, notes=notes)

    def check_3_14_ensure_log_metric_changes_to_vpc(self, cloud_trail):
        """
        CIS Rule 3.14 - Ensure a log metric filter and alarm exist for VPC
        changes (Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-mon-cis-3.14 - ',
            specific='Ensure a log metric filter and alarm exist for VPC changes.'
        )
        log_group = cloud_trail.config.get('cloud_watch_logs_log_group_arn')
        if not log_group:
            self.add_issue(10, issue, cloud_trail, notes=notes)
        else:
            for mf in cloud_trail.config['cloudwatch_metric_filters']:
                patterns = [
                    "\$\.eventName\s*=\s*\"?CreateVpc(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteVpc(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?ModifyVpcAttribute(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?AcceptVpcPeeringConnection(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?CreateVpcPeeringConnection(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DeleteVpcPeeringConnection(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?RejectVpcPeeringConnection(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?AttachClassicLinkVpc(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DetachClassicLinkVpc(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?DisableVpcClassicLink(\"|\)|\s)",
                    "\$\.eventName\s*=\s*\"?EnableVpcClassicLink(\"|\)|\s)"
                ]

                if self._find_in_string(patterns, str(mf['filter']['filterPattern'])):
                    if len(mf['subscribers']) == 0:
                        self.add_issue(10, issue, cloud_trail, notes=notes)
