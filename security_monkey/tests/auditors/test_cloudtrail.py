from security_monkey.tests import SecurityMonkeyTestCase


class MockObj:
    def __init__(self):
        self.config = {}
        self.audit_issues = []
        self.index = "unittestindex"
        self.region = "unittestregion"
        self.account = "unittestaccount"
        self.name = "unittestname"


class CloudTrailTestCase(SecurityMonkeyTestCase):

    test_config = {
        "cloudwatch_logs_log_group_arn": None,
        "cloudwatch_logs_role_arn": None,
        "home_region": "us-east-1",
        "include_global_service_events": True,
        "is_multi_region_trail": False,
        "kms_key_id": None,
        "log_file_validation_enabled": False,
        "s3_bucket_name": "726064622671-awsmacietrail-dataevent",
        "s3_key_prefix": None,
        "sns_topic_name": None,
        "trail": "AWSMacieTrail-DO-NOT-EDIT",
        "trail_arn": "arn:aws:cloudtrail:us-east-1:726064622671:trail/AWSMacieTrail-DO-NOT-EDIT",
        "trail_status": True
    }

    def test_2_4_cloudwatch_logs_integration(self):
        from security_monkey.auditors.cloudtrail import CloudTrailAuditor
        auditor = CloudTrailAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        cloud_trail_obj = MockObj()
        cloud_trail_obj.config = self.test_config

        auditor.check_2_4_cloudwatch_logs_integration(cloud_trail_obj)

        self.assertIs(len(cloud_trail_obj.audit_issues), 1)
        self.assertEquals(cloud_trail_obj.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            cloud_trail_obj.audit_issues[0].notes,
            'sa-log-cis-2.4 - CloudTrails without CloudWatch Logs discovered.'
        )

        cloud_trail_obj = MockObj()
        cloud_trail_obj.config = self.test_config
        cloud_trail_obj.config['cloudwatch_logs_log_group_arn'] = 'something'

        auditor.check_2_4_cloudwatch_logs_integration(cloud_trail_obj)

        self.assertIs(len(cloud_trail_obj.audit_issues), 1)
        self.assertEquals(cloud_trail_obj.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            cloud_trail_obj.audit_issues[0].notes,
            'sa-log-cis-2.4 - CloudTrails without CloudWatch Logs discovered.'
        )

        cloud_trail_obj = MockObj()
        cloud_trail_obj.config = self.test_config
        cloud_trail_obj.config['cloudwatch_logs_log_group_arn'] = 'arn:aws:logs/something'

        auditor.check_2_4_cloudwatch_logs_integration(cloud_trail_obj)

        self.assertIs(len(cloud_trail_obj.audit_issues), 0)

    def test_2_7_logs_encrypted(self):
        from security_monkey.auditors.cloudtrail import CloudTrailAuditor
        auditor = CloudTrailAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        cloud_trail_obj = MockObj()
        cloud_trail_obj.config = self.test_config

        auditor.check_2_7_logs_encrypted(cloud_trail_obj)

        self.assertIs(len(cloud_trail_obj.audit_issues), 1)
        self.assertEquals(cloud_trail_obj.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            cloud_trail_obj.audit_issues[0].notes,
            'sa-log-cis-2.7 - CloudTrail not using KMS CMK for encryption discovered.'
        )

        cloud_trail_obj = MockObj()
        cloud_trail_obj.config = self.test_config
        cloud_trail_obj.config['kms_key_id'] = '123szad'

        auditor.check_2_7_logs_encrypted(cloud_trail_obj)

        self.assertIs(len(cloud_trail_obj.audit_issues), 0)
