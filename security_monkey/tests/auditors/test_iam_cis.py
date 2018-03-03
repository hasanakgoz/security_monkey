from security_monkey.tests import SecurityMonkeyTestCase
from datetime import datetime, timedelta
from dateutil import tz


class MockIAMObj:
    def __init__(self):
        self.config = {}
        self.audit_issues = []
        self.index = "unittestindex"
        self.region = "unittestregion"
        self.account = "unittestaccount"
        self.name = "unittestname"


class CISIAMTestCase(SecurityMonkeyTestCase):

    def test_1_1_root_user(self):
        from security_monkey.auditors.custom.cis.iam_user import IAMUserCredsAuditor
        auditor = IAMUserCredsAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        now = datetime.now()
        now = now.replace(tzinfo=tz.gettz('UTC'))

        one_hour_ago = now - timedelta(hours=1)
        one_hour_ago = one_hour_ago.strftime(
            IAMUserCredsAuditor.DATE_FORMAT
        )

        # test that root user that has accessed account through pw in past 24
        # hours will alert
        iamobj = MockIAMObj()
        iamobj.config = {
            "password_last_used": one_hour_ago,
            "arn": "arn:aws:iam::726064622671:root",
            "access_key_1_last_used_date": "N/A",
            "access_key_2_last_used_date": "N/A",
        }
        auditor.check_1_1_root_user(iamobj)
        self.assertIs(len(iamobj.audit_issues), 1)
        self.assertEquals(iamobj.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            iamobj.audit_issues[0].notes,
            'sa-iam-cis-1.1 - Root Account used in past 24hrs.'
        )

        # test that root user that has NOT accessed account within 24 hours
        # does not alert
        over_24_hours_ago = now - timedelta(hours=25)
        over_24_hours_ago = over_24_hours_ago.strftime(
            IAMUserCredsAuditor.DATE_FORMAT
        )

        iamobj = MockIAMObj()
        iamobj.config = {
            "password_last_used": over_24_hours_ago,
            "arn": "arn:aws:iam::726064622671:root",
            "access_key_1_last_used_date": "N/A",
            "access_key_2_last_used_date": "N/A",
        }
        auditor.check_1_1_root_user(iamobj)
        self.assertIs(len(iamobj.audit_issues), 0)

        # test that non root user doesnt alert
        iamobj = MockIAMObj()
        iamobj.config = {
            "password_last_used": one_hour_ago,
            "arn": "arn:aws:iam::726064622671:user/rootman",
            "access_key_1_last_used_date": "N/A",
            "access_key_2_last_used_date": "N/A",
        }
        auditor.check_1_1_root_user(iamobj)
        self.assertIs(len(iamobj.audit_issues), 0)

        # test that root user didnt use passwod within 24 hours, but used
        # access key 1
        iamobj = MockIAMObj()
        iamobj.config = {
            "password_last_used": over_24_hours_ago,
            "arn": "arn:aws:iam::726064622671:root",
            "access_key_1_last_used_date": one_hour_ago,
            "access_key_2_last_used_date": "N/A",
        }
        auditor.check_1_1_root_user(iamobj)
        self.assertIs(len(iamobj.audit_issues), 1)

        # test that root user didnt use passwod within 24 hours, but used
        # access key 2
        iamobj = MockIAMObj()
        iamobj.config = {
            "password_last_used": over_24_hours_ago,
            "arn": "arn:aws:iam::726064622671:root",
            "access_key_1_last_used_date": "N/A",
            "access_key_2_last_used_date": one_hour_ago,
        }
        auditor.check_1_1_root_user(iamobj)
        self.assertIs(len(iamobj.audit_issues), 1)

    def test_1_3_unused_credentials(self):
        from security_monkey.auditors.custom.cis.iam_user import IAMUserCredsAuditor
        auditor = IAMUserCredsAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        now = datetime.now()
        now = now.replace(tzinfo=tz.gettz('UTC'))

        over_90_days_ago = now - timedelta(days=91)
        over_90_days_ago = over_90_days_ago.strftime(
            IAMUserCredsAuditor.DATE_FORMAT
        )

        under_90_days_ago = now - timedelta(days=89)
        under_90_days_ago = under_90_days_ago.strftime(
            IAMUserCredsAuditor.DATE_FORMAT
        )

        iamobj = MockIAMObj()
        iamobj.config = {
            "password_enabled": "TRUE",
            "password_last_used": over_90_days_ago,
            "access_key_1_active": "true",
            "access_key_1_last_used_date": over_90_days_ago,
            "access_key_2_active": "True",
            "access_key_2_last_used_date": over_90_days_ago,
        }

        auditor.check_1_3_unused_credentials(iamobj)
        self.assertIs(len(iamobj.audit_issues), 3)
        self.assertEquals(iamobj.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            iamobj.audit_issues[0].notes,
            'sa-iam-cis-1.3 - Detected active password unused for over 90 days.'
        )
        self.assertEquals(
            iamobj.audit_issues[1].notes,
            'sa-iam-cis-1.3 - Detected active access key 1 unused for over 90 days.'
        )
        self.assertEquals(
            iamobj.audit_issues[2].notes,
            'sa-iam-cis-1.3 - Detected active access key 2 unused for over 90 days.'
        )

        iamobj = MockIAMObj()
        iamobj.config = {
            "password_enabled": "TRUE",
            "password_last_used": under_90_days_ago,
            "access_key_1_active": "true",
            "access_key_1_last_used_date": under_90_days_ago,
            "access_key_2_active": "True",
            "access_key_2_last_used_date": under_90_days_ago,
        }

        auditor.check_1_3_unused_credentials(iamobj)
        self.assertIs(len(iamobj.audit_issues), 0)

        iamobj = MockIAMObj()
        iamobj.config = {
            "password_enabled": "FALSE",
            "password_last_used": over_90_days_ago,
            "access_key_1_active": "false",
            "access_key_1_last_used_date": over_90_days_ago,
            "access_key_2_active": "False",
            "access_key_2_last_used_date": over_90_days_ago,
        }

        auditor.check_1_3_unused_credentials(iamobj)
        self.assertIs(len(iamobj.audit_issues), 0)

    def test_1_12_root_key_exists(self):
        from security_monkey.auditors.custom.cis.iam_user import IAMUserCredsAuditor
        auditor = IAMUserCredsAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        iamobj = MockIAMObj()
        iamobj.config = {
            "arn": "arn:aws:iam::726064622671:root",
            "access_key_1_active": "true",
            "access_key_2_active": "false",
        }
        auditor.check_1_12_root_key_exists(iamobj)
        self.assertIs(len(iamobj.audit_issues), 1)
        self.assertEquals(iamobj.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            iamobj.audit_issues[0].notes,
            'sa-iam-cis-1.12 - Root account has active access keys.'
        )

        iamobj = MockIAMObj()
        iamobj.config = {
            "arn": "arn:aws:iam::726064622671:root",
            "access_key_1_active": "false",
            "access_key_2_active": "true",
        }
        auditor.check_1_12_root_key_exists(iamobj)
        self.assertIs(len(iamobj.audit_issues), 1)

        iamobj = MockIAMObj()
        iamobj.config = {
            "arn": "arn:aws:iam::726064622671:root",
            "access_key_1_active": "false",
            "access_key_2_active": "false",
        }
        auditor.check_1_12_root_key_exists(iamobj)
        self.assertIs(len(iamobj.audit_issues), 0)

    def test_1_13_mfa_root_account(self):
        from security_monkey.auditors.custom.cis.iam_user import IAMUserCredsAuditor
        auditor = IAMUserCredsAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        iamobj = MockIAMObj()
        iamobj.config = {
            "arn": "arn:aws:iam::726064622671:root",
            "mfa_active": "false",
        }
        auditor.check_1_13_mfa_root_account(iamobj)
        self.assertIs(len(iamobj.audit_issues), 1)
        self.assertEquals(iamobj.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            iamobj.audit_issues[0].notes,
            'sa-iam-cis-1.13 - Root account does not have MFA enabled.'
        )

        iamobj = MockIAMObj()
        iamobj.config = {
            "arn": "arn:aws:iam::726064622671:user/notroot",
            "mfa_active": "false",
        }
        auditor.check_1_13_mfa_root_account(iamobj)
        self.assertIs(len(iamobj.audit_issues), 0)

    def test_1_14_hardware_mfa_root_account(self):
        from security_monkey.auditors.custom.cis.iam_user import CISIAMUserAuditor
        auditor = CISIAMUserAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        iamobj = MockIAMObj()
        iamobj.config = {
            "MfaDevices": {
                "arn:aws:iam::726064622671:mfa/root-account-mfa-device": {
                    "UserName": "<root>",
                    "SerialNumber": "arn:aws:iam::726064622671:mfa/root-account-mfa-device",
                    "EnableDate": "2017-01-23 14:39:41+00:00"
                }
            },
            "Arn": "arn:aws:iam::726064622671:root",
        }
        auditor.check_1_14_root_hardware_mfa_enabled(iamobj)
        self.assertIs(len(iamobj.audit_issues), 1)
        self.assertEquals(iamobj.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            iamobj.audit_issues[0].notes,
            'sa-iam-cis-1.14 - Root account not using hardware MFA.'
        )

        iamobj = MockIAMObj()
        iamobj.config = {
            "MfaDevices": {
                "arn:aws:iam::726064622671:mfa/root-account-mfa-device": {
                    "UserName": "<root>",
                    "SerialNumber": "arn:aws:iam::726064622671:mfa/something-else",
                    "EnableDate": "2017-01-23 14:39:41+00:00"
                }
            },
            "Arn": "arn:aws:iam::726064622671:root",
        }
        auditor.check_1_14_root_hardware_mfa_enabled(iamobj)
        self.assertIs(len(iamobj.audit_issues), 0)

    def test_1_16_no_inline_policies(self):
        from security_monkey.auditors.custom.cis.iam_user import CISIAMUserAuditor
        auditor = CISIAMUserAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        iamobj = MockIAMObj()
        iamobj.config = {
            'InlinePolicies': {
                "AmazonSesSendingAccess": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Action": "ses:SendRawEmail",
                            "Resource": "*",
                            "Effect": "Allow"
                        }
                    ]
                }
            }
        }

        auditor.check_1_16_no_inline_policies(iamobj)
        self.assertIs(len(iamobj.audit_issues), 1)
        self.assertEquals(iamobj.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            iamobj.audit_issues[0].notes,
            'sa-iam-cis-1.16 - IAM user has inline policy attached.'
        )

        iamobj = MockIAMObj()
        iamobj.config = {
            'InlinePolicies': {}
        }

        auditor.check_1_16_no_inline_policies(iamobj)
        self.assertIs(len(iamobj.audit_issues), 0)

    def test_1_21_instance_roles_used(self):
        from security_monkey.auditors.custom.cis.ec2_instance import EC2InstanceAuditor
        auditor = EC2InstanceAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        iamobj = MockIAMObj()
        iamobj.config = {
            'iam_instance_profile': {}
        }

        auditor.check_1_21_ensure_iam_instance_roles_used(iamobj)
        self.assertIs(len(iamobj.audit_issues), 1)
        self.assertEquals(iamobj.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            iamobj.audit_issues[0].notes,
            'sa-iam-cis-1.21 - Instance not assigned IAM role for EC2.'
        )

        iamobj = MockIAMObj()
        iamobj.config = {
            'iam_instance_profile': {
                'Arn': 'blahblah',
                'Id': 123,
            }
        }

        auditor.check_1_21_ensure_iam_instance_roles_used(iamobj)
        self.assertIs(len(iamobj.audit_issues), 0)

    def test_1_23_no_active_initial_access_keys_with_iam_user(self):
        from security_monkey.auditors.custom.cis.iam_user import IAMUserCredsAuditor
        auditor = IAMUserCredsAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        iamobj = MockIAMObj()
        iamobj.config = {
            "arn": "arn:aws:iam::726064622671:user/notroot",
            "user": "test-user",
            "user_creation_time": "2016-12-01T22:19:58+00:00",
            "access_key_metadata": [
                {
                    'UserName': 'test-user',
                    'AccessKeyId': 'blahblah',
                    'Status': 'Active',
                    'CreateDate': datetime(2016, 12, 1, 22, 19, 58),
                },
            ],
        }
        auditor.check_1_23_no_active_initial_access_keys_with_iam_user(iamobj)
        self.assertIs(len(iamobj.audit_issues), 1)
        self.assertEquals(iamobj.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            iamobj.audit_issues[0].notes,
            'sa-iam-cis-1.23 - Users with keys created at user creation time found.'
        )
