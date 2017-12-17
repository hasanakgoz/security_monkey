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
        from security_monkey.auditors.custom.cis.iam_user import CISIAMUserAuditor
        auditor = CISIAMUserAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        now = datetime.now()
        now = now.replace(tzinfo=tz.gettz('UTC'))

        one_hour_ago = now - timedelta(hours=1)
        one_hour_ago = one_hour_ago.strftime('%Y-%m-%d %H:%M:%S+00:00')

        # test that root user that has accessed account through pw in past 24
        # hours will alert
        iamobj = MockIAMObj()
        iamobj.config = {
            "CreateDate": one_hour_ago,
            "PasswordLastUsed": one_hour_ago,
            "UserId": "AIDAJL6UJJSHWR74QASKA",
            "Arn": "arn:aws:iam::726064622671:root",
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
        over_24_hours_ago = over_24_hours_ago.strftime('%Y-%m-%d %H:%M:%S+00:00')

        iamobj = MockIAMObj()
        iamobj.config = {
            "CreateDate": over_24_hours_ago,
            "PasswordLastUsed": over_24_hours_ago,
            "UserId": "AIDAJL6UJJSHWR74QASKA",
            "Arn": "arn:aws:iam::726064622671:root",
        }
        auditor.check_1_1_root_user(iamobj)
        self.assertIs(len(iamobj.audit_issues), 0)

        # test that non root user doesnt alert
        iamobj = MockIAMObj()
        iamobj.config = {
            "CreateDate": one_hour_ago,
            "PasswordLastUsed": one_hour_ago,
            "UserId": "AIDAJL6UJJSHWR74QASKA",
            "Arn": "arn:aws:iam::726064622671:user/rootman",
        }
        auditor.check_1_1_root_user(iamobj)
        self.assertIs(len(iamobj.audit_issues), 0)

        # test that root user didnt use passwod within 24 hours, but created
        # access key
        iamobj = MockIAMObj()
        iamobj.config = {
            "CreateDate": over_24_hours_ago,
            "PasswordLastUsed": over_24_hours_ago,
            "UserId": "AIDAJL6UJJSHWR74QASKA",
            "Arn": "arn:aws:iam::726064622671:root",
            "AccessKeys": [
                {
                    "UserName": "ServiceCatalogAdmin",
                    "Status": "Active",
                    "CreateDate": one_hour_ago,
                    "AccessKeyId": "AKIAJN5B4PH4WMS5JRDQ",
                }
            ],
        }
        auditor.check_1_1_root_user(iamobj)
        self.assertIs(len(iamobj.audit_issues), 1)

        # test that root user didnt use passwod within 24 hours, and created
        # access key over 24 hours ago, but used it within 24 hours
        iamobj = MockIAMObj()
        iamobj.config = {
            "CreateDate": over_24_hours_ago,
            "PasswordLastUsed": over_24_hours_ago,
            "UserId": "AIDAJL6UJJSHWR74QASKA",
            "Arn": "arn:aws:iam::726064622671:root",
            "AccessKeys": [
                {
                    "UserName": "ServiceCatalogAdmin",
                    "Status": "Active",
                    "CreateDate": over_24_hours_ago,
                    "LastUsedDate": one_hour_ago,
                    "AccessKeyId": "AKIAJN5B4PH4WMS5JRDQ",
                }
            ],
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
