from security_monkey.tests import SecurityMonkeyTestCase


class MockPolicyItem:
    def __init__(self):
        self.config = {}
        self.audit_issues = []
        self.index = "unittestindex"
        self.region = "unittestregion"
        self.account = "unittestaccount"
        self.name = "unittestname"


class PasswordPolicyTestCase(SecurityMonkeyTestCase):

    def test_1_5_uppercase_letters(self):
        from security_monkey.auditors.custom.cis.password_policy import PasswordPolicyAuditor
        auditor = PasswordPolicyAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        policy = MockPolicyItem()
        policy.config = {
            'RequireUppercaseCharacters': False
        }

        auditor.check_1_5_uppercase_letters(policy)
        self.assertIs(len(policy.audit_issues), 1)
        self.assertEquals(policy.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            policy.audit_issues[0].notes,
            'sa-iam-cis-1.5 - Password Policy should require uppercase letters.'
        )

        policy = MockPolicyItem()
        policy.config = {
            'RequireUppercaseCharacters': True
        }

        auditor.check_1_5_uppercase_letters(policy)
        self.assertIs(len(policy.audit_issues), 0)

        policy = MockPolicyItem()
        policy.config = {}

        auditor.check_1_5_uppercase_letters(policy)
        self.assertIs(len(policy.audit_issues), 1)
        self.assertEquals(
            policy.audit_issues[0].notes,
            'sa-iam-cis-1.5 - Account has no password policy.'
        )
