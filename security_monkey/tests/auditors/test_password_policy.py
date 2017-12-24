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

    def test_1_6_lowercase_letters(self):
        from security_monkey.auditors.custom.cis.password_policy import PasswordPolicyAuditor
        auditor = PasswordPolicyAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        policy = MockPolicyItem()
        policy.config = {
            'RequireLowercaseCharacters': False
        }

        auditor.check_1_6_lowercase_letters(policy)
        self.assertIs(len(policy.audit_issues), 1)
        self.assertEquals(policy.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            policy.audit_issues[0].notes,
            'sa-iam-cis-1.6 - Password Policy should require lowercase letters.'
        )

        policy = MockPolicyItem()
        policy.config = {
            'RequireLowercaseCharacters': True
        }

        auditor.check_1_6_lowercase_letters(policy)
        self.assertIs(len(policy.audit_issues), 0)

        policy = MockPolicyItem()
        policy.config = {}

        auditor.check_1_6_lowercase_letters(policy)
        self.assertIs(len(policy.audit_issues), 1)
        self.assertEquals(
            policy.audit_issues[0].notes,
            'sa-iam-cis-1.6 - Account has no password policy.'
        )

    def test_1_7_require_symbole(self):
        from security_monkey.auditors.custom.cis.password_policy import PasswordPolicyAuditor
        auditor = PasswordPolicyAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        policy = MockPolicyItem()
        policy.config = {
            'RequireSymbols': False
        }

        auditor.check_1_7_require_symbols(policy)
        self.assertIs(len(policy.audit_issues), 1)
        self.assertEquals(policy.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            policy.audit_issues[0].notes,
            'sa-iam-cis-1.7 - Password Policy should require a symbol.'
        )

        policy = MockPolicyItem()
        policy.config = {
            'RequireSymbols': True
        }

        auditor.check_1_7_require_symbols(policy)
        self.assertIs(len(policy.audit_issues), 0)

        policy = MockPolicyItem()
        policy.config = {}

        auditor.check_1_7_require_symbols(policy)
        self.assertIs(len(policy.audit_issues), 1)
        self.assertEquals(
            policy.audit_issues[0].notes,
            'sa-iam-cis-1.7 - Account has no password policy.'
        )

    def test_1_8_require_numbers(self):
        from security_monkey.auditors.custom.cis.password_policy import PasswordPolicyAuditor
        auditor = PasswordPolicyAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        policy = MockPolicyItem()
        policy.config = {
            'RequireNumbers': False
        }

        auditor.check_1_8_require_numbers(policy)
        self.assertIs(len(policy.audit_issues), 1)
        self.assertEquals(policy.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            policy.audit_issues[0].notes,
            'sa-iam-cis-1.8 - Password Policy should require a number.'
        )

        policy = MockPolicyItem()
        policy.config = {
            'RequireNumbers': True
        }

        auditor.check_1_8_require_numbers(policy)
        self.assertIs(len(policy.audit_issues), 0)

        policy = MockPolicyItem()
        policy.config = {}

        auditor.check_1_8_require_numbers(policy)
        self.assertIs(len(policy.audit_issues), 1)
        self.assertEquals(
            policy.audit_issues[0].notes,
            'sa-iam-cis-1.8 - Account has no password policy.'
        )

    def test_1_9_password_policy_length(self):
        from security_monkey.auditors.custom.cis.password_policy import PasswordPolicyAuditor
        auditor = PasswordPolicyAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        policy = MockPolicyItem()
        policy.config = {
            'MinimumPasswordLength': 13
        }

        auditor.check_1_9_password_policy_length(policy)
        self.assertIs(len(policy.audit_issues), 1)
        self.assertEquals(policy.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            policy.audit_issues[0].notes,
            'sa-iam-cis-1.9 - Password Policy should require at least 14 characters.'
        )

        policy = MockPolicyItem()
        policy.config = {
            'MinimumPasswordLength': 14
        }

        auditor.check_1_9_password_policy_length(policy)
        self.assertIs(len(policy.audit_issues), 0)

        policy = MockPolicyItem()
        policy.config = {}

        auditor.check_1_9_password_policy_length(policy)
        self.assertIs(len(policy.audit_issues), 1)
        self.assertEquals(
            policy.audit_issues[0].notes,
            'sa-iam-cis-1.9 - Account has no password policy.'
        )

    def test_1_10_password_policy_reuse(self):
        from security_monkey.auditors.custom.cis.password_policy import PasswordPolicyAuditor
        auditor = PasswordPolicyAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        policy = MockPolicyItem()
        policy.config = {
            'PasswordReusePrevention': 23
        }

        auditor.check_1_10_password_policy_reuse(policy)
        self.assertIs(len(policy.audit_issues), 1)
        self.assertEquals(policy.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            policy.audit_issues[0].notes,
            'sa-iam-cis-1.10 - Password Policy should prevent password reuse.'
        )

        policy = MockPolicyItem()
        policy.config = {
            'PasswordReusePrevention': 24
        }

        auditor.check_1_10_password_policy_reuse(policy)
        self.assertIs(len(policy.audit_issues), 0)

        policy = MockPolicyItem()
        policy.config = {}

        auditor.check_1_10_password_policy_reuse(policy)
        self.assertIs(len(policy.audit_issues), 1)
        self.assertEquals(
            policy.audit_issues[0].notes,
            'sa-iam-cis-1.10 - Account has no password policy.'
        )


    def test_1_11_password_policy_expires(self):
        from security_monkey.auditors.custom.cis.password_policy import PasswordPolicyAuditor
        auditor = PasswordPolicyAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        policy = MockPolicyItem()
        policy.config = {
            'ExpirePasswords': False
        }

        auditor.check_1_11_password_policy_expires(policy)
        self.assertIs(len(policy.audit_issues), 1)
        self.assertEquals(policy.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            policy.audit_issues[0].notes,
            'sa-iam-cis-1.11 - Password Policy should expire passwords within 90 days.'
        )

        policy = MockPolicyItem()
        policy.config = {
            'ExpirePasswords': True,
            'MaxPasswordAge': 91
        }

        auditor.check_1_11_password_policy_expires(policy)
        self.assertIs(len(policy.audit_issues), 1)

        policy = MockPolicyItem()
        policy.config = {
            'ExpirePasswords': True,
            'MaxPasswordAge': 90
        }

        auditor.check_1_11_password_policy_expires(policy)
        self.assertIs(len(policy.audit_issues), 0)

        policy = MockPolicyItem()
        policy.config = {}

        auditor.check_1_11_password_policy_expires(policy)
        self.assertIs(len(policy.audit_issues), 1)
        self.assertEquals(
            policy.audit_issues[0].notes,
            'sa-iam-cis-1.11 - Account has no password policy.'
        )
