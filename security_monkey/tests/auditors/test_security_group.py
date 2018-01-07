from security_monkey.tests import SecurityMonkeyTestCase


class MockItem:
    def __init__(self):
        self.config = {}
        self.audit_issues = []
        self.index = "unittestindex"
        self.region = "unittestregion"
        self.account = "unittestaccount"
        self.name = "unittestname"


class SecurityGroupTestCase(SecurityMonkeyTestCase):

    def test_4_1_ssh_not_open_to_the_world(self):
        from security_monkey.auditors.custom.cis.security_group import CISSecurityGroupAuditor
        auditor = CISSecurityGroupAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        security_group = MockItem()
        security_group.config = {
            "id": "test",
            "rules": [
                {
                    "rule_type": "egress",
                    "from_port": 22,
                    "ip_protocol": "ssh",
                    "to_port": 22,
                    "owner_id": None,
                    "group_id": None,
                    "cidr_ip": "0.0.0.0/0",
                    "name": None
                },
            ],
        }

        auditor.check_4_1_ssh_not_open_to_world(security_group)
        self.assertIs(len(security_group.audit_issues), 1)
        self.assertEquals(security_group.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            security_group.audit_issues[0].notes,
            'sa-cis-4.1 - Found Security Group [test] with port 22 open to the world (0.0.0.0/0).'
        )

        security_group = MockItem()
        security_group.config = {
            "id": "test",
            "rules": [
                {
                    "rule_type": "egress",
                    "from_port": None,
                    "ip_protocol": "-1",
                    "to_port": None,
                    "owner_id": None,
                    "group_id": None,
                    "cidr_ip": "0.0.0.0/0",
                    "name": None
                },
            ],
        }

        auditor.check_4_1_ssh_not_open_to_world(security_group)
        self.assertIs(len(security_group.audit_issues), 1)

        security_group = MockItem()
        security_group.config = {
            "id": "test",
            "rules": [
                {
                    "rule_type": "egress",
                    "from_port": None,
                    "ip_protocol": "-1",
                    "to_port": None,
                    "owner_id": None,
                    "group_id": None,
                    "cidr_ip": "1.2.3.4/0",
                    "name": None
                },
            ],
        }

        auditor.check_4_1_ssh_not_open_to_world(security_group)
        self.assertIs(len(security_group.audit_issues), 0)

    def test_4_2_rdp_not_open_to_the_world(self):
        from security_monkey.auditors.custom.cis.security_group import CISSecurityGroupAuditor
        auditor = CISSecurityGroupAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        security_group = MockItem()
        security_group.config = {
            "id": "test",
            "rules": [
                {
                    "rule_type": "egress",
                    "from_port": 3389,
                    "ip_protocol": "ssh",
                    "to_port": 3389,
                    "owner_id": None,
                    "group_id": None,
                    "cidr_ip": "0.0.0.0/0",
                    "name": None
                },
            ],
        }

        auditor.check_4_2_rdp_not_open_to_world(security_group)
        self.assertIs(len(security_group.audit_issues), 1)
        self.assertEquals(security_group.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            security_group.audit_issues[0].notes,
            'sa-cis-4.2 - Found Security Group [test] with port 3389 open to the world (0.0.0.0/0).'
        )

        security_group = MockItem()
        security_group.config = {
            "id": "test",
            "rules": [
                {
                    "rule_type": "egress",
                    "from_port": None,
                    "ip_protocol": "-1",
                    "to_port": None,
                    "owner_id": None,
                    "group_id": None,
                    "cidr_ip": "0.0.0.0/0",
                    "name": None
                },
            ],
        }

        auditor.check_4_2_rdp_not_open_to_world(security_group)
        self.assertIs(len(security_group.audit_issues), 1)

        security_group = MockItem()
        security_group.config = {
            "id": "test",
            "rules": [
                {
                    "rule_type": "egress",
                    "from_port": None,
                    "ip_protocol": "-1",
                    "to_port": None,
                    "owner_id": None,
                    "group_id": None,
                    "cidr_ip": "1.2.3.4/0",
                    "name": None
                },
            ],
        }

        auditor.check_4_2_rdp_not_open_to_world(security_group)
        self.assertIs(len(security_group.audit_issues), 0)

    def test_4_4_default_security_groups_restricts_traffic(self):
        from security_monkey.auditors.custom.cis.security_group import CISSecurityGroupAuditor
        auditor = CISSecurityGroupAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        security_group = MockItem()
        security_group.config = {
            "id": "test",
            "name": "default",
            "rules": [
                {
                    "rule_type": "egress",
                    "from_port": 3389,
                    "ip_protocol": "ssh",
                    "to_port": 3389,
                    "owner_id": None,
                    "group_id": None,
                    "cidr_ip": "0.0.0.0/0",
                    "name": None
                },
            ],
        }

        auditor.check_4_4_default_security_groups_restricts_traffic(security_group)
        self.assertIs(len(security_group.audit_issues), 1)
        self.assertEquals(security_group.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            security_group.audit_issues[0].notes,
            'sa-cis-4.4 - Default security group with ingress or egress rules discovered.'
        )

        security_group = MockItem()
        security_group.config = {
            "id": "test",
            "name": "default",
            "rules": [],
        }

        auditor.check_4_4_default_security_groups_restricts_traffic(security_group)
        self.assertIs(len(security_group.audit_issues), 0)
