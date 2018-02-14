from security_monkey.tests import SecurityMonkeyTestCase


class MockItem:
    def __init__(self):
        self.config = {}
        self.audit_issues = []
        self.index = "unittestindex"
        self.region = "unittestregion"
        self.account = "unittestaccount"
        self.name = "unittestname"


class RouteTableTestCase(SecurityMonkeyTestCase):

    def test_4_5_route_tables_are_least_access(self):
        from security_monkey.auditors.custom.cis.route_table import RouteTableAuditor
        auditor = RouteTableAuditor(accounts=['TEST_ACCOUNT'])
        auditor.prep_for_audit()

        route_table = MockItem()
        route_table.config = {
            "routes": [
                {
                    "gateway_id": "local",
                    "vpc_peering_connection_id": "123",
                    "nat_gateway_id": None,
                    "interface_id": None,
                    "instance_id": None,
                    "state": "active",
                    "destination_cidr_block": "172.32.0.0/16"
                }
            ]
        }

        auditor.check_4_5_ensure_route_tables_are_least_access(route_table )
        self.assertIs(len(route_table.audit_issues), 1)
        self.assertEquals(route_table.audit_issues[0].issue, 'Informational')
        self.assertEquals(
            route_table .audit_issues[0].notes,
            'sa-cis-4.5 - Large CIDR block routed to peer discovered, please investigate.'
        )

        route_table = MockItem()
        route_table.config = {
            "routes": [
                {
                    "gateway_id": "local",
                    "vpc_peering_connection_id": None,
                    "nat_gateway_id": None,
                    "interface_id": None,
                    "instance_id": None,
                    "state": "active",
                    "destination_cidr_block": "172.32.0.0/16"
                }
            ]
        }

        auditor.check_4_5_ensure_route_tables_are_least_access(route_table)
        self.assertIs(len(route_table.audit_issues), 0)

        route_table = MockItem()
        route_table.config = {
            "routes": [
                {
                    "gateway_id": "local",
                    "vpc_peering_connection_id": "123",
                    "nat_gateway_id": None,
                    "interface_id": None,
                    "instance_id": None,
                    "state": "active",
                    "destination_cidr_block": "172.32.0.0/24"
                }
            ]
        }

        auditor.check_4_5_ensure_route_tables_are_least_access(route_table)
        self.assertIs(len(route_table.audit_issues), 0)
