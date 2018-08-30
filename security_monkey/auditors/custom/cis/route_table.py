"""
.. module: security_monkey.auditors.custom.cis.route_table
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor::  Hammad Hai <hammad.a.hai@gmail.com>

"""

from security_monkey.auditor import Categories, Auditor
from security_monkey.watchers.vpc.route_table import RouteTable


class RouteTableAuditor(Auditor):
    index = RouteTable.index
    i_am_singular = RouteTable.i_am_singular
    i_am_plural = RouteTable.i_am_plural

    def check_4_4_ensure_route_tables_are_least_access(self, item):
        """
        CIS Rule 4.5 (v1.10)/ 4.4 (v1.2.0) - Ensure routing tables for VPC peering are "least access"
        (Not Scored)
        """
        issue = Categories.INFORMATIONAL
        notes = Categories.INFORMATIONAL_NOTES.format(
            description='sa-cis-4.4 - ',
            specific='Large CIDR block routed to peer discovered, please investigate.'
        )
        for route in item.config.get('routes', []):
            if route['vpc_peering_connection_id']:
                if int(str(route['destination_cidr_block']).split('/', 1)[1]) < 24:
                    self.add_issue(
                        10,
                        issue,
                        item,
                        notes=notes
                    )
