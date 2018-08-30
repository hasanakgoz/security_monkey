
"""
.. module: security_monkey.auditors.CIS4_124_Auditor
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Pritam D. Gautam <pritam.gautam@nuagedm.com> @nuagedm

"""

from security_monkey.auditor import Auditor, Entity
from security_monkey.watchers.security_group import SecurityGroup
from security_monkey import app
from security_monkey.watchers.vpc.peering import Peering


def _check_empty_security_group(sg_item):
    if app.config.get('SECURITYGROUP_INSTANCE_DETAIL', None) in ['SUMMARY', 'FULL'] and \
            not sg_item.config.get("assigned_to", None):
        return 0
    return 1


class CIS_4_124_Auditor(Auditor):
    INTERNET_ACCESSIBLE_NOTES_SG = '{entity} Access: [{access}]'

    index = SecurityGroup.index
    i_am_singular = SecurityGroup.i_am_singular
    i_am_plural = SecurityGroup.i_am_plural

    def __init__(self, accounts=None, debug=False):
        super(CIS_4_124_Auditor, self).__init__(accounts=accounts, debug=debug)

    def _port_for_rule(self, rule):
        """
        Looks at the from_port and to_port and returns a sane representation.
        """
        phrase = '{direction}:{protocol}:{port}'
        direction = rule.get('rule_type')
        protocol = rule['ip_protocol']
        port_range = '{0}-{1}'.format(rule['from_port'], rule['to_port'])

        if protocol == '-1':
            protocol = 'all_protocols'
            port_range = 'all_ports'

        elif rule['from_port'] == rule['to_port']:
            port_range = str(rule['from_port'])

        return phrase.format(direction=direction, protocol=protocol, port=port_range)

    def check_cis_4_1(self, item):
        """
        alert if EC2 SG contains an ingress from 0.0.0.0/0 to port 22 either explicit or implicit.

        As per AWS CIS Guide:
            It is recommended that no security group allows unrestricted ingress access to port 22.
            Note: A Port value of ALL or a port range such as 0-1024 are inclusive of port 22.
        """
        tag = "CIS 4.1 Security Group permits unrestricted ingress access to port 22"
        severity = 10
        multiplier = _check_empty_security_group(item)
        score = severity * multiplier
        direction = 'ingress'  # check for ingress traffic rules only

        for rule in item.config.get("rules", []):
            actions = self._port_for_rule(rule)
            cidr = rule.get("cidr_ip")
            from_port = rule['from_port']
            to_port = rule['to_port']
            protocol = rule['ip_protocol']

            entity = Entity(category='cidr', value=cidr)

            if protocol == '-1':
                cidr = '0.0.0.0/0'
                from_port = 0
                to_port = 65535

            app.logger.debug("Checking {}/{}/{}".format(self.index, actions, entity))

            if not rule.get("rule_type") == direction:
                # Skip egress rules
                continue

            if not str(cidr).endswith('/0'):
                # Skip rules that do not end with /0
                continue

            if not (from_port <= 22 <= to_port):
                # Skip rules which do not have reference to port 22
                continue

            notes = self.INTERNET_ACCESSIBLE_NOTES_SG
            notes = notes.format(entity=entity, access=actions)

            self.add_issue(score, tag, item, notes=notes)

    def check_cis_4_2(self, item):
        """
        alert if EC2 SG contains an ingress from 0.0.0.0/0 to port 3389 either explicit or implicit.

        As per AWS CIS Guide:
            It is recommended that no security group allows unrestricted ingress access to port 3389.
            Note: A Port value of ALL or a port range such as 1024-4000 are inclusive of port 3389.
        """
        tag = "CIS 4.2 Security Group permits unrestricted ingress access to port 3389"
        severity = 10
        multiplier = _check_empty_security_group(item)
        score = severity * multiplier
        direction = 'ingress'  # check for ingress traffic rules only

        for rule in item.config.get("rules", []):
            actions = self._port_for_rule(rule)
            cidr = rule.get("cidr_ip")
            from_port = rule['from_port']
            to_port = rule['to_port']
            protocol = rule['ip_protocol']

            entity = Entity(category='cidr', value=cidr)

            if protocol == '-1':
                cidr = '0.0.0.0/0'
                from_port = 0
                to_port = 65535

            app.logger.debug("Checking {}/{}/{}".format(self.index, actions, entity))

            if not rule.get("rule_type") == direction:
                # Skip egress rules
                continue

            if not str(cidr).endswith('/0'):
                # Skip rules that do not end with /0
                continue

            if not (from_port <= 3389 <= to_port):
                # Skip rules which do not have reference to port 3389
                continue

            notes = self.INTERNET_ACCESSIBLE_NOTES_SG
            notes = notes.format(entity=entity, access=actions)

            self.add_issue(score, tag, item, notes=notes)

    def check_cis_4_3(self, item):
        """
        alert if EC2 default Security Group contains any ingress or egress rules.

        """

        severity = 10
        multiplier = _check_empty_security_group(item)
        score = severity * multiplier

        for rule in item.config.get("rules", []):
            if rule.get('name') != 'default':
                continue

            tag = "CIS 4.3 Security Group permits unrestricted {} access".format(rule.get("rule_type"))
            actions = self._port_for_rule(rule)
            cidr = rule.get("cidr_ip")

            entity = Entity(category='cidr', value=cidr)

            app.logger.debug("Checking {}/{}/{}".format(self.index, actions, entity))

            notes = self.INTERNET_ACCESSIBLE_NOTES_SG
            notes = notes.format(entity=entity, access=actions)

            self.add_issue(score, tag, item, notes=notes)


class CIS_4_4_Auditor(Auditor):
    index = Peering.index
    i_am_singular = Peering.i_am_singular
    i_am_plural = Peering.i_am_plural

    def __init__(self, accounts=None, debug=False):
        super(CIS_4_4_Auditor, self).__init__(accounts=accounts, debug=debug)

    def check_cis_4_4(self, item):
        """
        4.4 Ensure routing tables for VPC peering are "least access" (Not Scored)

        """

        score = 10
        tag = "CIS 4.4 Ensure routing tables for VPC peering are least access"
        note = "Requester {req_cidr}, Acceptor {acceptor_cidr} has {status} status"

        requester = item.config.get("requester_vpc_info")
        acceptor = item.config.get("accepter_vpc_info")
        vpc_peering_id = item.config.get("vpc_peering_connection_id")
        vpc_peering_status = item.config["status"]["Code"]
        requester_cid = Entity(category='cidr', value=requester.get("CidrBlock"))
        acceptor_cidr = Entity(category='cidr', value=acceptor.get("CidrBlock"))
        note = note.format(
            peeringid=vpc_peering_id,
            req_cidr=requester_cid,
            acceptor_cidr=acceptor_cidr,
            status=vpc_peering_status)
        app.logger.debug("Checking {}/{}/{}/{}/{}".format(self.index, vpc_peering_id, requester_cid, acceptor_cidr, vpc_peering_status))

        self.add_issue(score, tag, item, notes=note)
