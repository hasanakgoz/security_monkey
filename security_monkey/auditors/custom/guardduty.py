"""
.. module: security_monkey.auditors.custom.GuardDutyAuditor
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Pritam D. Gautam <pritam.gautam@nuagedm.com> @nuage

"""

from security_monkey.auditor import Auditor
from security_monkey.watchers.custom.guardduty import GuardDuty


class GuardDutyAuditor(Auditor):
    index = GuardDuty.index
    i_am_singular = GuardDuty.i_am_singular
    i_am_plural = GuardDuty.i_am_plural

    def __init__(self, accounts=None, debug=False):
        super(GuardDutyAuditor, self).__init__(accounts=accounts, debug=debug)

    def check_finding(self, item):
        # Add a default issue for each GuardDuty Finding
        if item.new_config:
            issue = item.new_config
            self.add_issue(
                score=int(issue.get('Severity')),
                issue=issue.get('Title'),
                notes=issue.get('Description'),
                item=item
            )
