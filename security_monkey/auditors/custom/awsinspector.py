"""
.. module: security_monkey.auditors.custom.AwsInspectorAuditor
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Pritam D. Gautam <pritam.gautam@nuagebiz.tech> @nuage

"""

from security_monkey import app
from security_monkey.auditor import Auditor
from security_monkey.watchers.custom.awsinspector import AwsInspector


class AwsInspectorAuditor(Auditor):
    index = AwsInspector.index
    i_am_singular = AwsInspector.i_am_singular
    i_am_plural = AwsInspector.i_am_plural

    def __init__(self, accounts=None, debug=False):
        super(AwsInspectorAuditor, self).__init__(accounts=accounts, debug=debug)

    def check_finding(self, item):
        # Add a default issue for each AWS Inspector Finding
        if item.new_config:
            issue = item.new_config
            app.logger.debug("Adding {}/{}".format(self.index,
                                                   issue.get(u'title')))
            self.add_issue(score=int(issue.get(u'numericSeverity')),
                           issue=issue.get(u'title'),
                           item=item,
                           notes=issue.get(u'description'),
                           action_instructions=issue.get(u'recommendation'))
