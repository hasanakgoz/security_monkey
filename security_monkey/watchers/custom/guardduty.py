"""
.. module: security_monkey.watchers.custom.GuardDuty
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Pritam D. Gautam <pritam.gautam@nuagedm.com> @nuage

"""

from security_monkey.watcher import Watcher
from security_monkey.watcher import ChangeItem
from security_monkey.exceptions import BotoConnectionIssue
from security_monkey import app


class GuardDuty(Watcher):
    index = 'guardduty'
    i_am_singular = 'GuardDuty Event'
    i_am_plural = 'GuardDuty Events'
    honor_ephemerals = False

    def __init__(self, accounts=None, debug=False):
        super(GuardDuty, self).__init__(accounts=accounts, debug=debug)

    def slurp(self):

        self.prep_for_slurp()
        item_list = []
        exception_map = {}

        from security_monkey.common.sts_connect import connect
        for account in self.accounts:
            gd_findings = []

            try:
                # Establish connection with AWS using Boto3
                client = connect(account, 'boto3.guardduty.client')

                # Get list of all detector ids associated
                gd_detector_ids = self._list_gd_detector_ids(client)

                # Process all the detectors
                for detector_id in gd_detector_ids:
                    app.logger.debug('GuardDuty: Processing detector:  {}'.format(detector_id))
                    gd_findings = self._list_findings(client, detector_id)

            except Exception as e:
                exc = BotoConnectionIssue(str(e), self.index, account, None)
                self.slurp_exception((self.index, account, 'universal'), exc, exception_map,
                                     source="{}-watcher".format(self.index))
                continue

            for gd_finding in gd_findings:
                item = GuardDutyItem(account=account, arn=gd_finding.get('Arn'), region=gd_finding.get('Region'),
                                     name=gd_finding.get('Title'), config=gd_finding)
                item_list.append(item)

        return item_list, exception_map

    """
    Get a list of all detector ids associated with the client
    """

    def _list_gd_detector_ids(self, client):
        next_token = u''
        gd_detector_ids = []
        while True:
            detectors_list = client.list_detectors(
                NextToken=next_token
            )
            # Response may not contain NextToken
            next_token = detectors_list.get('NextToken', u'')
            gd_detector_ids += list(detectors_list.get('DetectorIds'))
            if not next_token:
                break
        return gd_detector_ids

    """
    Get a list of all findings for all associated account identifiers
    """

    def _list_findings(self, client, detector_id):
        next_token = u''
        gd_findings = []
        while True:
            _finding_ids = client.list_findings(
                DetectorId=detector_id,
                FindingCriteria={'Criterion': {'accountId': {'Eq': self.account_identifiers}}},
                NextToken=next_token
            )
            next_token = _finding_ids.get('NextToken', u'')

            _findings = []
            if len(_finding_ids[u'FindingIds']) > 0:
                _findings = client.get_findings(
                    DetectorId=detector_id,
                    FindingIds=_finding_ids[u'FindingIds']
                )
            gd_findings += list(_findings.get(u'Findings'))
            if not next_token:
                break

        return gd_findings


class GuardDutyItem(ChangeItem):
    def __init__(self, account=None, region='Unknown', name=None, arn=None, config=None, audit_issues=None):
        super(GuardDutyItem, self).__init__(
            index=GuardDuty.index,
            region=region,
            account=account,
            name=name,
            arn=arn,
            audit_issues=audit_issues,
            new_config=config if config else {},
        )
