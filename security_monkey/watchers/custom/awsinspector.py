"""
.. module: security_monkey.watchers.custom.AwsInspector
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Pritam D. Gautam <pritam.gautam@nuagebiz.tech> @nuage

"""
from datetime import datetime, timedelta

from security_monkey import app
from security_monkey.decorators import iter_account_region, record_exception
from security_monkey.watcher import ChangeItem
from security_monkey.watcher import Watcher


class AwsInspector(Watcher):
    index = 'awsinspector'
    i_am_singular = 'AWS Inspector Issue'
    i_am_plural = 'AWS Inspector Issues'
    honor_ephemerals = False

    def __init__(self, accounts=None, debug=False):
        super(AwsInspector, self).__init__(accounts=accounts, debug=debug)

    @record_exception()
    def list_findings(self, **kwargs):
        from security_monkey.common.sts_connect import connect

        response_items = []
        inspector = connect(kwargs['account_name'], 'boto3.inspector.client', region=kwargs['region'],
                            assumed_role=kwargs['assumed_role'])

        next_token = None
        begin_date = datetime.today() - timedelta(days=90)
        while True:
            if next_token:
                response = self.wrap_aws_rate_limited_call(
                    inspector.list_findings,
                    nextToken=next_token,
                    filter={
                        'creationTimeRange': {
                            'beginDate': begin_date,
                        }
                    }
                )
            else:
                response = self.wrap_aws_rate_limited_call(
                    inspector.list_findings,
                    filter={
                        'creationTimeRange': {
                            'beginDate': begin_date,
                        }
                    }
                )

            findings = response.get('findingArns')
            if findings:
                response = self.wrap_aws_rate_limited_call(
                    inspector.describe_findings,
                    findingArns=findings,
                )
                response_items.extend(response.get('findings'))

            if response.get('nextToken'):
                next_token = response.get('nextToken')
            else:
                break

        return response_items

    def slurp(self):

        self.prep_for_slurp()

        @iter_account_region(index=self.index, accounts=self.accounts, service_name='inspector')
        def slurp_items(**kwargs):
            item_list = []
            exception_map = {}
            kwargs['exception_map'] = exception_map
            app.logger.debug("Checking {}/{}/{}".format(self.index,
                                                        kwargs['account_name'], kwargs['region']))
            findings = self.list_findings(**kwargs)

            if findings:
                for finding in findings:
                    name = None
                    if finding.get('Tags') is not None:
                        for tag in finding.get('Tags'):
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break

                    if name is None:
                        name = finding.get('title')

                    if self.check_ignore_list(name):
                        continue

                    config = finding
                    # Converting Date to String as getting the following error while inserting data.
                    # sqlalchemy.exc.StatementError: datetime.datetime(2018, 8, 18, 17, 23, 15, 413000, tzinfo=tzlocal())
                    # is not JSON serializable (original cause: TypeError: datetime.datetime(2018, 8, 18, 17, 23, 15, 413000,
                    #  tzinfo=tzlocal()) is not JSON serializable)
                    config['createdAt'] = str(config['createdAt'])
                    config['updatedAt'] = str(config['updatedAt'])
                    item = InspectorItem(region=kwargs['region'],
                                         account=kwargs['account_name'],
                                         name=name,
                                         arn=config.get('arn'),
                                         config=config)

                    item_list.append(item)

            return item_list, exception_map

        return slurp_items()


class InspectorItem(ChangeItem):
    def __init__(self, account=None, region='Unknown', name=None, arn=None, config=None, audit_issues=None):
        super(InspectorItem, self).__init__(
            index=AwsInspector.index,
            region=region,
            account=account,
            name=name,
            arn=arn,
            audit_issues=audit_issues,
            new_config=config if config else {},
        )
