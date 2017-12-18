import csv

from security_monkey.watcher import Watcher
from security_monkey.watcher import ChangeItem
from security_monkey.exceptions import (
    BotoConnectionIssue,
    CredentialReportException,
)
from security_monkey import app, ARN_PREFIX

class CredentialReportWatcher(Watcher):
    index = 'credreport'
    i_am_singular = 'Credential Report'
    i_am_plural = 'Credential Reports'

    def __init__(self, accounts=None, debug=False):
        super(CredentialReportWatcher, self).__init__(accounts=accounts, debug=debug)

    def slurp(self):
        """
        :returns: item_list - list of credential reports.
        :returns: exception_map - A dict where the keys are a tuple containing the
            location of the exception and the value is the actual exception
        """
        self.prep_for_slurp()
        item_list = []
        exception_map = {}

        from security_monkey.common.sts_connect import connect
        for account in self.accounts:
            try:
                iam = connect(account, 'boto3.iam.client')
            except Exception as e:
                exc = BotoConnectionIssue(str(e), 'iamcredreport', account, None)
                self.slurp_exception((self.index, account, 'universal'), exc, exception_map,
                                     source="{}-watcher".format(self.index))
                continue

            try:
                app.logger.debug('Generating credential report for account {}'.format(account))
                iam.generate_credential_report()

                app.logger.debug('Getting credential report for account {}'.format(account))
                response = iam.get_credential_report()

                credential_report = csv.DictReader(open(response['Content'], 'rb'))
            except Exception as e:
                # credential report is not ready yet, pull it the next time
                exc = CredentialReportException(str(e), 'iamcredreport', account, None)
                self.slurp_exception((self.index, account, 'universal'), exc, exception_map,
                                     source="{}-watcher".format(self.index))
                continue

            for user_report in credential_report:
                item_list.append(
                    UserReport(
                        account=account,
                        config=user_report,
                        name=user_report['user'],
                    )
                )

        return item_list, exception_map


class UserReport(ChangeItem):
    def __init__(self, account=None, name=None, region=None, config={}):
        super(UserReport, self).__init__(
                index=CredentialReportWatcher.index,
                region=region,
                account=account,
                name=name,
                new_config=config)
