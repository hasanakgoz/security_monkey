import csv
import time

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

            timeout = 0
            error = None

            app.logger.debug('Generating credential report for account {}'.format(account))
            while iam.generate_credential_report()['State'] != "COMPLETE":
                time.sleep(2)
                timeout += 1
                # If no credentail report is delivered within this time fail the check.
                if timeout > 5:
                    error = "Timeout: No CredentialReport available."
                    app.logger.error(error)
                    exc = CredentialReportException(
                        error,
                        'iamcredreport',
                        account,
                        None
                    )
                    self.slurp_exception((self.index, account, 'universal'), exc, exception_map,
                                     source="{}-watcher".format(self.index))
                    break

            if error:
                continue

            app.logger.debug('Getting credential report for account {}'.format(account))
            response = iam.get_credential_report()
            credential_report = csv.DictReader(response['Content'].splitlines(), delimiter=',')

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
