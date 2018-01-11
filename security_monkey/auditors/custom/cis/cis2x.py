
"""
.. module: security_monkey.auditors.custom.cis.CIS2_36_Auditor
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Pritam D. Gautam <pritam.gautam@nuagedm.com> @nuagedm

"""
from security_monkey.auditor import Auditor, Entity
from security_monkey.watchers.cloud_trail import CloudTrail
from security_monkey.watchers.s3 import S3


class CIS2_36_Auditor(Auditor):
    index = CloudTrail.index
    i_am_singular = CloudTrail.i_am_singular
    i_am_plural = CloudTrail.i_am_plural
    support_watcher_indexes = [S3.index]

    def __init__(self, accounts=None, debug=False):
        super(CIS2_36_Auditor, self).__init__(accounts=accounts, debug=debug)

    def prep_for_audit(self):
        super(CIS2_36_Auditor, self).prep_for_audit()
        self.INTERNET_ACCESSIBLE = [
            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'.lower(),
            'http://acs.amazonaws.com/groups/global/AllUsers'.lower()]

    def check_cis_2_3(self, cloud_trail):
        """
        alert if S3 bucket CloudTrail logs is publicly accessible.

        As per AWS CIS Guide:
            CloudTrail logs a record of every API call made in your AWS account. These logs file are stored in an
            S3 bucket. It is recommended that the bucket policy or access control list (ACL) applied to the S3 bucket
            that CloudTrail logs to prevents public access to the CloudTrail logs.
        """
        tag = "CIS 2.3 Ensure the S3 bucket CloudTrail logs to is not publicly accessible"

        s3_bucket_name = cloud_trail.config.get('s3_bucket_name')
        s3_watcher_items = self.get_watcher_support_items(S3.index, cloud_trail.account)
        notes = "{entity}"

        for item in s3_watcher_items:
            if item.name != s3_bucket_name:
                continue
            acl = item.config.get('Grants', {})
            owner = item.config["Owner"]["ID"].lower()
            for key in acl.keys():
                if key.lower() not in self.INTERNET_ACCESSIBLE:
                    continue

                # Canonical ID == Owning Account - No issue
                if key.lower() == owner.lower():
                    continue

                entity = Entity(category='ACL', value=self.INTERNET_ACCESSIBLE)
                account = self._get_account('aws', self.INTERNET_ACCESSIBLE)
                if account:
                    entity.account_name = account['name']
                    entity.account_identifier = account['identifier']

                issue = tag + " - " + str(s3_bucket_name) + " has " + str(acl[key][0]).decode()
                notes = notes.format(entity=entity)
                self.add_issue(score=10, issue=issue, item=cloud_trail, notes=notes)

    def check_cis_2_6(self, cloud_trail):
        """
        alert if S3 bucket access logging is not enabled on the CloudTrail S3 bucket

        As per AWS CIS Guide:
            S3 Bucket Access Logging generates a log that contains access records for each request made to your
            S3 bucket. An access log record contains details about the request, such as the request type, the
            resources specified in the request worked, and the time and date the request was processed. It is
            recommended that bucket access logging be enabled on the CloudTrail S3 bucket.
        """

        tag = "CIS 2.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket "
        notes = "Access Logging is not enabled on CloudTrail S3 bucket {s3_bucket_name}"

        s3_bucket_name = cloud_trail.config.get('s3_bucket_name')

        s3_watcher_items = self.get_watcher_support_items(S3.index, cloud_trail.account)

        for item in s3_watcher_items:
            if item.name != s3_bucket_name:
                continue
            logging = item.config.get('Logging', {})
            if logging == {} or not logging.get('enabled'):
                notes = notes.format(s3_bucket_name=s3_bucket_name)
                self.add_issue(10, tag, cloud_trail, notes=notes)
