"""
.. module: security_monkey.auditors.custom.AnchoreAuditor
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Pritam D. Gautam <pritam.gautam@nuagedm.com> @nuagedm

"""

from security_monkey.auditor import Auditor
from security_monkey.watchers.custom.anchoreengine import AnchoreEngine

ANCHORE_VULN_TAG = '{vulnid} Vulnerability'
ANCHORE_VULN_NOTES = '{pkg} package has {sev} vulnerability [{vulnid}]. ' \
                     'Repository: {reponame}:{repotag}. ' \
                     'Visit {INFO} for more details on vulnerability. '

class AnchoreAuditor(Auditor):
    index = AnchoreEngine.index
    i_am_singular = AnchoreEngine.i_am_singular
    i_am_plural = AnchoreEngine.i_am_plural

    def __init__(self, accounts=None, debug=False):
        super(AnchoreAuditor, self).__init__(accounts=accounts, debug=debug)


    def check_vuln_status(self, item):
        # Following is relationship between Vulnerability Severity Ratings & Score
        # Severity  |   Base Score Range    |   ThreatAlert Score
        # ----------+-----------------------+--------------------
        # Low       |   0.0-3.9             |   3
        # Medium    |   4.0-6.9             |   6
        # High 	    |   7.0-10.0            |   10
        # Unknown   |   -                   |   0
        #

        score_mapping = {'Low':3,'Medium':6,'High':10}

        if item.new_config:
            for vuln in item.new_config['vulns']:
                score = score_mapping.get(vuln['severity'],0)
                tag = ANCHORE_VULN_TAG.format(vulnid=vuln.get('vuln_id'))
                notes = ANCHORE_VULN_NOTES.format(pkg=item.new_config.get('pkg'), sev=vuln['severity'],
                                                  vulnid=vuln.get('vuln_id'),INFO=vuln.get('information'),
                                                  reponame=item.new_config.get('Reponame'),
                                                  repotag=item.new_config.get('RepoTag'))
                self.add_issue(score, tag , item, notes=notes)
