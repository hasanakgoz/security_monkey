"""
.. module: security_monkey.watchers.custom.AnchoreEngine
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Pritam D. Gautam <pritam.gautam@nuagedm.com> @nuagedm

Define following on your config file for using this module:

# Anchore Connection Configuration
ANCHORE_USER='XXX'
ANCHORE_PASS='XXX'
ANCHORE_URL='XXX'
ANCHORE_URL_SSL_VERIFY=True
ANCHORE_JSONMODE=False
ANCHORE_DEBUG=False
"""

from security_monkey.datastore import Account, AnchoreConfig
from security_monkey.watcher import Watcher
from security_monkey.watcher import ChangeItem
from security_monkey import app

import requests
import json
import re


def get_images(config):
    userId = config['user']
    password = config['pass']
    base_url = config['url']
    ret = {}
    base_url = re.sub("/$", "", base_url)
    app.logger.debug("Base = " + base_url)
    url = '/'.join([base_url, "images"])
    app.logger.debug("Url = " + url)

    try:
        app.logger.debug("GET url=" + str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'])
        ret = make_client_result(r, raw=False)
    except Exception as err:
        raise err
    return ret


def make_client_result(response, raw=False):
    ret = {
        'success': False,
        'httpcode': 0,
        'payload': {},
        'error': {}
    }
    try:
        ret['httpcode'] = response.status_code

        if response.status_code == 200:
            ret['success'] = True
            if raw == True:
                ret['payload'] = response.text
            else:
                try:
                    ret['payload'] = json.loads(response.text)
                except:
                    ret['payload'] = response.text
        else:
            ret['success'] = False
            if raw == True:
                ret['error'] = response.text
            else:
                try:
                    ret['error'] = json.loads(response.text)
                except:
                    ret['error'] = response.text
    except Exception as err:
        raise err
    return ret


def query_image(config, imageDigest=None, query_group="vuln", query_type="os", vendor_only=False):
    userId = config['user']
    password = config['pass']
    base_url = config['url']
    ret = {}
    base_url = re.sub("/$", "", base_url)
    url = '/'.join([base_url, "images", imageDigest])

    if query_group:
        url = '/'.join([url, query_group])
    else:
        raise Exception("need to specify a query group")

    if query_type:
        url = '/'.join([url, query_type])
    if query_group == 'vuln':
        url = url + "?vendor_only={}".format(vendor_only)

    try:
        app.logger.debug("GET url=" + str(url))
        r = requests.get(url, auth=(userId, password), verify=config['ssl_verify'])
        ret = make_client_result(r, raw=False)
    except Exception as err:
        raise err
    return ret


class AnchoreEngine(Watcher):
    index = 'anchore'
    i_am_singular = 'Anchore-Vuln'
    i_am_plural = 'Anchore-Vulns'

    def __init__(self, accounts=None, debug=False):
        super(AnchoreEngine, self).__init__(accounts=accounts, debug=debug)

    def _get_anchore_config(self, id):
        """
        :param name: name of the anchore image
        :return: config
        """
        anchore_result = AnchoreConfig.query.filter(AnchoreConfig.id == id).first()
        if not anchore_result:
            raise Exception("Anchore Entity with id [{}] not found.".format(id))
        config = {
            'user': anchore_result.username,
            'pass': anchore_result.password,
            'url': anchore_result.url,
            'ssl_verify': anchore_result.ssl_verify,
            'jsonmode': False,
            'debug': False,
        }
        return config


    def _list_anchore_configs(self):
        """
        :return: all records
        """
        # Get all anchore engine configuration records for matching accountids

        output = []
        try:
            anchore_results = AnchoreConfig.query.all()
            if not anchore_results:
                app.logger.debug('AnchoreEngine: No Anchore Entities found. Exiting Watcher-{}'.format(self.index))

            for anchore_result in anchore_results:
                config = {
                    'user': anchore_result.username,
                    'pass': anchore_result.password,
                    'url': anchore_result.url,
                    'ssl_verify': anchore_result.ssl_verify,
                    'jsonmode': False,
                    'debug': False,
                }
                output.append(config)
        except:
            return output
        return output


    def slurp(self):

        self.prep_for_slurp()
        item_list = []
        exception_map = {}
        flag_network = 0

        # # Check if Anchore has been properly configured
        # if (app.config.get('ANCHORE_USER') and app.config.get('ANCHORE_PASS') and app.config.get(
        #         'ANCHORE_URL')) == None:
        #     # Return Empty List
        #     app.logger.debug('AnchoreEngine: Skip processing no/bad configuration ')
        #     return
        #
        # # Set Appropriate Config for Anchore System
        # config = {
        #     'user': app.config.get('ANCHORE_USER'),
        #     'pass': app.config.get('ANCHORE_PASS'),
        #     'url': app.config.get('ANCHORE_URL'),
        #     'ssl_verify': app.config.get('ANCHORE_URL_SSL_VERIFY', False),
        #     'jsonmode': app.config.get('ANCHORE_JSONMODE', False),
        #     'debug': app.config.get('ANCHORE_DEBUG', False),
        # }

        # Set Appropriate Config for Anchore System
        configs = self._list_anchore_configs()
        if len(configs) == 0:
            return item_list, exception_map

        for config in configs:
            try:
                images = get_images(config)
                if not images['success']:
                    raise Exception("####Images Not Fetched####")
                images = images['payload']
            except Exception as e:
                app.logger.debug('AnchoreEngine: Exiting Watcher-{}'.format(self.index) + e)
                return

            for image in images:
                image_digest = image[u'image_detail'][0][u'imageDigest']
                image_fulltag = image[u'image_detail'][0][u'fulltag']

                # Find Account Id from image_fulltag
                data = image_fulltag.split(".")

                # Find Account Name from the account id to send in the anchore item
                identifier = data[0]

                if identifier not in self.account_identifiers:
                    app.logger.debug(
                        "AnchoreEngine: Skipping image {} for account(s) {}".format(image[u'image_detail'][0][u'fulltag'],
                                                                                    str(",".join(self.accounts))))
                    # Skip processing images that are not tied to this account.
                    continue

                account = Account.query.filter(Account.identifier == identifier).first()
                # Assumption region is part of URL where url is in this format '150676063069.dkr.ecr.us-east-1.amazonaws.com/insights:latest'
                region = (image_fulltag.split("/")[0]).split(".")[-3]

                app.logger.debug(
                    "AnchoreEngine: Slurping image {} for account {}".format(image[u'image_detail'][0][u'fulltag'],
                                                                             account.name))
                try:
                    image_data = query_image(config, image_digest)
                    vulnerabilities = image_data['payload'][u'vulnerabilities']
                except Exception as e:
                    app.logger.debug('AnchoreEngine: Skipping Image -{}'.format(image[u'image_detail'][0][u'fulltag']) + e)
                    continue

                # Create Empty Packages List
                packages = {}
                for vuln in vulnerabilities:

                    single_vuln = {
                        'package': vuln['package'],
                        'fix': vuln['fix'],
                        'vuln_id': vuln['vuln'],
                        'severity': vuln['severity'],
                        'description': None,
                        'information': vuln['url']
                    }

                    if vuln['package'] in packages:
                        packages[vuln['package']].append(single_vuln)
                    else:
                        packages[vuln['package']] = [single_vuln]

                for pack in packages:
                    item_config = {
                        'AwsAccountId': account.identifier,
                        'Reponame': image[u'image_detail'][0][u'repo'],
                        'RepoTag': image[u'image_detail'][0][u'tag'],
                        'OS': image[u'image_content'][u'metadata'][u'distro'],
                        'OSversion': image[u'image_content'][u'metadata'][u'distro_version'],
                        'pkg': pack,
                        'vulns': packages[pack],
                    }

                    item_name = "{reponame}:{repotag}/{package}".format(reponame=image[u'image_detail'][0][u'repo'],
                                                                        repotag=image[u'image_detail'][0][u'tag'],
                                                                        package=pack)

                    item = AnchoreItem(account=account.name, region=region, name=item_name, config=item_config,
                                       arn='arn:anchore:{}/{}'.format(image_fulltag,pack))
                    item_list.append(item)
        if flag_network == 1:
            return
        else:
            return item_list, exception_map


class AnchoreItem(ChangeItem):
    def __init__(self, account=None, region='Unknown', name=None, arn=None, config=None):
        super(AnchoreItem, self).__init__(
            index=AnchoreEngine.index,
            region=region,
            account=account,
            name=name,
            arn=arn,
            new_config=config if config else {},
        )
