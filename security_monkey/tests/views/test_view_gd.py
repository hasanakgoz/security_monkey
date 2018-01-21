#     Copyright 2016 Bridgewater Associates
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
"""
.. module: security_monkey.tests.test_view_gd
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Hammad Hai <hammad.a.hai@gmail.com>

"""
from security_monkey.tests.views import SecurityMonkeyApiTestCase
from security_monkey.datastore import (
    Item,
    ItemAudit,
    ItemRevision,
    GuardDutyEvent,
    Account,
    AccountType,
    AuditorSettings
)
from security_monkey.tests import db
from security_monkey import ARN_PREFIX

from datetime import datetime, timedelta
import json


class GuardDutyViewsTestCase(SecurityMonkeyApiTestCase):

    def test_guard_duty_post_issue(self):

        account_type = AccountType(name='test')
        db.session.add(account_type)
        db.session.commit()
        db.session.refresh(account_type)

        account = Account(
            active=True,
            third_party=False,
            name='TEST',
            identifier="123",
            account_type_id=account_type.id
        )
        db.session.add(account)
        db.session.commit()
        db.session.refresh(account)

        test_data = {
            "account": "123",
            "region": "us-east-1",
            "detail": {
                "description": "EC2 instance has an unprotected port which is being probed by a known malicious host.",
                "resource": {
                    "resourceType": "Instance",
                    "instanceDetails": {
                        "productCodes": [],
                        "availabilityZone": "us-east-1b",
                        "tags": [
                            {
                                "value": "stackarmor Tools",
                                "key": "Name"
                            }
                        ],
                        "instanceId": "i-036cb01d26bb09166",
                        "instanceState": "running",
                        "imageDescription": "",
                        "imageId": "ami-3181d827",
                        "launchTime": 1497058274000,
                        "iamInstanceProfile": {
                            "id": "AIPAIB2MSH55V2UVVRQGS",
                            "arn": "arn:aws:iam::726064622671:instance-profile/SimpleCloudBuilderRole"
                        },
                        "instanceType": "t2.micro",
                        "networkInterfaces": [
                            {
                                "vpcId": "vpc-76181913",
                                "publicDnsName": "ec2-54-91-89-220.compute-1.amazonaws.com",
                                "subnetId": "subnet-1b900f30",
                                "privateIpAddresses": [
                                    {
                                        "privateDnsName": "ip-10-0-0-128.ec2.internal",
                                        "privateIpAddress": "10.0.0.128"
                                    }
                                ],
                                "publicIp": "54.91.89.220",
                                "privateDnsName": "ip-10-0-0-128.ec2.internal",
                                "securityGroups": [
                                    {
                                        "groupName": "wellarchitected-framework-security-group",
                                        "groupId": "sg-a534fcd9"
                                    },
                                    {
                                        "groupName": "stackarmor-access-group",
                                        "groupId": "sg-f736fe8b"
                                    }
                                ],
                                "ipv6Addresses": [],
                                "privateIpAddress": "10.0.0.128"
                            }
                        ]
                    }
                },
                "severity": 2,
                "service": {
                    "count": 1,
                    "additionalInfo": {
                        "threatName": "Scanner",
                        "threatListName": "ProofPoint"
                    },
                    "archived": False,
                    "resourceRole": "TARGET",
                    "eventFirstSeen": "2018-01-08T00:43:49Z",
                    "detectorId": "a8b006e056e2d054c79f0a8f26820e00",
                    "action": {
                        "portProbeAction": {
                            "portProbeDetails": [
                                {
                                    "remoteIpDetails": {
                                        "organization": {
                                            "org": "NexG Co.",
                                            "isp": "NexG Co.",
                                            "asn": 17877,
                                            "asnOrg": "NexG Co., LTD"
                                        },
                                        "ipAddressV4": "221.132.75.236",
                                        "city": {
                                            "cityName": "Seoul"
                                        },
                                        "geoLocation": {
                                            "lat": 37.5111,
                                            "lon": 126.9743
                                        },
                                        "country": {
                                            "countryName": "South Korea"
                                        }
                                    },
                                    "localPortDetails": {
                                        "portName": "SSH",
                                        "port": 22
                                    }
                                },
                                {
                                    "remoteIpDetails": {
                                        "organization": {
                                            "org": "CariNet",
                                            "isp": "CariNet",
                                            "asn": 10439,
                                            "asnOrg": "CariNet, Inc."
                                        },
                                        "ipAddressV4": "71.6.167.142",
                                        "city": {
                                            "cityName": "San Diego"
                                        },
                                        "geoLocation": {
                                            "lat": 32.8073,
                                            "lon": -117.1324
                                        },
                                        "country": {
                                            "countryName": "United States"
                                        }
                                    },
                                    "localPortDetails": {
                                        "portName": "Unknown",
                                        "port": 81
                                    }
                                }
                            ],
                            "blocked": False
                        },
                        "actionType": "PORT_PROBE"
                    },
                    "serviceName": "guardduty",
                    "eventLastSeen": "2018-01-08T00:44:46Z"
                },
                "title": "Unprotected port on EC2 instance i-036cb01d26bb09166 is being probed.",
                "region": "us-east-1",
                "partition": "aws",
                "createdAt": "2018-01-08T00:52:34.750Z",
                "updatedAt": "2018-01-08T00:52:34.750Z",
                "schemaVersion": "2.0",
                "type": "Recon:EC2/PortProbeUnprotectedPort",
                "id": "c0b069a09b9f39764cf3d9e44251e079",
                "arn": "arn:aws:guardduty:us-east-1:726064622671:detector/a8b006e056e2d054c79f0a8f26820e00/finding/c0b069a09b9f39764cf3d9e44251e079",
                "accountId": "726064622671"
            },
            "detail-type": "GuardDuty Finding",
            "source": "aws.guardduty",
            "version": "0",
            "time": "1970-01-01T00:00:00Z",
            "id": "9fd36791-b982-24d8-738c-d8e2c69a48dd",
            "resources": []
        }

        assert GuardDutyEvent.query.count() == 0
        assert Item.query.count() == 0
        assert ItemRevision.query.count() == 0
        assert ItemAudit.query.count() == 0
        assert AuditorSettings.query.count() == 0

        response = self.test_app.post('/api/1/gde', headers=self.token_headers, data=json.dumps(test_data))

        assert response.status_code == 201
        assert GuardDutyEvent.query.count() == 1
        assert Item.query.count() == 1
        assert ItemRevision.query.count() == 1
        assert ItemAudit.query.count() == 1
        assert AuditorSettings.query.count() == 1
