
"""
.. module: security_monkey.views.GuardDutyEventMapPointsList
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Pritam D. Gautam <pritam.gautam@nuagedm.com> @nuagedm

"""
import datetime

from flask import jsonify, request
from security_monkey import db, rbac
from security_monkey.views import AuthenticatedService
from security_monkey.views import AuthenticatedService
from security_monkey.datastore import (
    GuardDutyEvent,
    Item,
    ItemAudit,
    Account,
    AccountType,
    Technology,
    AuditorSettings,
    Datastore
)

# Returns a list of Map Circle Marker Points List
class GuardDutyEventMapPointsList(AuthenticatedService):
    decorators = [rbac.allow(['View'], ["GET"])]

    def get(self):
        """
            .. http:get:: /api/1/worldmapguarddutydata

            Get a list of World Map Data points matching the given criteria.

            **Example Request**:

            .. sourcecode:: http

                GET /api/1/worldmapguarddutydata HTTP/1.1
                Host: example.com
                Accept: application/json

            **Example Response**:

            .. sourcecode:: http

                HTTP/1.1 200 OK
                Vary: Accept
                Content-Type: application/json
                {
                    "auth": {
                        "authenticated": true,
                        "roles": [
                            {
                                "name": "Admin"
                            },
                            {
                                "name": "Justify"
                            },
                            {
                                "name": "Comment"
                            },
                            {
                                "name": "View"
                            }
                        ],
                        "user": "admin@example.org"
                    },
                    "items": [
                                {
                                    "cityName": "Mar del Plata",
                                    "count": 1,
                                    "countryName": "Argentina",
                                    "lat": -38.0,
                                    "localPort": 22.0,
                                    "localPortName": "SSH",
                                    "lon": -57.55,
                                    "remoteIpV4": "186.62.51.117",
                                    "remoteOrg": "Telefonica de Argentina",
                                    "remoteOrgASN": 22927.0,
                                    "remoteOrgASNOrg": "Telefonica de Argentina",
                                    "remoteOrgISP": "Telefonica de Argentina"
                                }
                            ],
                    "page": 1,
                    "total": 197
                }

            :statuscode 200: no error
            :statuscode 401: Authentication Error. Please Login.
        """

        # Reference query as provided by Rick
        #     select
        #   g.item_id,
        #   g.config -> 'detail' -> 'service' -> 'action' -> 'portProbeAction' -> 'portProbeDetails' as "guarddutyjson"
        # from item i
        #   inner join itemaudit ia on i.id = ia.item_id
        #   inner join guarddutyevent g ON i.id = g.item_id
        # where coalesce(justified, FALSE) = FALSE
        #   and coalesce(fixed, FALSE) = FALSE
        #   and g.config -> 'detail' -> 'service' -> 'action' -> 'portProbeAction' -> 'portProbeDetails' is not NULL;
        #     """
        self.reqparse.add_argument('accounts', type=str, default=None, location='args')
        args = self.reqparse.parse_args()
        for k, v in args.items():
            if not v:
                del args[k]


        # Read more about filtering:
        # https://docs.sqlalchemy.org/en/latest/orm/query.html
        from sqlalchemy.sql.functions import coalesce
        query = GuardDutyEvent.query.with_entities(
            GuardDutyEvent.item_id, GuardDutyEvent.config[('detail', 'service', 'action', 'portProbeAction',
                                                           'portProbeDetails')]) \
            .join((Item, Item.id == GuardDutyEvent.item_id), (ItemAudit, Item.id == ItemAudit.item_id)) \
            .filter((coalesce(ItemAudit.justified, False) == False), (coalesce(ItemAudit.fixed, False) == False),
                    (GuardDutyEvent.config[
                         ('detail', 'service', 'action', 'portProbeAction', 'portProbeDetails')] != None))
        if 'accounts' in args:
            accounts = args['accounts'].split(',')
            query = query.join((Account, Account.id == Item.account_id))
            query = query.filter(Account.name.in_(accounts))

        records = query.all()
        items = []

        if len(records) > 0:
            import pandas as pd
            from ..flatten import flatten_json
            flatten_records = (flatten_json(record[1][0]) for record in records)
            fulldata_dataFrame = pd.DataFrame(flatten_records).rename(
                columns={'remoteIpDetails_geoLocation_lat': 'lat', 'remoteIpDetails_geoLocation_lon': 'lon',
                         'localPortDetails_port': 'localPort', 'localPortDetails_portName': 'localPortName',
                         'remoteIpDetails_city_cityName': 'cityName', 'remoteIpDetails_country_countryName': 'countryName',
                         'remoteIpDetails_ipAddressV4': 'remoteIpV4', 'remoteIpDetails_organization_asn': 'remoteOrgASN',
                         'remoteIpDetails_organization_asnOrg': 'remoteOrgASNOrg',
                         'remoteIpDetails_organization_isp': 'remoteOrgISP',
                         'remoteIpDetails_organization_org': 'remoteOrg', 'counts': 'count'})

            mapdata_dataframe = fulldata_dataFrame.groupby(['lat', 'lon']).size().reset_index(name='count').merge(
                fulldata_dataFrame.drop_duplicates(keep='first', subset=['lat', 'lon']), on=['lat', 'lon'], how='left')

            items = mapdata_dataframe.to_dict('records')

        marshaled_dict = {
            'page': 1,
            'total': len(items),
            'auth': self.auth_dict,
            'items': items
        }
        return marshaled_dict, 200


# Returns a list of Top 10 Countries by number of probe events received to display in Bar Chart
class GuardDutyEventTop10Countries(AuthenticatedService):
    decorators = [rbac.allow(['View'], ["GET"])]

    def get(self):
        """
            .. http:get:: /api/1/top10countryguarddutydata

            Get a list of Top 10 Countries by number of probe events received to display in Bar Chart

            **Example Request**:

            .. sourcecode:: http

                GET /api/1/worldmapguarddutydata HTTP/1.1
                Host: example.com
                Accept: application/json

            **Example Response**:

            .. sourcecode:: http

                HTTP/1.1 200 OK
                Vary: Accept
                Content-Type: application/json
                {
                    "auth": {
                        "authenticated": true,
                        "roles": [
                            {
                                "name": "Admin"
                            },
                            {
                                "name": "Justify"
                            },
                            {
                                "name": "Comment"
                            },
                            {
                                "name": "View"
                            }
                        ],
                        "user": "admin@example.org"
                    },
                    "items": [
                        {
                            "count": 1527,
                            "countryName": "China"
                        },
                        {
                            "count": 456,
                            "countryName": "United States"
                        },
                        {
                            "count": 116,
                            "countryName": "Russia"
                        },
                    ],
                    "page": 1,
                    "total": 197
                }

            :statuscode 200: no error
            :statuscode 401: Authentication Error. Please Login.
        """
        self.reqparse.add_argument('accounts', type=str, default=None, location='args')
        args = self.reqparse.parse_args()
        for k, v in args.items():
            if not v:
                del args[k]

        # Reference query as provided by Rick
        #     select
        #   g.item_id,
        #   g.config -> 'detail' -> 'service' -> 'action' -> 'portProbeAction' -> 'portProbeDetails' as "guarddutyjson"
        # from item i
        #   inner join itemaudit ia on i.id = ia.item_id
        #   inner join guarddutyevent g ON i.id = g.item_id
        # where coalesce(justified, FALSE) = FALSE
        #   and coalesce(fixed, FALSE) = FALSE
        #   and g.config -> 'detail' -> 'service' -> 'action' -> 'portProbeAction' -> 'portProbeDetails' is not NULL;
        #     """

        # Read more about filtering:
        # https://docs.sqlalchemy.org/en/latest/orm/query.html
        from sqlalchemy.sql.functions import coalesce
        query = GuardDutyEvent.query.with_entities(
            GuardDutyEvent.item_id, GuardDutyEvent.config[('detail', 'service', 'action', 'portProbeAction',
                                                           'portProbeDetails')]) \
            .join((Item, Item.id == GuardDutyEvent.item_id), (ItemAudit, Item.id == ItemAudit.item_id)) \
            .filter((coalesce(ItemAudit.justified, False) == False), (coalesce(ItemAudit.fixed, False) == False),
                    (GuardDutyEvent.config[
                         ('detail', 'service', 'action', 'portProbeAction', 'portProbeDetails')] != None))

        if 'accounts' in args:
            accounts = args['accounts'].split(',')
            query = query.join((Account, Account.id == Item.account_id))
            query = query.filter(Account.name.in_(accounts))

        records = query.all()
        items = []

        if len(records) > 0:
            import pandas as pd
            from ..flatten import flatten_json
            flatten_records = (flatten_json(record[1][0]) for record in records)
            fulldata_dataFrame = pd.DataFrame(flatten_records).rename(
                columns={'remoteIpDetails_geoLocation_lat': 'lat', 'remoteIpDetails_geoLocation_lon': 'lon',
                         'localPortDetails_port': 'localPort', 'localPortDetails_portName': 'localPortName',
                         'remoteIpDetails_city_cityName': 'cityName', 'remoteIpDetails_country_countryName': 'countryName',
                         'remoteIpDetails_ipAddressV4': 'remoteIpV4', 'remoteIpDetails_organization_asn': 'remoteOrgASN',
                         'remoteIpDetails_organization_asnOrg': 'remoteOrgASNOrg',
                         'remoteIpDetails_organization_isp': 'remoteOrgISP',
                         'remoteIpDetails_organization_org': 'remoteOrg', 'counts': 'count'})

            # Sorting and Limiting the resultset to 10
            items = fulldata_dataFrame.groupby(['countryName']).size().reset_index(
                name='count').sort_values(['count'], ascending=False).head(10).to_dict('records')

        marshaled_dict = {
            'page': 1,
            'total': len(items),
            'auth': self.auth_dict,
            'items': items
        }
        return marshaled_dict, 200


class GuardDutyEventService(AuthenticatedService):
    decorators = [
        rbac.allow(["Admin"], ["POST"])
    ]

    def post(self):

        datastore = Datastore()

        config = request.get_json(force=True)
        #action_type = config['detail']['service']['action']['actionType']
        action_type = 'guardduty'

        gd_tech = Technology.query.filter(Technology.name == action_type).first()
        if not gd_tech:
            gd_tech = Technology(name=action_type)
            db.session.add(gd_tech)
            db.session.commit()
            db.session.refresh(gd_tech)

        identifier = config['detail']['accountId']
        account = Account.query.filter(Account.identifier == identifier).first()

        if not account:
            raise Exception(
                "Account with identifier [{}] not found.".format(identifier)
            )

        item = datastore.store(
            gd_tech.name,
            config['region'],
            account.name,
            config['detail']['type'],
            True,
            config
        )

        auditor_settings = AuditorSettings.query.filter(
            AuditorSettings.auditor_class=='GuardDuty',
            AuditorSettings.tech_id==gd_tech.id,
            AuditorSettings.account_id==account.id
        ).first()

        if not auditor_settings:
            auditor_settings = AuditorSettings(
                disabled=False,
                issue_text='Guard Duty',
                auditor_class='GuardDuty',
                tech_id=gd_tech.id,
                account_id=account.id
            )
            db.session.add(auditor_settings)
            db.session.commit()
            db.session.refresh(auditor_settings)

        issue = ItemAudit(
            score=int(config['detail']['severity']),
            issue=config['detail']['title'],
            notes=config['detail']['description'],
            item_id=item.id,
            auditor_setting_id=auditor_settings.id,
        )
        db.session.add(issue)
        db.session.commit()
        db.session.refresh(issue)

        gd_event = GuardDutyEvent(
            item_id=item.id,
            config=config,
            date_created=datetime.datetime.utcnow()
        )

        db.session.add(gd_event)
        db.session.commit()
        db.session.refresh(gd_event)

        return {
            'id': gd_event.id,
            'config': gd_event.config,
        }, 201

