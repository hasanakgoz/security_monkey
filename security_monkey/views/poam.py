"""
.. module: security_monkey.views.poam
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Pritam D. Gautam <pritam.gautam@nuagedm.com> @nuagedm

"""

from security_monkey import db, rbac
from security_monkey.views import AuthenticatedService
from sqlalchemy import func, text, null as sqlnull


# Get a List of POA&M Items
class POAMItemList(AuthenticatedService):
    decorators = [rbac.allow(['View'], ["GET"])]

    def get(self):
        """
            .. http:get:: /api/1/poamlist

            Get a List of POA&M Items by account.

            **Example Request**:

            .. sourcecode:: http

                GET /api/1/items HTTP/1.1
                Host: example.com
                Accept: application/json

            **Example Response**:

            .. sourcecode:: http

                HTTP/1.1 200 OK
                Vary: Accept
                Content-Type: application/json

                {
                    "items": [
                            {
                                "control": "policy",
                                "create_date": "2017-11-01 19:29:52.329638",
                                "poam_comments": null,
                                "poam_id": "sa_poam-12868",
                                "score": 10,
                                "weakness_description": "Service [iam] Category: [Permissions] Resources: [\"*\"], universal, ServiceCatalogAdmin-SupplementalPermissions",
                                "weakness_name": "Sensitive Permissions"
                            }
                        ],
                    "total": 1,
                    "page": 1,
                    "count" 1,
                    "auth": {
                        "authenticated": true,
                        "user": "user@example.com"
                    }
                }

            :statuscode 200: no error
            :statuscode 401: Authentication Error. Please Login.
        """

        self.reqparse.add_argument('accounts', type=str, default=None, location='args')
        self.reqparse.add_argument('limit', type=int, default=10, location='args')
        self.reqparse.add_argument('offset', type=int, default=0, location='args')
        args = self.reqparse.parse_args()
        sqlsql = text('select * from select_poam_items_summary(:account, :limit, :offset)')

        baseQuery = db.session.execute(sqlsql,{'account':args['accounts'], 'limit':args['limit'], 'offset':args['offset']}).fetchall()

        marshaled_items = []

        for row in baseQuery:
            _item_marshalled = dict(row)
            _item_marshalled['create_date'] = str(_item_marshalled['create_date'])
            marshaled_items.append(_item_marshalled)

        marshaled_dict = {
            'page': 1,
            'total': 1,
            'count': 1,
            'auth': self.auth_dict,
            'items': marshaled_items
        }
        return marshaled_dict, 200
