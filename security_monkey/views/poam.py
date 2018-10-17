"""
.. module: security_monkey.views.poam
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Pritam D. Gautam <pritam.gautam@nuagedm.com> @nuagedm

"""
from sqlalchemy.orm import joinedload, aliased, load_only, defer

from security_monkey import db, rbac
from security_monkey.views import AuthenticatedService
from security_monkey.datastore import Item, ItemAudit, Account, Technology, ItemRevision
from sqlalchemy import func, text, null as sqlnull, false, between


# Get a List of POA&M Items
class POAMItemList(AuthenticatedService):
    decorators = [rbac.allow(['View'], ["GET"])]

    def get(self):
        """
            .. http:get:: /api/1/poamitems

            Get a List of POA&M Items by account.

            **Example Request**:

            .. sourcecode:: http

                GET /api/1/poamitems HTTP/1.1
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
                                "item_id": "",
                                "account": "DEV",
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

        # SQL Query base for implementation
        # select
        #     distinct concat('sa_poam-', ia.id) as "poam_id",
        #         i.id as "item_id",
        #         acc.name as "account",
        #         t.name as "control",
        #         ia.issue as "weakness_name",
        #         concat(
        #             ia.notes, ', ', i.region, ', ', i.name
        #         ) as "weakness_description",
        #         ia.score,
        #         ir.create_date,
        #         ia.action_instructions as "poam_comments"
        #     from
        #         item i
        #         inner join itemaudit ia ON i.id = ia.item_id
        #         and (
        #             (i.account_id in  (select a.id from account a where a."name" in (p_account_id))  )
        #             or (p_account_id is null)
        #         )
        #         inner join technology t ON i.tech_id = t.id
        #         inner join (
        #             select
        #                 item_id,
        #                 min(date_created) as "create_date"
        #             from
        #                 itemrevision
        #             group by
        #                 item_id
        #         ) ir on i.id = ir.item_id
        #         inner join account acc ON i.account_id = acc.id
        #     where
        #         ia.justified = FALSE
        #         and ia.fixed = FALSE
        #         and i.arn is not null
        #         and ia.score > 1
        #     order by
        #         ir.create_date asc,
        #         ia.score desc

        self.reqparse.add_argument('accounts', type=str, default=None, location='args')
        self.reqparse.add_argument('count', type=int, default=10, location='args')
        self.reqparse.add_argument('page', type=int, default=1, location='args')
        self.reqparse.add_argument('sev', type=str, default=None, location='args')
        self.reqparse.add_argument('tech', type=str, default=None, location='args')

        args = self.reqparse.parse_args()
        page = args.pop('page', None)
        count = args.pop('count', None)
        for k, v in args.items():
            if not v:
                del args[k]

        # Read more about filtering:
        # https://docs.sqlalchemy.org/en/latest/orm/query.html
        query = Item.query.join((ItemAudit, Item.id == ItemAudit.item_id)) \
            .options(load_only(Item.id)) \
            .distinct()
        query = query.join((Technology, Technology.id == Item.tech_id))

        # Subquery on ItemRevision Table
        itemrevision_subquery = db.session \
            .query(ItemRevision, func.min(ItemRevision.date_created).label('create_date')) \
            .options(load_only("item_id")) \
            .group_by(ItemRevision.item_id) \
            .subquery()

        query = query.join(itemrevision_subquery, Item.id == itemrevision_subquery.c.item_id)
        query = query.join((Account, Account.id == Item.account_id))

        # Add Select Columns
        query = query \
            .add_column(func.concat('sa_poam-', ItemAudit.id).label('poam_id')) \
            .add_column(Account.name.label('account')) \
            .add_column(Technology.name.label('control')) \
            .add_column(ItemAudit.issue.label('weakness_name')) \
            .add_column(func.concat(ItemAudit.notes, ',', Item.region, ',', Item.name).label('weakness_description')) \
            .add_column(ItemAudit.score.label('score')) \
            .add_column(itemrevision_subquery.c.create_date.label('create_date')) \
            .add_column(ItemAudit.action_instructions.label('poam_comments'))

        # Filters
        query = query.filter(ItemAudit.justified == false())
        query = query.filter(ItemAudit.fixed == false())
        query = query.filter(ItemAudit.score > 1)
        query = query.filter(Item.arn != sqlnull())

        if 'accounts' in args:
            accounts = args['accounts'].split(',')
            query = query.filter(Account.name.in_(accounts))

        if 'sev' in args:
            sev = args['sev'].lower()
            if sev == 'low':
                query = query.filter(ItemAudit.score < 5)
            elif sev == 'medium':
                query = query.filter(between(ItemAudit.score, 5, 10))
            elif sev == 'high':
                query = query.filter(ItemAudit.score > 10)

        if 'tech' in args:
            tech = args['tech'].split(',')
            query = query.join((Technology, Technology.id == Item.tech_id))
            query = query.filter(Technology.name.in_(tech))



        # Order By
        query = query.order_by(itemrevision_subquery.c.create_date)
        query = query.order_by(ItemAudit.score.desc())

        # Eager load the joins
        query = query.options(joinedload('account'))
        query = query.options(joinedload('technology'))

        # Paginate
        items = query.paginate(page, count)

        marshaled_dict = {
            'page': items.page,
            'total': items.total,
            'auth': self.auth_dict
        }

        marshaled_items = []
        for row in items.items:
            row_dict = dict(row.__dict__)
            marshaled_items.append({
                'poam_id': row_dict['poam_id'],
                'item_id': row_dict['Item'].id,
                'account': row_dict['account'],
                'control': row_dict['control'],
                'weakness_name': row_dict['weakness_name'],
                'weakness_description': row_dict['weakness_description'],
                'score': row_dict['score'],
                'create_date': str(row_dict['create_date']),
                'poam_comments': row_dict['poam_comments']
            })

        marshaled_dict['items'] = marshaled_items
        marshaled_dict['count'] = len(marshaled_items)

        return marshaled_dict, 200
