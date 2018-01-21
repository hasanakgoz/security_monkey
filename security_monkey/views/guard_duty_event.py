import datetime

from flask import jsonify, request
from security_monkey.views import AuthenticatedService
from security_monkey.datastore import (
    GuardDutyEvent,
    Item,
    ItemAudit,
    Account,
    AccountType,
    Technology,
)
from security_monkey import db, rbac


class GuardDutyEventService(AuthenticatedService):
    decorators = [
        rbac.allow(["Admin"], ["POST"])
    ]

    def post(self):

        config = request.get_json(force=True)
        #action_type = config['detail']['service']['action']['actionType']
        action_type = 'guardduty'

        gd_tech = Technology.query.filter(Technology.name == action_type).first()
        if not gd_tech:
            gd_tech = Technology(name=action_type)
            db.session.add(gd_tech)
            db.session.commit()
            db.session.refresh(gd_tech)

        account = Account.query.filter(Account.identifier == config['account']).first()

        if not account:
            account_type = AccountType.query.filter(AccountType.name=='AWS').first()

            if not account_type:
                account_type = AccountType(name='AWS')
                db.session.add(account_type)
                db.session.commit()
                db.session.refresh(account_type)

            account = Account(
                active=True,
                third_party=False,
                identifier=config['account'],
                account_type_id=account_type.id,
            )
            db.session.add(account)
            db.session.commit()
            db.session.refresh(account)

        item = Item.query.filter(
            Item.region==config['region'],
            Item.name==config['detail']['type'],
            Item.tech_id==gd_tech.id,
            Item.account_id==account.id,
        ).first()

        if not item:
            item = Item(
                region=config['region'],
                name=config['detail']['type'],
                tech_id=gd_tech.id,
                account_id=account.id,
            )
            db.session.add(item)
            db.session.commit()
            db.session.refresh(item)

        issue = ItemAudit(
            score=int(config['detail']['severity']),
            issue=config['detail']['title'],
            notes=config['detail']['description'],
            item_id=item.id,
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
