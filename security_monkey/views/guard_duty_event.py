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
    AuditorSettings,
    Datastore
)
from security_monkey import db, rbac


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

        account = Account.query.filter(Account.identifier == config['account']).first()

        if not account:
            raise Exception(
                "Account with identifier [{}] not found.".format(config['account'])
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
