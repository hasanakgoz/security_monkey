from flask import Response
from flask.blueprints import Blueprint
from sqlalchemy import String, func
from sqlalchemy.sql.expression import cast

from security_monkey import rbac
from security_monkey.datastore import Item, ItemRevision, Account, Technology, ItemAudit

servicenow_blueprint = Blueprint("servicenow", __name__)


@servicenow_blueprint.route("/servicenow/report/item/<itemid>")
@rbac.allow(roles=["View"], methods=["GET"])
def report_incident(itemid):
    query = Item.query.join((ItemRevision, Item.latest_revision_id == ItemRevision.id))
    query = query.join((Account, Item.account_id == Account.id))  # Join for Account Identifier
    query = query.join((ItemAudit, Item.id == ItemAudit.item_id))  # Join for notes, score
    query = query.join((Technology, Item.tech_id == Technology.id))  # Join for Technology Name
    query = query.filter(Item.id == itemid)

    # # Eager load the joins and leave the config column out of this.
    # query = query.options(joinedload('issues'))
    # # Now loaded by the join on line 29 I think...
    # query = query.options(joinedload('revisions')) #.defer('config'))
    # query = query.options(joinedload('account'))
    # query = query.options(joinedload('technology'))

    query = query.order_by(ItemRevision.date_created.desc())

    # Add Select Columns
    query = query \
        .add_column(func.concat('sa_poam-', ItemAudit.id).label('poam_id')) \
        .add_column(Account.identifier.label('account')) \
        .add_column(Technology.name.label('control')) \
        .add_column(ItemAudit.issue.label('weakness_name')) \
        .add_column(func.concat(ItemAudit.notes, ',', Item.region, ',', Item.name).label('weakness_description')) \
        .add_column(ItemAudit.score.label('score')) \
        .add_column(ItemAudit.action_instructions.label('poam_comments')) \
        .add_column(cast(ItemRevision.config, String).label('config'))

    row_dict = dict(query.first().__dict__)

    payload_dict = {
        # 'poam_id': row_dict['poam_id'],
        # 'item_id': row_dict['Item'].id,
        # 'account': row_dict['account'],
        'caused_by': row_dict['control'],
        # 'weakness_name': row_dict['weakness_name'],
        'short_description': row_dict['weakness_description'],
        'impact': row_dict['score'],
        # 'create_date': str(row_dict['create_date']),
        'description': row_dict['config']
    }

    import requests
    import json

    url = "https://dev71680.service-now.com/api/now/table/incident"
    username = 'admin'
    password = 'oe8JIMrpi0SQ'

    payload = str(payload_dict)
    headers = {
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
    }

    response = requests.post(url, auth=requests.auth.HTTPBasicAuth(username, password), json=payload_dict,
                             headers=headers)

    if response.status_code == 201:
        return Response('Incident ' + (json.loads(response.content))['result']['number'] + ' opened, successfully.')
    else:
        return Response('An error occured while opening an incident. Please get in touch with your system administrator.')
    # return Response(out, mimetype='text/csv',
    #                 headers={"Content-disposition": "attachment; filename=security-monkey-items.csv"})
