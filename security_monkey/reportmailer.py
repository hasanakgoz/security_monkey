"""
.. module: security_monkey.watchers.custom.GuardDuty
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Pritam D. Gautam <pritam.gautam@nuagebiz.tec> @nuage

"""
from datetime import datetime, timedelta

from sqlalchemy import false, true, case, literal_column
from sqlalchemy.exc import OperationalError, InvalidRequestError, StatementError
from sqlalchemy.sql.functions import count as sqlcount, sum, coalesce, func

from security_monkey import app, db
from security_monkey.common.jinja import get_jinja_env
from security_monkey.common.utils import send_email
from security_monkey.datastore import Technology, Item, ItemAudit, Account, ItemRevision


def create_report(account_name, account_identifier, days=1, debug=True):
    """
    Finds all the reporting items for the account, and using a Jinja template, create a report that can be emailed.

    :param days:
    :param account_name:
    :param account_identifier:
    :param debug:
    :return: HTML - The output of the rendered template.
    """

    jenv = get_jinja_env()
    template = jenv.get_template('ta_daily_summary_report.html')

    _top_unjustfix_findings = get_top_x_findings_by_account(account_name)
    _top_tech_unjustfix_findings = get_top_x_technologies_by_account(account_name)
    _recent_findings = get_top_x_recent_findings(account_name, days)
    _top_recent_justified_findings = get_top_x_recent_justified_findings(account_name, days)
    _recent_guardduty_findings = get_guardduty_findings(account_name, days)

    _report_date = datetime.today().strftime('%a, %d %b %Y')

    return template.render(
        {'report_date': _report_date, 'account_identifier': account_identifier, 'account_name': account_name,
         'top_unjustfix_findings': _top_unjustfix_findings,
         'top_tech_unjustfix_findings': _top_tech_unjustfix_findings,
         'recent_findings': _recent_findings,
         'top_recent_justified_findings': _top_recent_justified_findings,
         'recent_guardduty_findings': _recent_guardduty_findings})


def email_report(report, recipients):
    """
    Given a report, send an email .
    """
    if not report:
        app.logger.info("No report.  Not sending email.")
        return
    _report_date = datetime.today().strftime('%a, %d %b %Y')

    subject = "stackArmor ThreatAlert Report for {} ".format(_report_date)
    send_email(subject=subject, recipients=recipients, html=report)


def report_mailer(accounts, days=1):
    """
    Runs Mail Reporter to send reports for last (period) days
    :param interval:
    :param accounts:
    :return:
    """

    try:
        for account in accounts:
            _account_info = Account.query.filter(Account.name == account).limit(1).all()
            if not _account_info:
                app.logger.info("No Account identified with this name {}".format(account))
                continue

            if not _account_info[0].email_address or not _account_info[0].active:
                app.logger.info("No email address associated with this account {}".format(account))
                continue

            _masked_identifier = 'XXXXXXXX{}'.format(_account_info[0].identifier[-4:])
            report = create_report(account_name=account, account_identifier=_masked_identifier, days=days,
                                   debug=True)
            recipients = _account_info[0].email_address.split(',')
            email_report(report, recipients=recipients)
    except (OperationalError, InvalidRequestError, StatementError) as e:
        app.logger.exception("Database error processing accounts %s, cleaning up session.", accounts)
        db.session.remove()


def get_top_x_findings_by_account(account, num_findings=5, debug=True):
    """
    Get Customer's Top X (5) Unjustified/Unfixed Findings
    :param account:
    :param num_findings:
    :param debug:
    :return: marshalled dict of findings
    """
    # /* CUSTOMER'S TOP X (5) UNJUSTIFIED/UNFIXED FINDINGS */
    # select distinct t.name,
    #       ia.issue,
    #       count(1) as "total_findings"
    # from item i
    # inner join itemaudit ia on i.id = ia.item_id
    # inner join technology t on i.tech_id = t.id
    # inner join account a on i.account_id = a.id
    # where a.identifier = '150676063069'
    # and ia.justified = false
    # and ia.fixed = false
    # and ia.notes not like '%[egress:%'
    # and score > 7
    # group by t.name, ia.issue
    # order by count(1) desc
    # limit 5;

    # Read more about filtering:
    # https://docs.sqlalchemy.org/en/latest/orm/query.html

    # Lookup tables
    query = Technology.query.with_entities(Technology.name, ItemAudit.issue,
                                           sqlcount(1).label('total_findings')).distinct()
    query = query.join(Item, Item.tech_id == Technology.id)
    query = query.join(ItemAudit, Item.id == ItemAudit.item_id)
    query = query.join((Account, Account.id == Item.account_id))

    # Lookup filters
    query = query.filter(Account.name == account)
    query = query.filter(ItemAudit.justified == false())
    query = query.filter(ItemAudit.fixed == false())
    query = query.filter(ItemAudit.notes.notilike('%[egress:%'))
    query = query.filter(ItemAudit.score > 7)

    # Result grouping and ordering
    query = query.group_by(Technology.name)
    query = query.group_by(ItemAudit.issue)
    query = query.order_by(sqlcount(1).desc())

    # Get records
    items = query.limit(num_findings).all()

    marshaled_items = []

    for row in items:
        row_dict = dict(row.__dict__)
        marshaled_items.append({
            'name': row_dict['name'].capitalize(),
            'issue': row_dict['issue'].capitalize(),
            'total_findings': row_dict['total_findings']
        })

    marshaled_response = {
        'items': marshaled_items,
        'count': num_findings
    }

    return marshaled_response


def get_top_x_technologies_by_account(account, num_findings=5, debug=True):
    """
    Get Customer's overall top X (5) technologies with findings current and not-fixed/justified
    :param account:
    :param num_findings:
    :param debug:
    :return:
    """

    # /* CUSTOMER'S OVERALL TOP X (5) TECHNOLOGIES WITH FINDINGS CURRENT AND NOT-FIXED/JUSTIFIED */
    # select distinct t.name,
    #       count(1) as "total_findings"
    # from item i
    # inner join itemaudit ia on i.id = ia.item_id
    # inner join technology t on i.tech_id = t.id
    # inner join account a on i.account_id = a.id
    # where a.identifier = '150676063069'
    # and ia.notes not like '%[egress:%'
    # and score > 7
    # group by t.name
    # order by count(1) desc
    # limit 5;

    query = Technology.query.with_entities(Technology.name,
                                           sqlcount(1).label('total_findings')).distinct()
    query = query.join(Item, Item.tech_id == Technology.id)
    query = query.join(ItemAudit, Item.id == ItemAudit.item_id)
    query = query.join((Account, Account.id == Item.account_id))

    # Lookup filters
    query = query.filter(Account.name == account)
    query = query.filter(ItemAudit.justified == false())
    query = query.filter(ItemAudit.fixed == false())
    query = query.filter(ItemAudit.notes.notilike('%[egress:%'))
    query = query.filter(ItemAudit.score > 7)

    # Result grouping and ordering
    query = query.group_by(Technology.name)
    query = query.order_by(sqlcount(1).desc())

    # Get records
    items = query.limit(num_findings).all()

    marshaled_items = []

    for row in items:
        row_dict = dict(row.__dict__)
        marshaled_items.append({
            'name': row_dict['name'].capitalize(),
            'total_findings': row_dict['total_findings']
        })

    marshaled_response = {
        'items': marshaled_items,
        'count': num_findings
    }

    return marshaled_response


def get_top_x_recent_findings(account, days, num_findings=10, debug=True):
    """
    Get Customer's X (10) most recent findings
    :param interval:
    :param account:
    :param num_findings:
    :param debug:
    :return:
    """

    # /* CUSTOMER'S X (10) MOST RECENT FINDINGS */
    # select distinct t.name as "technology",
    #       ia.issue as "finding",
    #       ia.notes
    # from item i
    # inner join itemaudit ia on i.id = ia.item_id
    # inner join technology t on i.tech_id = t.id
    # inner join itemrevision ir on i.id = ir.item_id
    # inner join account a on i.account_id = a.id
    # where a.identifier = '150676063069'
    # and ia.justified = false
    # and ia.fixed = false
    # and ia.notes not like '%[egress:%'
    # and ir.date_created >= '2018-08-06 00:00:00.000001'
    # order by ia.score desc
    # limit 10;

    query = Technology.query.with_entities(Technology.name, ItemAudit.issue,
                                           ItemAudit.notes)
    query = query.join(Item, Item.tech_id == Technology.id)
    query = query.join(ItemAudit, Item.id == ItemAudit.item_id)
    query = query.join(ItemRevision, Item.id == ItemRevision.item_id)
    query = query.join((Account, Account.id == Item.account_id))

    # Lookup filters
    query = query.filter(Account.name == account)
    query = query.filter(ItemAudit.justified == false())
    query = query.filter(ItemAudit.fixed == false())
    query = query.filter(ItemAudit.notes.notilike('%[egress:%'))
    query = query.filter(ItemAudit.score > 7)
    query = query.filter(ItemRevision.date_created >= (datetime.now() - timedelta(days=days)).date())

    # Result grouping and ordering
    query = query.order_by(ItemAudit.score.desc())

    # Get records
    items = query.limit(num_findings).all()

    marshaled_items = []

    for row in items:
        row_dict = dict(row.__dict__)
        marshaled_items.append({
            'technology': row_dict['name'].capitalize(),
            'finding': row_dict['issue'],
            'notes': row_dict['notes']
        })

    marshaled_response = {
        'items': marshaled_items,
        'count': num_findings
    }

    return marshaled_response


def get_top_x_recent_justified_findings(account, days, num_findings=10, debug=True):
    """
    Get Customer's X (10) most recent justified/fixed findings
    :param interval:
    :param account:
    :param num_findings:
    :param debug:
    :return:
    """

    # /* CUSTOMER'S X (10) MOST RECENT JUSTIFIED/FIXED FINDINGS */
    # ---- Query Part 1 ---
    # select distinct t.name as "technology",
    #       ia.issue as "finding",
    #       ia.notes,
    #       ia.justified_date
    # from item i
    # inner join itemaudit ia on i.id = ia.item_id
    # inner join technology t on i.tech_id = t.id
    # inner join account a on i.account_id = a.id
    # where a.identifier = '150676063069'
    # and ia.justified = true
    # and ia.notes not like '%[egress:%'
    # and ia.justified_date >= '2018-08-06 00:00:00.000001'

    query_1 = Technology.query.with_entities(Technology.name, ItemAudit.issue,
                                             ItemAudit.notes, ItemAudit.justified_date)
    query_1 = query_1.join(Item, Item.tech_id == Technology.id)
    query_1 = query_1.join(ItemAudit, Item.id == ItemAudit.item_id)
    query_1 = query_1.join(ItemRevision, Item.id == ItemRevision.item_id)
    query_1 = query_1.join((Account, Account.id == Item.account_id))

    # Lookup filters
    query_1 = query_1.filter(Account.name == account)
    query_1 = query_1.filter(ItemAudit.justified == true())
    query_1 = query_1.filter(ItemAudit.notes.notilike('%[egress:%'))
    query_1 = query_1.filter(ItemAudit.justified_date >= (datetime.now() - timedelta(days=days)).date())

    # --- Query Part 2 ---
    # union
    # select distinct t.name as "technology",
    #       ia.issue as "finding",
    #       ia.notes,
    #       ia.justified_date
    # from item i
    # inner join itemaudit ia on i.id = ia.item_id
    # inner join technology t on i.tech_id = t.id
    # inner join itemrevision ir on i.id = ir.item_id
    # inner join account a on i.account_id = a.id
    # where a.identifier = '150676063069'
    # and ia.fixed = true
    # and ia.notes not like '%[egress:%'
    # and ir.date_last_ephemeral_change >= '2018-08-06 00:00:00.000001'
    # limit 10;

    query_2 = Technology.query.with_entities(Technology.name, ItemAudit.issue,
                                             ItemAudit.notes, ItemAudit.justified_date)
    query_2 = query_2.join(Item, Item.tech_id == Technology.id)
    query_2 = query_2.join(ItemAudit, Item.id == ItemAudit.item_id)
    query_2 = query_2.join(ItemRevision, Item.id == ItemRevision.item_id)
    query_2 = query_2.join((Account, Account.id == Item.account_id))

    # Lookup filters
    query_2 = query_2.filter(Account.name == account)
    query_2 = query_2.filter(ItemAudit.fixed == true())
    query_2 = query_2.filter(ItemAudit.notes.notilike('%[egress:%'))
    query_2 = query_2.filter(ItemRevision.date_last_ephemeral_change >= (datetime.now() - timedelta(days=days)).date())

    # Get records
    items = query_1.union(query_2).limit(num_findings).all()

    marshaled_items = []

    for row in items:
        row_dict = dict(row.__dict__)
        marshaled_items.append({
            'technology': row_dict['name'].capitalize(),
            'finding': row_dict['issue'],
            'notes': row_dict['notes'],
            'justified_date': row_dict['justified_date']
        })

    marshaled_response = {
        'items': marshaled_items,
        'count': num_findings
    }

    return marshaled_response


def get_guardduty_findings(account, days, num_findings=99999999, debug=True):
    """
    Get a list of recent GuardDuty Findings
    :param account:
    :param days:
    :param num_findings:
    :param debug:
    :return:
    """

    # select case
    #          when ia.score > 7 then 'High'
    #          when ia.score >= 5 and ia.score <= 7 then 'Medium'
    #          else 'Low'
    #            end as Severity,
    #        i.name,
    #        ia.issue
    # from item i
    # inner join itemaudit ia on i.id = ia.item_id
    # inner join account a on i.account_id = a.id
    #   and a.identifier = '726064622671'           -- ACCOUNT IDENTIFIER PARAMETER
    # inner join (select item_id,
    #               max(date_created) as "last_updated"
    #             from itemrevision group by item_id) ir on i.id = ir.item_id
    #   and ir.last_updated >= '2018-01-01 06:03:39.394533'    -- DATE PARAMETER
    # inner join technology t on i.tech_id = t.id
    #   and t.name = 'guardduty'
    # where coalesce (ia.justified, false) is false
    #   and coalesce (ia.fixed, false) is false;


    subquery = ItemRevision.query.with_entities(ItemRevision.item_id.label('item_id'), func.max(ItemRevision.date_created).label('last_updated'))
    subquery = subquery.group_by(ItemRevision.item_id).subquery('ir')

    query = Item.query.with_entities(Item.name, ItemAudit.issue,
                                           case([
                                               (ItemAudit.score > 7 , 'High'),
                                               (ItemAudit.score.between(4,8) , 'Medium'),
                                                 ], else_ = 'Low').label('severity'))
    query = query.join(Technology, Item.tech_id == Technology.id)
    query = query.join(ItemAudit, Item.id == ItemAudit.item_id)
    query = query.join(subquery, subquery.c.item_id == Item.id)
    query = query.join((Account, Account.id == Item.account_id))

    # Lookup filters
    query = query.filter(Account.name == account)   # Match Account Name
    query = query.filter(Technology.name == 'guardduty')   # Match Technology Name
    query = query.filter((coalesce(ItemAudit.justified, False) == False))
    query = query.filter((coalesce(ItemAudit.fixed, False) == False))
    query = query.filter(subquery.c.last_updated >= (datetime.now() - timedelta(days=days)).date())

    # Sort by ItemAudit Severity High -> Low
    query = query.order_by(ItemAudit.score.desc())

    # Get records
    items = query.limit(num_findings).all()

    marshaled_items = []

    for row in items:
        row_dict = dict(row.__dict__)
        marshaled_items.append({
            'name': row_dict['name'].capitalize(),
            'issue': row_dict['issue'].capitalize(),
            'severity': row_dict['severity'].capitalize()
        })

    marshaled_response = {
        'items': marshaled_items,
        'count': num_findings
    }

    return marshaled_response
