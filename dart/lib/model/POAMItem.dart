library security_monkey.poamitem_model;

import 'package:security_monkey/util/utils.dart' show localDateFromAPIDate;


/*
  POA&M Item Model for parsing and displaying POA&M reports on Dashboard

  Sample POA&M Item
  {
      "control": "policy",
      "create_date": "2017-11-01 19:29:52.329638",
      "poam_comments": null,
      "poam_id": "sa_poam-12868",
      "score": 10,
      "weakness_description": "Service [iam] Category: [Permissions] Resources: [\"*\"], universal, ServiceCatalogAdmin-SupplementalPermissions",
      "weakness_name": "Sensitive Permissions"
  }
*/

class POAMItem {
  int score;
  String poam_id,
      control,
      weakness_name,
      weakness_description,
      comments;

  DateTime create_date = null;

  POAMItem();

  POAMItem.fromMap(Map data) {
    poam_id = data['poam_id'];
    score = data['score'];
    control = data['control'];
    weakness_name = data['weakness_name'];
    weakness_description = data['weakness_description'];
    comments = data['poam_comments'];
    if (data.containsKey('create_date')) {
      create_date =  localDateFromAPIDate(data['create_date']);
    }
  }
}
