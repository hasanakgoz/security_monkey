library security_monkey.poamitem_model;

import 'package:security_monkey/util/utils.dart' show localDateFromAPIDate;


/*
  POA&M Item Model for parsing and displaying POA&M reports on Dashboard

*/

class POAMItem {
  int score, item_id;
  String poam_id,
      control,
      account,
      weakness_name,
      weakness_description,
      comments;

  DateTime create_date = null;

  POAMItem();

  POAMItem.fromMap(Map data) {
    poam_id = data['poam_id'];
    item_id = data['item_id'];
    account = data['account'];
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
