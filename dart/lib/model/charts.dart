library security_monkey.model_charts;

class VulnByTech {
  String technology;
  int count;
  num percentage;
  VulnByTech();

  VulnByTech.fromMap(Map data) {
    technology = data['technology'];
    count = data['count'];
    percentage = data['percentage'];
  }
}

class VulnBySeverity {
  int low, medium, high;
  VulnBySeverity();

  VulnBySeverity.fromMap(Map data) {
    low = data['low'];
    medium = data['medium'];
    high = data['high'];
  }
}
