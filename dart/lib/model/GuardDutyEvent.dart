library security_monkey.guarddutyevent;

class WorldMapGuardDutyData {
  int lat, lon, count, localPort, remoteOrgASN;
  String cityName,
      countryName,
      localPortName,
      remoteIpV4,
      remoteOrg,
      remoteOrgASNOrg,
      remoteOrgISP;

  WorldMapGuardDutyData();

  WorldMapGuardDutyData.fromMap(Map data) {
    lat = data['lat'];
    lon = data['lon'];
    count = data['count'];
    cityName = data['cityName'];
    countryName = data['countryName'];
    localPort = data['localPort'];
    localPortName = data['localPortName'];
    remoteIpV4 = data['remoteIpV4'];
    remoteOrg = data['remoteOrg'];
    remoteOrgASN = data['remoteOrgASN'];
    remoteOrgASNOrg = data['remoteOrgASNOrg'];
    remoteOrgISP = data['remoteOrgISP'];
  }
}

class Top10CountriesGaurdDutyData {
  String countryName;
  int probeCount;

  Top10CountriesGaurdDutyData();

  Top10CountriesGaurdDutyData.fromMap(Map data) {
    probeCount = data['count'];
    countryName = data['countryName'];
  }
}
