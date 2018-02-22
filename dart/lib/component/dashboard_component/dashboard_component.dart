part of security_monkey;

@Component(
    selector: 'dashboard',
    templateUrl:
        'packages/security_monkey/component/dashboard_component/dashboard_component.html',
    useShadowDom: false)
class DashboardComponent implements ShadowRootAware {
  static int SEVERITY_LOW = 2;
  static int SEVERITY_MEDIUM = 1;
  static int SEVERITY_HIGH = 0;

  List accounts;
  List technologies;
  List<Item> selectedItems;
  List<Issue> agingIssues;
  Map techScoreMap;
  Map accountScoreMap;
  RouteProvider routeProvider;
  Router router;
  ObjectStore store;
  bool accountsLoaded = false;
  bool technologySummaryLoaded = false;
  bool highScoreSummaryLoaded = false;
  bool agingIssueSummaryLoaded = false;
  bool selectAll = true;

  // New Account List Dropdown
  String selectedAccount = '__all_accounts__';

  // Vulnerability Severity Chart Variables
  bool vulnSevChartLoading = false;
  bool vulnTechChartLoading = false;
  bool topCountryChartLoading = false;
  List<int> vulnSevScores = [0, 0, 0];
  Chart vulnSevChart, vulnTechChart, topCountryChart;

  Map<String, String> accountFilterParams = {
    'page': '1',
    'active': true,
    'count': '1000000000' // This should retrieve all
  };

  Map<String, String> itemFilterParams = {
    'regions': '',
    'technologies': '',
    'accounts': '',
    'accounttypes': '',
    'names': '',
    'active': true,
    'searchconfig': null,
    'summary': true,
    'page': '1',
    'count': '1000000000' // This should retrieve all
  };

  Map<String, String> agingIssueFilterParams = {
    'regions': '',
    'technologies': '',
    'accounts': '',
    'accounttypes': '',
    'names': '',
    'active': null,
    'searchconfig': null,
    'justified': false,
    'enabledonly': 'true',
    'summary': true,
    'page': '1',
    'count': '10'
  };

  Map<String, String> severityChartFilterParams = {
    'regions': '',
    'technologies': '',
    'accounts': '',
    'accounttypes': '',
    'names': '',
    'active': null,
    'searchconfig': null,
    'justified': false,
    'fixed': false, // This is mock param as the API by default implements this
    'enabledonly': 'true',
    'summary': true,
    'page': '1',
    'count': '1000000000' // This should retrieve all
  };

  Map<String, String> guardDutyEventFilterParams = {'accounts': ''};

  DashboardComponent(this.routeProvider, this.router, this.store) {
    store.list(Account, params: accountFilterParams).then((accountItems) {
      this.accounts = new List();
      this.selectedItems = new List();
      for (var accountItem in accountItems) {
        var account = new Map();
        account['selected_for_action'] = selectAll;
        account['id'] = accountItem.id;
        account['name'] = accountItem.name;
        account['items'] = new List();
        account['total_score'] = 0;
        this.accounts.add(account);
        fetchItems(account);
      }
      accountsLoaded = true;
      recalculateAgingIssueSummary();
    });
  }

  void fetchItems(account) {
    itemFilterParams['accounts'] = account['name'];
    store.list(Item, params: itemFilterParams).then((items) {
      account['items'] = items;
      if (account['selected_for_action']) {
        this.selectedItems =
            [this.selectedItems, account['items']].expand((x) => x).toList();
      }
      highScoreSummaryLoaded = true;
      recalculateSummaryScores();
    });
  }

  void recalculateSummaryScores() {
    technologySummaryLoaded = false;
    techScoreMap = new Map();
    accountScoreMap = new Map();
    for (var item in selectedItems) {
      // Add item score to technology map
      if (techScoreMap.containsKey(item.technology)) {
        techScoreMap[item.technology] =
            techScoreMap[item.technology] + item.totalScore();
      } else {
        techScoreMap[item.technology] = item.totalScore();
      }
      // Add item score to account score map
      if (accountScoreMap.containsKey(item.account)) {
        accountScoreMap[item.account] =
            accountScoreMap[item.account] + item.totalScore();
      } else {
        accountScoreMap[item.account] = item.totalScore();
      }
    }
    // angular.dart does not support iterating over hash map so convert to array
    technologies = new List();
    techScoreMap.forEach((k, v) {
      technologies.add({'name': k, 'score': v});
    });
    technologySummaryLoaded = true;

    // Update accounts['total_score'] after items have been parsed
    for (var account in accounts) {
      if (accountScoreMap.containsKey(account['name'])) {
        account['total_score'] = accountScoreMap[account['name']];
      }
    }
  }

  void recalculateAgingIssueSummary() {
    agingIssueSummaryLoaded = false;
    agingIssueFilterParams['accounts'] = selectedAccountsParam();

    store.list(Issue, params: agingIssueFilterParams).then((issues) {
      this.agingIssues = issues;
      this.agingIssueSummaryLoaded = true;
    });
  }

  void recalculateAllSummaries() {
    var selectedAccountsList = selectedAccounts();
    // Combine selected accounts items
    this.selectedItems = new List();
    for (var account in selectedAccountsList) {
      this.selectedItems =
          [this.selectedItems, account['items']].expand((x) => x).toList();
    }
    recalculateSummaryScores();
    recalculateAgingIssueSummary();
    // High Score Items is updated when selectedItems changes
  }

  String selectedAccountsParam() {
    var selectedAccountNamesList = selectedAccountNames();
    if (selectedAccountNamesList.length > 0) {
      return selectedAccountNamesList.join(',');
    } else {
      return 'NONE';
    }
  }

  List selectedAccounts() {
    var accountsArray = new List();
    for (var account in accounts) {
      if (account['selected_for_action']) {
        accountsArray.add(account);
      }
    }
    return accountsArray;
  }

  List selectedAccountNames() {
    var accountNamesArray = new List();
    for (var account in accounts) {
      if (account['selected_for_action']) {
        accountNamesArray.add(account['name']);
      }
    }
    return accountNamesArray;
  }

  String getAccountFilter() {
    var accountFilters = new List();
    for (var account in accounts) {
      if (account['selected_for_action']) {
        accountFilters.add(account['name']);
      }
    }

    if (accountFilters.length == accounts.length) {
      return '-';
    } else if (accountFilters.length > 0) {
      return accountFilters.join('%2C');
    } else {
      return 'None';
    }
  }

  void selectAllToggle() {
    selectAll = !selectAll;
    for (var account in accounts) {
      account['selected_for_action'] = selectAll;
    }
  }

  // Sorting
  var sort_params = {
    'account': {
      'sorting_column': 'total_score',
      'sort_asc': false,
      'sort_value': '-score'
    },
    'technology': {
      'sorting_column': 'score',
      'sorc_asc': false,
      'sort_value': '-score'
    }
  };

  void sortColumn(var table, var column) {
    if (sort_params[table]['sorting_column'] == column) {
      sort_params[table]['sort_asc'] = !sort_params[table]['sort_asc'];
      if (sort_params[table]['sort_asc']) {
        sort_params[table]['sort_value'] = column;
      } else {
        sort_params[table]['sort_value'] = '-' + column;
      }
    } else {
      sort_params[table]['sorting_column'] = column;
      sort_params[table]['sort_asc'] = true;
      sort_params[table]['sort_value'] = column;
    }
  }

  String classForColumn(var table, var column) {
    if (sort_params[table]['sorting_column'] == column) {
      if (sort_params[table]['sort_asc']) {
        return "glyphicon glyphicon glyphicon-sort-by-attributes";
      } else {
        return "glyphicon glyphicon glyphicon-sort-by-attributes-alt";
      }
    } else {
      return "glyphicon glyphicon-sort";
    }
  }

  void onShadowRoot(ShadowRoot shadowRoot) {
    // Load Dashboard Charts
    loadDashboardCharts();
  }

  void loadDashboardCharts() {
    //    Display Loading Message on the Chart Controls
    String loadingMessage = "Loading...";
    showChartSpinner("countrycanvas", loadingMessage);
    showChartSpinner("severitycanvas", loadingMessage);
    showChartSpinner("categorycanvas", loadingMessage);

    loadSeverityBarChartData();
    loadTechnologyPieChartData();
    loadWorldMap();
    loadTop10CountryBarChart();
  }

  Future loadTechnologyPieChartData() async {
    // Set selected account as filter for Vulnerability by Technology Chart
    this.vulnTechChartLoading = true;

    this.itemFilterParams['accounts'] =
        this.selectedAccount == '__all_accounts__' ? '' : this.selectedAccount;

    store.list(Item, params: itemFilterParams).then((items) {
      List<Item> allItems = [items].expand((x) => x).toList();
      loadTechnologyPieChart(allItems);
    });
  }

  Future loadSeverityBarChartData() async {
    this.vulnSevChartLoading = true;
    // Set selected account as filter for Vulnerability by Severity Chart
    this.severityChartFilterParams['accounts'] =
        this.selectedAccount == '__all_accounts__' ? '' : this.selectedAccount;
    store.list(Issue, params: severityChartFilterParams).then((issues) {
      int _low = 0, _medium = 0, _high = 0;
      for (Issue issue in issues) {
        if (issue.score < 5) {
          _low++;
        } else if (issue.score >= 5 && issue.score <= 10) {
          _medium++;
        } else if (issue.score > 10) {
          _high++;
        }
      }
      this.vulnSevScores[SEVERITY_LOW] = _low;
      this.vulnSevScores[SEVERITY_MEDIUM] = _medium;
      this.vulnSevScores[SEVERITY_HIGH] = _high;

      loadSeverityBarChart();
    });
  }

  Future loadSeverityBarChart() async {
    List<String> severityLabels = <String>[
      'High - ' + this.vulnSevScores[SEVERITY_HIGH].toString(),
      'Medium - ' + this.vulnSevScores[SEVERITY_MEDIUM].toString(),
      'Low - ' + this.vulnSevScores[SEVERITY_LOW].toString()
    ];
    ChartDataSets chartDataSet = new ChartDataSets(
        label: 'Vulnerabilities by Severity',
        backgroundColor: [
          'rgba(214,145,73,1)',
          'rgba(237,194,79,1)',
          'rgba(116,172,87,1)'
        ],
        data: this.vulnSevScores);

    LinearChartData chartJsdata = new LinearChartData(
        labels: severityLabels, datasets: <ChartDataSets>[chartDataSet]);

    LinearTickOptions yTickOptions = new LinearTickOptions(beginAtZero: true);
    ChartYAxe yAxisOptions = new ChartYAxe(ticks: yTickOptions);
    ChartScales chartScale = new ChartScales(yAxes: [yAxisOptions]);
    ChartOptions chartOptions =
        new ChartOptions(responsive: false, scales: chartScale);
    ChartLegendOptions chartLegendOptions =
        new ChartLegendOptions(display: false, position: 'top');
    ChartLegendLabelOptions chartLegendLabelOptions =
        new ChartLegendLabelOptions(
            fontSize: 18, fontColor: 'rgb(168, 168, 168)');
    chartLegendOptions.labels = chartLegendLabelOptions;
    chartOptions.responsive = true;
    chartOptions.scales = chartScale;
    chartOptions.legend = chartLegendOptions;

    ChartConfiguration config = new ChartConfiguration(
        type: 'bar', data: chartJsdata, options: chartOptions);

    CanvasElement _canvas =
        document.querySelector('#severitycanvas') as CanvasElement;
    _canvas.parent.classes.remove('spinner');

    this.vulnSevChart = new Chart(_canvas, config);
    this.vulnSevChartLoading = false;
  }

  Future loadTechnologyPieChart(List<Item> allItems) async {
    List<String> pieLabels = new List<String>();
    List<String> pieColors = new List<String>();
    List<int> pieData = new List<int>();
    int totalItems = allItems.length;
    // Calculate Technology Pie Chart Data Points
    Map techCountMap = new Map();
    for (var item in allItems) {
      // Add item score to technology map
      if (techCountMap.containsKey(item.technology)) {
        techCountMap[item.technology]++;
      } else {
        techCountMap[item.technology] = 1;
      }
    }
    // build arrays for ChartJS
    techCountMap.forEach((k, v) {
      double percent = (v * 100 / totalItems);
      pieData.add(percent.round());
      pieLabels.add('${k[0].toUpperCase()}${k.substring(1)} ' +
          v.toString() +
          ' - ' +
          percent.round().toString() +
          '%');
      String color = dynamicColors();
      pieColors.add(color);
    });

    ChartDataSets chartDataSet = new ChartDataSets(
        label: 'Vulnerabilities by Technology',
        data: pieData,
        backgroundColor: pieColors);

    LinearChartData chartJsdata = new LinearChartData(
        labels: pieLabels, datasets: <ChartDataSets>[chartDataSet]);

    ChartTitleOptions chartTitleOptions = new ChartTitleOptions();
    ChartOptions chartOptions = new ChartOptions();

    ChartLegendOptions chartLegendOptions =
        new ChartLegendOptions(display: false, position: 'right');
    ChartLegendLabelOptions chartLegendLabelOptions =
        new ChartLegendLabelOptions(fontColor: 'rgb(168, 168, 168)');
    chartLegendOptions.labels = chartLegendLabelOptions;
    chartTitleOptions.text = "Vulnerabilities by Technology";

    chartOptions.responsive = false;
    chartOptions.legend = chartLegendOptions;
    chartOptions.maintainAspectRatio = false;

    ChartConfiguration config = new ChartConfiguration(
        type: 'pie', data: chartJsdata, options: chartOptions);

    CanvasElement _canvas =
        document.querySelector('#categorycanvas') as CanvasElement;

    _canvas.parent.classes.remove('spinner');
    this.vulnTechChart = new Chart(_canvas, config);
    this.vulnTechChartLoading = false;
  }

  Future loadWorldMap() async {
    // Set selected account as filter for World Map Chart
    this.guardDutyEventFilterParams['accounts'] =
        this.selectedAccount == '__all_accounts__' ? '' : this.selectedAccount;

    store
        .list(WorldMapGuardDutyData, params: this.guardDutyEventFilterParams)
        .then((items) {
      Element mapElement = document.querySelector('#worldmap');
      for (Element element in mapElement.querySelectorAll("leaflet-circle")) {
        element.remove();
      }
      for (WorldMapGuardDutyData item in items) {
        Element circleMarker = new Element.tag("leaflet-circle");
        circleMarker.setAttribute("latitude", item.lat.toString());
        circleMarker.setAttribute("longitude", item.lon.toString());
        circleMarker.setAttribute("radius", (item.count * 500).toString());
        circleMarker.setAttribute("color", "crimson");
        circleMarker.setAttribute("fillColor", "crimson");
        circleMarker.setAttribute("fillOpacity", "0.5");
        circleMarker.setAttribute("fill", "true");
        mapElement.children.add(circleMarker);
      }
    });
  }

  Future loadTop10CountryBarChart() async {
    this.topCountryChartLoading = true;
    List<String> barLabels = new List<String>();
    List<int> barValues = new List<int>();
    List<String> barColors = new List<String>();
    // Set selected account as filter for Top 10 Countries Chart
    this.guardDutyEventFilterParams['accounts'] =
        this.selectedAccount == '__all_accounts__' ? '' : this.selectedAccount;

    store
        .list(Top10CountriesGaurdDutyData, params: guardDutyEventFilterParams)
        .then((items) {
      for (Top10CountriesGaurdDutyData item in items) {
        print("loadTop10CountryBarChart::Processing Item " + item.countryName);
        barLabels.add(item.countryName);
        barValues.add(item.probeCount);
        barColors.add(dynamicColors());
      }

      ChartDataSets chartDataSet = new ChartDataSets();
      chartDataSet.label = 'Top Countries';
      chartDataSet.backgroundColor = barColors;
      chartDataSet.data = barValues;

      LinearChartData chartJsdata = new LinearChartData();
      chartJsdata.labels = barLabels;
      chartJsdata.datasets = <ChartDataSets>[chartDataSet];

      LinearTickOptions yTickOptions = new LinearTickOptions(beginAtZero: true);
      ChartYAxe yAxisOptions = new ChartYAxe(ticks: yTickOptions);
      ChartScales chartScale = new ChartScales(yAxes: [yAxisOptions]);
      ChartOptions chartOptions =
          new ChartOptions(responsive: true, scales: chartScale);
      ChartLegendOptions chartLegendOptions =
          new ChartLegendOptions(display: false, position: 'top');
      ChartLegendLabelOptions chartLegendLabelOptions =
          new ChartLegendLabelOptions(
              fontSize: 18, fontColor: 'rgb(168, 168, 168)');
      chartLegendOptions.labels = chartLegendLabelOptions;
      chartOptions.responsive = true;
      chartOptions.scales = chartScale;
      chartOptions.legend = chartLegendOptions;

      ChartConfiguration config = new ChartConfiguration(
          type: 'bar', data: chartJsdata, options: chartOptions);

      CanvasElement _canvas =
          document.querySelector('#countrycanvas') as CanvasElement;
      _canvas.parent.classes.remove('spinner');
      this.topCountryChart = new Chart(_canvas, config);
      this.topCountryChartLoading = false;
    });
  }

  void showChartSpinner(String canvasElement, String message) {
    // Due to a bug in ChartJS destroy function there is need to recreate Canvas Element

    CanvasElement canvas = document.getElementById(canvasElement);
    CanvasElement newCanvas = new CanvasElement();
    newCanvas.setAttribute('id', canvasElement);
    Element parent = canvas.parent;
    canvas.remove();
    parent.children.add(newCanvas);
    parent.classes.add('spinner');
  }

  String dynamicColors() {
    Random random = new Random();
    int r = random.nextInt(255);
    int g = random.nextInt(255);
    int b = random.nextInt(255);
    return "rgb(" +
        r.toString() +
        "," +
        g.toString() +
        "," +
        b.toString() +
        ")";
  }

  void newAccountSelected() {
    new Future(() {
      print("New Account Selected: " + this.selectedAccount);
      // Due to a bug in ChartJS destroy does not work, but still calling it to clear max
      this.vulnSevChart.destroy();
      this.vulnTechChart.destroy();
      this.topCountryChart.destroy();
      this.loadDashboardCharts();
    });
  }

  bool isAccountSelectDisabled() {
    return (this.vulnSevChartLoading ||
        this.vulnTechChartLoading ||
        this.topCountryChartLoading);
  }
}
