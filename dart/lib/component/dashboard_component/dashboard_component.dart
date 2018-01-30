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

  // Vulnerability Severity Chart Variables
  bool vulnSevScoresLoaded = false;
  List<int> vulnSevScores = [0,0,0];


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
    store.list(Issue, params: severityChartFilterParams).then((issues) {
      int _low =0, _medium=0,_high=0;
      for (Issue issue in issues) {
        if(issue.score < 5){
          _low++;
        } else if ( issue.score >=5 && issue.score <=10) {
          _medium++;
        } else if (issue.score > 10){
          _high++;
        }
      }
      this.vulnSevScores[SEVERITY_LOW] = _low;
      this.vulnSevScores[SEVERITY_MEDIUM] = _medium;
      this.vulnSevScores[SEVERITY_HIGH] = _high;

      loadSeverityBarChart(shadowRoot);
    });

    store.list(Item, params: itemFilterParams).then((items) {
      List<Item> allItems = [items].expand((x) => x).toList();
      loadTechnologyPieChart(shadowRoot, allItems);
    });
  }

  void loadSeverityBarChart(ShadowRoot shadowRoot) {
    List<String> severityLabels = <String>['High - ' + this.vulnSevScores[SEVERITY_HIGH].toString(),
                                        'Medium - ' + this.vulnSevScores[SEVERITY_MEDIUM].toString(),
                                        'Low - ' + this.vulnSevScores[SEVERITY_LOW].toString()];
    ChartDataSets chartDataSet = new ChartDataSets(
        label: 'Vulnerabilities by Severity',
        backgroundColor: [
      'rgba(214,145,73,1)',
      'rgba(237,194,79,1)',
      'rgba(116,172,87,1)'
    ], data: this.vulnSevScores);

    LinearChartData chartJsdata = new LinearChartData(
        labels: severityLabels, datasets: <ChartDataSets>[chartDataSet]);

    LinearTickOptions yTickOptions = new LinearTickOptions(beginAtZero: true);
    ChartYAxe yAxisOptions = new ChartYAxe(ticks: yTickOptions);
    ChartScales chartScale = new ChartScales(yAxes: [yAxisOptions]);
    ChartOptions chartOptions = new ChartOptions(
        responsive: true,
        scales: chartScale);
    ChartLegendOptions chartLegendOptions =
        new ChartLegendOptions(display: false, position: 'top');
    ChartLegendLabelOptions chartLegendLabelOptions =
        new ChartLegendLabelOptions(
            fontSize: 18,
            fontColor: 'rgb(168, 168, 168)');
    chartLegendOptions.labels = chartLegendLabelOptions;
    chartOptions.responsive = true;
    chartOptions.scales = chartScale;
    chartOptions.legend = chartLegendOptions;

    ChartConfiguration config = new ChartConfiguration(
        type: 'bar', data: chartJsdata, options: chartOptions);

    CanvasElement _canvas = document.querySelector('#severitycanvas') as CanvasElement;

    new Chart(_canvas, config);
  }

  void loadTechnologyPieChart(ShadowRoot shadowRoot, List<Item> allItems) {

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
      double percent = (v*100/totalItems);
      pieData.add(percent.round());
      pieLabels.add('${k[0].toUpperCase()}${k.substring(1)} ' + v.toString() +  ' - ' + percent.round().toString() + '%');
      String color = dynamicColors();
      pieColors.add(color);
    });

    ChartDataSets chartDataSet = new ChartDataSets(
        label: 'Vulnerabilities by Technology', data: pieData, backgroundColor: pieColors);

    LinearChartData chartJsdata = new LinearChartData(
        labels: pieLabels, datasets: <ChartDataSets>[chartDataSet]);

    ChartOptions chartOptions = new ChartOptions();

    ChartLegendOptions chartLegendOptions = new ChartLegendOptions(display: true, position: 'right');
    ChartLegendLabelOptions chartLegendLabelOptions = new ChartLegendLabelOptions(fontColor: 'rgb(168, 168, 168)');
    chartLegendOptions.labels = chartLegendLabelOptions;
    chartOptions.responsive = true;
//    chartOptions.maintainAspectRatio = false;
    chartOptions.legend = chartLegendOptions;

    ChartConfiguration config = new ChartConfiguration(
        type: 'pie', data: chartJsdata, options: chartOptions);

    CanvasElement _canvas =
    document.querySelector('#categorycanvas') as CanvasElement;

    new Chart(_canvas, config);
  }

  String dynamicColors(){
    Random random = new Random();
    int r = random.nextInt(255);
    int g = random.nextInt(255);
    int b = random.nextInt(255);
    return "rgb(" + r.toString() + "," + g.toString() + "," + b.toString() + ")";
  }


}
