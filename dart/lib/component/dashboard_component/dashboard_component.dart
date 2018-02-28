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
    'count': '20'
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
        account['total_score'] = 0;
        this.accounts.add(account);
        fetchItems(account['name']);
      }
      accountsLoaded = true;
      recalculateAgingIssueSummary();
    });
  }

  void fetchItems(account) {
    itemFilterParams['accounts'] = account;
    store.list(Item, params: itemFilterParams).then((items) {
      this.selectedItems =
          [this.selectedItems, items].expand((x) => x).toList();
      highScoreSummaryLoaded = true;
    });
  }

  void recalculateAgingIssueSummary() {
    agingIssueSummaryLoaded = false;
    agingIssueFilterParams['accounts'] =
        this.selectedAccount == '__all_accounts__' ? '' : this.selectedAccount;

    store.list(Issue, params: agingIssueFilterParams).then((issues) {
      this.agingIssues = issues;
      this.agingIssueSummaryLoaded = true;
    });
  }

  void onShadowRoot(ShadowRoot shadowRoot) {
    // Load Dashboard Charts
    loadDashboardCharts();
  }

  void loadDashboardCharts() {
    //    Display Loading Spinner on the Chart Controls
    showChartSpinner("countrycanvas");
    showChartSpinner("severitycanvas");
    showChartSpinner("categorycanvas");

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

    store.list(VulnByTech, params: itemFilterParams).then((items) {
      List<VulnByTech> allItems = [items].expand((x) => x).toList();
      loadTechnologyPieChart(allItems);
    });
  }

  Future loadSeverityBarChartData() async {
    this.vulnSevChartLoading = true;
    // Set selected account as filter for Vulnerability by Severity Chart
    this.severityChartFilterParams['accounts'] =
        this.selectedAccount == '__all_accounts__' ? '' : this.selectedAccount;
    store.list(VulnBySeverity, params: severityChartFilterParams).then((items) {
      for (VulnBySeverity item in items) {
        this.vulnSevScores[SEVERITY_LOW] = item.low;
        this.vulnSevScores[SEVERITY_MEDIUM] = item.medium;
        this.vulnSevScores[SEVERITY_HIGH] = item.high;
      }
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
    DivElement spinnerDiv =
        _canvas.parent.querySelector('.spinner') as DivElement;
    spinnerDiv.remove();
    if (this.vulnSevScores.length == 0) {
      showNoDataMessage("#severitycanvas");
    }

    this.vulnSevChart = new Chart(_canvas, config);
    this.vulnSevChartLoading = false;
  }

  Future loadTechnologyPieChart(List<VulnByTech> allItems) async {
    List<String> pieLabels = new List<String>();
    List<String> pieColors = new List<String>();
    List<int> pieData = new List<int>();

    for (VulnByTech item in allItems) {
      pieData.add(item.percentage);
      pieLabels
          .add('${item.technology[0].toUpperCase()}${item.technology.substring(
              1)} ' +
              item.count.toString() +
              ' - ' +
              item.percentage.toString() +
              '%');
      String color = dynamicColors();
      pieColors.add(color);
    }
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
    DivElement spinnerDiv =
        _canvas.parent.querySelector('.spinner') as DivElement;
    spinnerDiv.remove();

    if (pieData.length == 0) {
      showNoDataMessage("#categorycanvas");
    }

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
      removeNoDataDIV(mapElement.parent);
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
      if (items.length == 0) {
        showNoDataMessage("#worldmap");
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

      DivElement spinnerDiv =
          _canvas.parent.querySelector('.spinner') as DivElement;
      spinnerDiv.remove();

      if (barLabels.length == 0) {
        showNoDataMessage("#countrycanvas");
      }
      this.topCountryChart = new Chart(_canvas, config);
      this.topCountryChartLoading = false;
    });
  }

  void showChartSpinner(String canvasElement) {
    // Due to a bug in ChartJS destroy function there is need to recreate Canvas Element

    CanvasElement canvas = document.getElementById(canvasElement);
    Element parent = canvas.parent;

    //Remove Canvas
    canvas.remove();

    //Remove NoData Message If Any
    removeNoDataDIV(parent);

    //Add Canvas
    CanvasElement newCanvas = new CanvasElement();
    newCanvas.setAttribute('id', canvasElement);
    parent.children.add(newCanvas);

    //Add Spinner
    DivElement spinnerDiv = new DivElement();
    spinnerDiv.classes.add('spinner');
    parent.children.add(spinnerDiv);
  }

  void removeNoDataDIV(Element parent) {
    //Remove NoData Message If Any
    DivElement noDataDiv = parent.querySelector('.nodata') as DivElement;
    if (noDataDiv != null) {
      noDataDiv.remove();
    }
  }

  void showNoDataMessage(String canvasElement) {
    CanvasElement canvas = document.querySelector(canvasElement);
    Element parent = canvas.parent;
    DivElement messageDiv = new DivElement();
    messageDiv.className = 'nodata center-block';
    String message =
        "<div class='alert alert-warning inner text-center'><strong>No Data Available!</strong></div>";
    messageDiv.innerHtml = message;
    parent.children.add(messageDiv);
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
      recalculateAgingIssueSummary();
      this.selectedItems.clear();
      highScoreSummaryLoaded = false;
      fetchItems(this.selectedAccount == '__all_accounts__'
          ? ''
          : this.selectedAccount);
    });
  }

  bool isAccountSelectDisabled() {
    return (this.vulnSevChartLoading ||
        this.vulnTechChartLoading ||
        this.topCountryChartLoading || !highScoreSummaryLoaded);
  }
}
