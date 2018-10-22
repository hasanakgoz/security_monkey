part of security_monkey;

@Component(
    selector: 'dashboard',
    templateUrl:
        'packages/security_monkey/component/dashboard_component/dashboard_component.html',
    useShadowDom: false)
class DashboardComponent extends PaginatedTable implements ShadowRootAware {
  List accounts;
  List technologies;
  List<POAMItem> poamItems;
  Map techScoreMap;
  Map accountScoreMap;
  RouteProvider routeProvider;
  Router router;
  ObjectStore store;
  bool accountsLoaded = false;
  bool technologySummaryLoaded = false;
  bool poamItemsLoaded = false;
  bool selectAll = true;

  // New Account List Dropdown
  String selectedAccount = '__all_accounts__';
  String selectedSev = '';
  String selectedTech = '';

  // Vulnerability Severity Chart Variables
  bool vulnSevChartLoading = false;
  bool vulnTechChartLoading = false;
  bool topCountryChartLoading = false;
  List<int> vulnSevScores = [0, 0, 0];
  Chart vulnSevChart, vulnTechChart, topCountryChart;

  // Link up with Technology Chart
  DivElement techMapDiv;

  Map<String, String> accountFilterParams = {
    'page': '1',
    'active': true,
    'count': '1000000000' // This should retrieve all
  };

  Map<String, String> vulnbytechFilterParams = {
    'accounts': '',
  };

  Map<String, String> poamItemFilterParams = {
    'accounts': '',
    'tech':'',
    'sev':'',
    'page': '1',
    'count': '10'
  };

  Map<String, String> severityChartFilterParams = {
    'accounts': '',
    'tech':'',
  };

  Map<String, String> guardDutyEventFilterParams = {'accounts': ''};

  int vulnSevScores_high = 0;

  Map<String, String> vulnSevScores_n = {
    'high': '-',
    'medium': '-',
    'low': '-'
  };

  DashboardComponent(this.routeProvider, this.router, this.store) {
    // Initialize Pagination to display only 10 items per page
    super.items_per_page = "10";
    store.list(Account, params: accountFilterParams).then((accountItems) {
      this.accounts = new List();
      for (var accountItem in accountItems) {
        var account = new Map();
        account['selected_for_action'] = selectAll;
        account['id'] = accountItem.id;
        account['name'] = accountItem.name;
        account['total_score'] = 0;
        this.accounts.add(account);
      }
      accountsLoaded = true;
    });
  }

  // Function inherited from PaginatedTable class
  list() {
    fetchPOAMItems();
  }

  void fetchPOAMItems() {
    if (this.poamItemsLoaded = false) {
      return;
    }
    this.poamItemsLoaded = false;
    super.is_loaded = false;
    poamItemFilterParams['accounts'] =
        this.selectedAccount == '__all_accounts__'
            ? null
            : this.selectedAccount;
    poamItemFilterParams['tech'] = this.selectedTech;
    poamItemFilterParams['sev'] = this.selectedSev;

    // Update the page and count parameters
    poamItemFilterParams['page'] = super.currentPage.toString();
    poamItemFilterParams['count'] = super.items_per_page;
    print("Loading Filtered Data : $poamItemFilterParams");

    store.list(POAMItem, params: poamItemFilterParams).then((items) {
      super.setPaginationData(items.meta);
      this.poamItems = items;
      super.is_loaded = true;
      super.currentPage = int.parse(poamItemFilterParams['page']);
      this.poamItemsLoaded = true;
    });
  }

  void onShadowRoot(ShadowRoot shadowRoot) {
    print("onShadowRoot: $shadowRoot.activeElement");
    // Load Dashboard Charts
    loadDashboardCharts();
    this.techMapDiv = document.querySelector('#tech_piechart_wrapper');
  }

  void filterBySev(String sev) {
    this.selectedSev = sev;
    this.loadDashboardCharts();
    print("Applying filter by sev: $sev");
  }

  void loadDashboardCharts() {
    loadSeverityBarChartData();
    fetchPOAMItems();
  }

  Future loadSeverityBarChartData() async {
    this.vulnSevChartLoading = true;
    // Set selected account as filter for Vulnerability by Severity Chart
    this.severityChartFilterParams['accounts'] =
        this.selectedAccount == '__all_accounts__' ? '' : this.selectedAccount;
    this.severityChartFilterParams['tech'] = this.selectedTech;
    store.list(VulnBySeverity, params: severityChartFilterParams).then((items) {
      for (VulnBySeverity item in items) {
        this.vulnSevScores_n['high'] = item.high.toString();
        this.vulnSevScores_n['medium'] = item.medium.toString();
        this.vulnSevScores_n['low'] = item.low.toString();
      }
    });
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
      print("Switching to Account: $selectedAccount");
      // Due to a bug in ChartJS destroy does not work, but still calling it to clear max
      this.vulnSevScores_n['high'] = '-';
      this.vulnSevScores_n['medium'] = '-';
      this.vulnSevScores_n['low'] = '-';
      this.selectedSev='';
      this.selectedTech='';
      this.loadDashboardCharts();
    });
  }

  void filterByTech() {
    new Future(() {
      Map<String, String> divAttributes = this.techMapDiv.attributes;
      this.selectedTech = divAttributes['tech'];
      this.loadDashboardCharts();
      print("filterByTech: $selectedTech");
    });
  }

  bool isAccountSelectDisabled() {
    return (!this.poamItemsLoaded);
  }

  String get getFilterInfo{
    String filtersInfo='';

    if (this.selectedTech != "") {
      filtersInfo = "technology: " + this.selectedTech;
    }

    if (this.selectedSev != "") {
      filtersInfo = filtersInfo + " severity: " + this.selectedSev;
    }

    return filtersInfo;
  }
}
