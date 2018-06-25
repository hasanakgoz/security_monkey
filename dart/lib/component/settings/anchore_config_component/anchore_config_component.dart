part of security_monkey;

@Component(
    selector: 'anchore-config-cmp',
    templateUrl:
    'packages/security_monkey/component/settings/anchore_config_component/anchore_config_component.html',
    //cssUrl: const ['/css/bootstrap.min.css']
    useShadowDom: false)

class AnchoreConfigComponent extends PaginatedTable {
  UsernameService us;
  AnchoreConfigItem k;

  List<AnchoreConfigItem> configitems = [];
  Router router;
  ObjectStore store;
  final Http _http;

  get isLoaded => super.is_loaded;

  get isError => super.is_error;

//  int imagesCount = 0 ;

  void list() {
    super.is_loaded = false;
    store.list(AnchoreConfigItem, params: {
      "count": ipp_as_int,
      "page": currentPage,
      "order_by": sorting_column,
      "order_dir": order_dir()
    }).then((configitems) {
      super.setPaginationData(configitems.meta);
      this.configitems = configitems;

      super.is_loaded = true;
    });
  }

  String verify;
  var p = new AnchoreConfigItem();

  void create_configitem() {
    if (p.name != null &&
        p.username != null &&
        p.url != null &&
        p.password != null) {
      if (verify == "True")
        p.ssl_verify = true;
      else
        p.ssl_verify = false;
      store.create(p).then((_) {
        list();
      });
    } else {
      return;
    }
  }

  String update_id;
  var r = new AnchoreConfigItem();
  String v2;

  void set_update(configitem) {
    update_id = configitem.id;
    r.id = configitem.id;
    r.name = configitem.name;
    r.username = configitem.username;
    r.password = configitem.password;
    r.url = configitem.url;
    r.ssl_verify = configitem.ssl_verify;
    if (configitem.ssl_verify)
      v2 = "True";
    else
      v2 = "False";
  }

  void update_configitem() {
    print(r.name + r.username + r.password + r.url);
    if (r.name != null &&
        r.username != null &&
        r.url != null &&
        r.password != null) {
      if (v2 == "True")
        r.ssl_verify = true;
      else
        r.ssl_verify = false;
      store.update(r).then((_) {
        list();
      });
    }

    update_id = null;
    return;
  }

  AnchoreConfigComponent(this.router, this.store, this._http, this.us) {
    list();
  }

  void delete_configitem(configitem) {
    store.delete(configitem).then((_) {
      list();
    });
  }
}
