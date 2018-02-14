library security_monkey;

import 'dart:async';
import 'dart:convert';
import 'dart:core';
import 'dart:html';
import 'dart:js';
import 'dart:math';

import 'package:angular/angular.dart';
import 'package:angular_ui/angular_ui.dart';
import 'package:chartjs/chartjs.dart';
import 'package:di/di.dart';
import 'package:hammock/hammock.dart';
import 'package:ng_infinite_scroll/ng_infinite_scroll.dart';

import 'model/Account.dart';
import 'model/AccountBulkUpdate.dart';
import 'model/AccountPatternAuditScore.dart';
import 'model/GuardDutyEvent.dart';
import 'model/Issue.dart';
import 'model/Item.dart';
import 'model/ItemComment.dart';
import 'model/Revision.dart';
import 'model/RevisionComment.dart';
import 'model/Role.dart';
import 'model/User.dart';
import 'model/UserSetting.dart';
import 'model/account_config.dart';
import 'model/auditorsetting.dart';
import 'model/auditscore.dart';
import 'model/custom_field_config.dart';
import 'model/hammock_config.dart';
import 'model/ignore_entry.dart';
import 'model/network_whitelist_entry.dart';
import 'model/techmethods.dart';
import 'model/watcher_config.dart';
import 'routing/securitymonkey_router.dart';
import 'service/justification_service.dart';
import 'service/username_service.dart';
import 'util/constants.dart';

part 'component/account_pattern_audit_score_view_component/account_pattern_audit_score_view_component.dart';
part 'component/account_view_component/account_view_component.dart';

part 'component/auditscore_view_component/auditscore_view_component.dart';
part 'component/compare_item_revisions/compare_item_revisions.dart';

part 'component/dashboard_component/dashboard_component.dart';

part 'component/ignore_entry_component/ignore_entry_component.dart';
part 'component/issue_table_component/issue_table_component.dart';
part 'component/item_table_component/item_table_component.dart';
part 'component/itemdetails/itemdetails_component.dart';

part 'component/justified_table_component/justified_table_component.dart';
part 'component/modal_justify_issues/modal_justify_issues.dart';

part 'component/paginated_table/paginated_table.dart';

part 'component/revision/revision_component.dart';

part 'component/revision_table_component/revision_table_component.dart';

part 'component/search_bar_component/search_bar_component.dart';

part 'component/search_page_component/search_page_component.dart';

part 'component/settings/audit_score_component/audit_score_component.dart';
part 'component/settings/auditor_settings_component/auditor_settings_component.dart';
part 'component/settings/ignore_list_component/ignore_list_component.dart';

part 'component/settings/network_whitelist_component/network_whitelist_component.dart';

part 'component/settings/user_role_component/user_role_component.dart';
part 'component/settings/watcher_config_component/watcher_config_component.dart';

part 'component/settings_component/settings_component.dart';

part 'component/signout_component/signout_component.dart';

part 'component/username_component/username_component.dart';

part 'component/whitelist_view_component/whitelist_view_component.dart';

part 'interceptor/global_http_interceptor.dart';

part 'service/messages.dart';

// select2 is still in JavaScript
// select2 querySelector
// Dashboard Graphs
// NG-infinite-scroll
// Hammock
// Services
// Model
// Routing
// import 'package:security_monkey/routing/securitymonkey_router.dart' show param_from_url, param_to_url, map_from_url, map_to_url;
// HTTP Interceptor
// Interceptor Error Messages
// Parent Component
// Part components


class SecurityMonkeyModule extends Module {

  SecurityMonkeyModule() {

    // AngularUI
    install(new AngularUIModule());

    // Hammock (like restangular)
    install(new Hammock());
    Injector inj;
    bind(HammockConfig, toValue: createHammockConfig(inj));

    // NG-infinite-scroll
    install(new InfiniteScrollModule());

    // Components
    bind(CompareItemRevisions);
    bind(ItemDetailsComponent);
    bind(RevisionTableComponent);
    bind(ItemTableComponent);
    bind(RevisionComponent);
    bind(IssueTableComponent);
    bind(AccountViewComponent);
    bind(SearchPageComponent);
    bind(SearchBarComponent);
    bind(SignoutComponent);
    bind(SettingsComponent);
    bind(ModalJustifyIssues);
    bind(WhitelistViewComponent);
    bind(IgnoreEntryComponent);
    bind(UsernameComponent);
    bind(AuditorSettingsComponent);
    bind(DashboardComponent);
    bind(UserRoleComponent);
    bind(NetworkWhitelistComponent);
    bind(IgnoreListComponent);
    bind(JustifiedTableComponent);
    bind(AuditScoreComponent);
    bind(AccountPatternAuditScoreComponent);
    bind(AuditScoreListComponent);
    bind(WatcherConfigComponent);

    // Services
    bind(JustificationService);
    bind(UsernameService);
    bind(Messages);

    // Routing
    bind(RouteInitializerFn, toValue: securityMonkeyRouteInitializer);
    bind(NgRoutingUsePushState,
        toValue: new NgRoutingUsePushState.value(false));
  }
}
