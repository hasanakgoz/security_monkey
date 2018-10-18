var vulnbyseverityJSON;
var top10CountryGuardDutyJSON;
var worldmapguarddutydataJSON;
var selectedAccount = '';
var issuesByTimeJSON;
var count = 10;
var page = 1;

var nodatachild = "<div class=\"nodata center-block\"><div class=\"alert alert-warning inner text-center\"><strong>No Data Available!</strong></div></div>"
var spinnerchild = "<div class=\"spinner\"></div>"

function loadCharts(option) {
    param = 'tech=' + js_filter_tech + '&sev=' + js_filter_sev + '&accounts=' + selectedAccount;

    if(option === 'all'){
        // We are not applying Tech and Sev filters to Guardduty based WorldMap and Country Barchart
        getTop10CountryGuardDuty('accounts=' + selectedAccount);
        getWorldMapGuardDutyData('accounts=' + selectedAccount);
    }

    getVulnByTech(param);
    getIssuesByTime(param);
    document.getElementById('mapModal').style.display = "none";
}

$(document).ready(function () {
    // getAccounts('active=true&count=1000000000&page='+page);
    loadCharts('all');
    drawmap();

})


function getVulnByTech(params) {
    $('#tech_piechart_wrapper').children('.nodata').remove();
    $('#piechart').css("visibility", 'hidden');
    $('#tech_piechart_wrapper').append(spinnerchild);
    $.when(callapi('vulnbytech?' + params, 'GET')).then(function (response) {
        response.then(resp => {
            $('#tech_piechart_wrapper').children('.spinner').remove();
            $('#piechart').css("visibility", 'visible');

            vulnbytechJSON = JSON.parse(resp);
            if (vulnbytechJSON.items.length == 0) {
                //    No matching data received from server
                $('#tech_piechart_wrapper').prepend(nodatachild);
            } else {
                createPieChart(vulnbytechJSON.items);
            }
        });
    });
}

function getTop10CountryGuardDuty(params) {
    $('#countries_chart').children('.nodata').remove();
    $('#barchart').css("visibility", 'hidden');
    $('#countries_chart').append(spinnerchild);

    $.when(callapi('top10countryguarddutydata?' + params, 'GET')).then(function (response) {
        response.then(resp => {
            $('#countries_chart').children('.spinner').remove();
            $('#barchart').css("visibility", 'visible');
            top10CountryGuardDutyJSON = JSON.parse(resp);
            if (top10CountryGuardDutyJSON.items.length == 0) {
                //    No matching data received from server
                $('#countries_chart').prepend(nodatachild);
            } else {
                createCountryBarChart(top10CountryGuardDutyJSON.items, 'barchart');
            }
        });
    });
}

function getWorldMapGuardDutyData(params) {
    $('#worldmap_wrapper').children('.nodata').remove();
    $('#mapid').css("visibility", 'hidden');
    $('#worldmap_wrapper').append(spinnerchild);
    $.when(callapi('worldmapguarddutydata?' + params, 'GET')).then(function (response) {
        response.then(resp => {
            $('#worldmap_wrapper').children('.spinner').remove();
            $('#mapid').css("visibility", 'visible');
            worldmapguarddutydataJSON = JSON.parse(resp);
            if (worldmapguarddutydataJSON.items.length == 0) {
                //    No matching data received from server
                $('#worldmap_wrapper').prepend(nodatachild);
            } else {
                loadData(worldmapguarddutydataJSON.items);
            }
        });
    });
}

function getIssuesByTime(param) {
    $('#barchart_time_wrapper').children('.nodata').remove();
    $('#barchart_time').css("visibility", 'hidden');
    $('#barchart_time_wrapper').append(spinnerchild);

    $.when(callapi('issuescountbymonth?' + param, 'GET')).then(function (response) {
        response.then(resp => {
            $('#barchart_time_wrapper').children('.spinner').remove();
            $('#barchart_time').css("visibility", 'visible');
            issuesByTimeJSON = JSON.parse(resp);
            if (issuesByTimeJSON.items.length == 0) {
                //    No matching data received from server
                $('#barchart_time_wrapper').prepend(nodatachild);
            } else {
                createCountryBarChart(issuesByTimeJSON.items, 'barchart_time');
            }
        });
    });
}


// function appendAccounts() {
//     for (var i = 0; i < accountsJSON.items.length; i++) {
//         // $("#accounts_menu ul").append(' <li onClick="filterAccounts()" data-custom='+accountsJSON.items[i].identifier+'>'+accountsJSON.items[i].name+'</li>')
//         $("#accounts_menu").append('<li><a href="#" onClick=filterAccounts("'+accountsJSON.items[i].name+'")>' + accountsJSON.items[i].name + "</a></li>");
//     }
// }

function deleteGraphs(options) {
    // Issues Over time
    $('#barchart_time').empty();
    // Technology PieChart
    $('#piechart').empty();
    if(options === 'all'){
        // Clear Map Markers
        removeMarkers();
        // Reset Connection Volume
        $('#barchart').empty();
    }
}

function filterAccounts(data) {
    js_filter_sev = '';
    js_filter_tech = '';
    selectedAccount = data;
    console.log('events is ', data);
    deleteGraphs('all');
    loadCharts('all')
}

function filterBySev(data) {
    js_filter_sev = data;
    console.log('techdata is ', data);
    deleteGraphs('');
    loadCharts('');
}

function filterByTech(data) {
    js_filter_tech = data.data.technology;
    // Set the attribute tech attribute value to the selected Chart Element Value.
    // This value is used by Dart to apply PAOM Filters.
    $('#tech_piechart_wrapper').attr('tech', data.data.technology);
    deleteGraphs('');
    loadCharts('');
}


