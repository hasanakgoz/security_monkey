
var vulnbyseverityJSON;
var top10CountryGuardDutyJSON;
var worldmapguarddutydataJSON;
var selectedAccount='';
var issuesByTimeJSON;
var count=10;
var page =1;

$(document).ready(function () {
    // getAccounts('active=true&count=1000000000&page='+page);
    getVulnBySeverity('accounts=');
    getTop10CountryGuardDuty('accounts=');
    getWorldMapGuardDutyData('accounts=');
    // getPoamItems('count='+count+'&page='+page);
    getVulnByTech('accounts=');
    getIssuesByTime('');
    drawmap();
    document.getElementById('mapModal').style.display = "none"
})


function getVulnBySeverity(params) {
    $.when(callapi('vulnbyseverity?'+params, 'GET')).then(function (response) {
        response.then(resp=>{
            vulnbyseverityJSON = JSON.parse(resp);
            $('#spn_high').text(vulnbyseverityJSON.items[0].high);
            $('#spn_medium').text(vulnbyseverityJSON.items[0].medium);
            $('#spn_low').text(vulnbyseverityJSON.items[0].low);
        });
    });
}

function getVulnByTech(params) {

    $.when(callapi('vulnbytech?'+params, 'GET')).then(function (response) {
        response.then(resp=>{
            vulnbytechJSON = JSON.parse(resp);
            createPieChart(vulnbytechJSON.items);
        });
    });
}

function getTop10CountryGuardDuty(params) {
    $.when(callapi('top10countryguarddutydata?'+params, 'GET')).then(function (response) {
        response.then(resp=>{
            top10CountryGuardDutyJSON = JSON.parse(resp);
            createCountryBarChart(top10CountryGuardDutyJSON.items,'barchart');
        });
    });
}

function getWorldMapGuardDutyData(params) {
    $.when(callapi('worldmapguarddutydata?'+params, 'GET')).then(function (response) {
        response.then(resp=>{
            worldmapguarddutydataJSON = JSON.parse(resp);
            loadData(worldmapguarddutydataJSON.items);
        });
    });
}

function getIssuesByTime(param) {
    $.when(callapi('issuescountbymonth'+param, 'GET')).then(function (response) {
        response.then(resp=>{
            issuesByTimeJSON = JSON.parse(resp);
            createCountryBarChart(issuesByTimeJSON.items,'barchart_time');
        });
    });
}


// function appendAccounts() {
//     for (var i = 0; i < accountsJSON.items.length; i++) {
//         // $("#accounts_menu ul").append(' <li onClick="filterAccounts()" data-custom='+accountsJSON.items[i].identifier+'>'+accountsJSON.items[i].name+'</li>')
//         $("#accounts_menu").append('<li><a href="#" onClick=filterAccounts("'+accountsJSON.items[i].name+'")>' + accountsJSON.items[i].name + "</a></li>");
//     }
// }

function deleteGraphs(){
    $('#barchart_time').empty();
    $('#piechart').empty();
}

function filterAccounts(data) {
    selectedAccount = data;
    console.log('events is ', data);
    deleteGraphs();
    $('#barchart').empty();
    getVulnBySeverity('accounts='+data);
    getTop10CountryGuardDuty('accounts='+data);
    getWorldMapGuardDutyData('accounts='+data);
    // getPoamItems('count='+count+'&page='+page+'&accounts='+data);
    getVulnByTech('accounts='+data);
    getIssuesByTime('?accounts='+data);
}

function filterBySev(data){
    console.log('techdata is ',data);
    deleteGraphs();
    // getPoamItems('count='+count+'&page='+page+'&sev='+data);
    getVulnByTech('sev='+data);
    getIssuesByTime('?sev='+data);
}

function filterByTech(data){
    console.log('techdata is ',data);
    $('#barchart_time').empty();
    // getPoamItems('count='+count+'&page='+page+'&tech='+data);
    getIssuesByTime('?tech='+data);
}


