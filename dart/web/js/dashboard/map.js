<!-- World map MapBox-->

var map;
var markergroup;
var markerClusters;

function drawmap() {
    var apiKey = 'pk.eyJ1Ijoic2FjaGlucmF0aGkiLCJhIjoiY2plNWxxNzUwMWg2ZzMzbXU2Zmh3cHR2aCJ9.9FJw0UNcmUlfQNQV7NJayg';
    var Icon;
    markergroup = [];
    if (!map) {
        map = L.map('mapid', {
                //worldCopyJump: true
            }
        ).setView([-33.743, 151.275], 11);
    }
    // create the tile layer with correct attribution
    var osmUrl = 'https://api.tiles.mapbox.com/v4/{id}/{z}/{x}/{y}.png?access_token=' + apiKey;
    var osmAttrib = 'Map data © <a href="http://openstreetmap.org">OpenStreetMap</a> contributors';
    var osm = new L.TileLayer(osmUrl, {
        attribution: osmAttrib,
        id: 'mapbox.streets',
        maxZoom: 18
    });
    map.addLayer(osm);
}

function loadData(d) {
    if (markergroup.length > 0) {
        removeMarkers();
    }
    markerClusters = L.markerClusterGroup();
    var iconurl = 'images/pin-green@2x.png';
    Icon = L.icon({
        iconUrl: iconurl
    });
    for (var i = 0; i < d.length; i++) {
        var marker = L.marker([d[i].lat, d[i].lon], {icon: Icon})
            .on('click', markerOnClick.bind(null, d[i]))
            .on('mouseout', markermouseout);
        marker['country'] = d[i].countryName;
        markergroup.push(marker);
        markerClusters.addLayer(marker);
    }
    map.addLayer(markerClusters);
    var group = new L.featureGroup(markergroup);
    map.fitBounds(group.getBounds());
}

function removeMarkers() {
    for (var i = 0; i < markergroup.length; i++) {
        map.removeLayer(markergroup[i]);
    }
    map.removeLayer(markerClusters);
    markerClusters.clearLayers()
}

function markerOnClick(data) {
    if(data.severity === 'Low'){
        $('#sev_img').attr('src','images/low_sev.png');
    }
    else if(data.severity === 'Medium'){
        $('#sev_img').attr('src','images/med_sev.png');
    }
    else if(data.severity === 'High'){
        $('#sev_img').attr('src','images/high_sev.png');
    }
    $('#gotoitem').attr('href','#/viewitem/'+data.item_id)
    $('#ip_address').text(data.remoteIpV4);
    $('#city').text(data.cityName);
    $('#country').text(data.countryName);
    $('#lat').text(data.lat);
    $('#lon').text(data.lon);
    $('#asn').text(data.remoteOrgASN);
    $('#asn_org').text(data.remoteOrgASNOrg);
    $('#isp').text(data.remoteOrgISP);
    $('#org').text(data.remoteOrg);
    $('#first_seen').text(data.first_seen);
    $('#last_seen').text(data.last_seen);
    $('#port').text(data.localPort);
    $('#port_name').text(data.LocalPortDetails_PortName);
    $('#severity').text(data.severity);
    $('#region').text(data.region);
    $('#count').text(data.count);
    $('#accountid').text(data.accountid);
    $('#description').text(data.description);

    document.getElementById('mapModal').style.display = "block";
}

function closeModal() {
    if (document.getElementById('mapModal').style.display == "block") {
        document.getElementById('mapModal').style.display = "none"
    }
    else if (document.getElementById('mapModal').style.display == "none") {
        document.getElementById('mapModal').style.display = "block";
    }
}

function markermouseout(e) {
    // var chart = null;
}

function changecenter(datacountry) {
    var countrymarkers = markergroup.filter(element => {
        return element.country === datacountry.countryName;
    })
    var group = new L.featureGroup(countrymarkers);

    map.fitBounds(group.getBounds());

}