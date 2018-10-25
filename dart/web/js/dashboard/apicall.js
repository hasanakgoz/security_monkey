var resp;

function callapi(specificurl, type) {
    return new Promise((resolve, reject) => {
        var data = null;
    var xhr = new XMLHttpRequest();
    xhr.withCredentials = true;
    xhr.addEventListener("readystatechange", function () {
        if (this.readyState === 4) {
            // console.log(this.responseText);
            resolve(this.responseText);
        }
    });

    xhr.open("GET", baseurl + specificurl);
    xhr.setRequestHeader("Accept", "application/json, text/plain, */*");
    xhr.setRequestHeader("Accept-Language", "en-US,en;q=0.5");
    xhr.send(data);
});
}
