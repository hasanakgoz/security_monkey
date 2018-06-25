library security_monkey.anchore_config_item;

import 'dart:convert';
import 'dart:html';
import '../util/constants.dart';


class AnchoreConfigItem {
    int id;
    String name;
    String username;
    String password;
    String url;
    bool ssl_verify;
    AnchoreConfigItem();
    AnchoreConfigItem.fromMap(Map data) {
        id = data["id"];
        name = data["name"];
        username = data["username"];
        password = data["password"];
        url = data["url"];
        ssl_verify = data["ssl_verify"];
    }


    String toJson() {
        Map objmap = {
            "id":id,
            "name": name,
            "username": username,
            "password": password,
            "url": url,
            "ssl_verify": ssl_verify,
        };
        return JSON.encode(objmap);
    }

}
