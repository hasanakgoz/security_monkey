from security_monkey.datastore import AnchoreConfig
from security_monkey.views import AuthenticatedService
from security_monkey import rbac
from security_monkey.anchore_manager import AnchoreManager
from flask import request
from flask_restful import marshal, reqparse, fields

ANCHORE_DATA_FIELDS = {
    'id' : fields.Integer,
    'name': fields.String,
    'username': fields.String,
    'password': fields.String,
    'url': fields.String,
    'ssl_verify': fields.Boolean
}


class AnchoreGetPutDelete(AuthenticatedService):

    decorators = [
        rbac.allow(["View"], ["GET"]),
        rbac.allow(["Admin"], ["PUT", "DELETE"])
    ]
    anchore = AnchoreManager()

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(AnchoreGetPutDelete, self).__init__()

    def get(self, anchore_id):
        """
            .. http:get:: /api/1/anchore/<integer:anchore_id>
            Get a list of Anchore Engine Configuration Items matching the given criteria
            **Example Request**:
            .. sourcecode:: http
                GET /api/1/account/1 HTTP/1.1
                Host: example.com
        """

        result = self.anchore.get_anchore_config_item(anchore_id)
        anchore_marshaled = marshal(result, ANCHORE_DATA_FIELDS)
        anchore_marshaled = dict(
            anchore_marshaled.items())

        return anchore_marshaled, 200

    def put(self, anchore_id):
        """
            .. http:put:: /api/1/account/<integer:anchore_id>

            Edit an existing anchore configuration item.
            **Example Request**:
            .. sourcecode:: http
                PUT /api/1/anchore/1 HTTP/1.1
                Host: example.com
                Accept: application/json
                {
                    'name': 'edited_name'
                    'username': '0123456789',
                    'password': 'SeCrEtPassword',
                    'ssl_verify': true,
                    'url': "http://go.to/here"
                }
        """
        args = request.json
        username = args['username']
        name = args['name']
        password = args['password']
        url = args['url']
        ssl_verify = args['ssl_verify']

        try:
            anchore_config_item = self.anchore.update_anchore_config_item(anchore_id, name, username, password, url, ssl_verify)
        except:
            return {'status': 'error. No such configuration item exists.'}, 409
        if not anchore_config_item:
            return {'status': 'error. No such configuration item exists.'}, 404

        marshaled_anchore = marshal(anchore_config_item.__dict__, ANCHORE_DATA_FIELDS)
        marshaled_anchore['auth'] = self.auth_dict

        return marshaled_anchore, 200

    def delete(self, anchore_id):
        """
            .. http:delete:: /api/1/anchore/<integer:anchore_id>
            Delete an existing anchore configuration item.
            **Example Request**:
            .. sourcecode:: http
                DELETE /api/1/account/1 HTTP/1.1
                Host: example.com
                Accept: application/json
        """
        self.anchore.delete_anchore_config_item(anchore_id)
        return {'status': 'deleted'}, 202


class AnchorePostList(AuthenticatedService):
    decorators = [
        rbac.allow(["View"], ["GET"]),
        rbac.allow(["Admin"], ["POST"])
    ]
    anchore = AnchoreManager()

    def __init__(self):
        super(AnchorePostList, self).__init__()
        self.reqparse = reqparse.RequestParser()

    def post(self):
        """
            .. http:post:: /api/1/anchore/
            Create a new anchore configuration item.
            **Example Request**:
            .. sourcecode:: http
                POST /api/1/anchore/ HTTP/1.1
                Host: example.com
                Accept: application/json
                {
                    'name': 'Test Anchore Instance'
                    'username': 'anchore_username',
                    'password': 'pass',
                    'url': '///////',
                    'ssl_verify': true
                }
        """
        args = request.json
        username = args['username']
        password = args['password']
        url = args['url']
        ssl_verify = args['ssl_verify']
        name = args['name']
        try:
            anchore_config_item = self.anchore.create_anchore_config_item(name, username, password, url, ssl_verify)
        except:
            return {'status': 'error. saving Anchore Engine Configuration.'}, 409

        if not anchore_config_item:
            return {'status': 'Another configuration with same name {} exists!'.format(name) }, 409

        marshaled_anchore_config_items = marshal(anchore_config_item.__dict__, ANCHORE_DATA_FIELDS)
        return marshaled_anchore_config_items, 200

    def get(self):

        """
            .. http:get:: /api/1/anchore/
            Get a list of all Anchore Configuration Items
            **Example Request**:
            .. sourcecode:: http
                GET /api/1/account/1 HTTP/1.1
                Host: example.com
        """

        self.reqparse.add_argument('count', type=int, default=30, location='args')
        self.reqparse.add_argument('page', type=int, default=1, location='args')
        self.reqparse.add_argument('order_by', type=str, default=None, location='args')
        self.reqparse.add_argument('order_dir', type=str, default='desc', location='args')

        args = self.reqparse.parse_args()
        page = args.pop('page', None)
        count = args.pop('count', None)
        order_by = args.pop('order_by', None)
        order_dir = args.pop('order_dir', None)
        for k, v in args.items():
            if not v:
                del args[k]

        query = AnchoreConfig.query

        if order_by and hasattr(AnchoreConfig, order_by):
            if order_dir.lower() == 'asc':
                    query = query.order_by(getattr(AnchoreConfig, order_by).asc())
            else:
                    query = query.order_by(getattr(AnchoreConfig, order_by).desc())
        else:
            query = query.order_by(AnchoreConfig.id)

        result = query.paginate(page, count, error_out=False)

        items = []
        for item in result.items:
            anchore_config_marshaled = marshal(item.__dict__, ANCHORE_DATA_FIELDS)
            items.append(anchore_config_marshaled)

        marshaled_dict = {
            'total': result.total,
            'count': len(items),
            'page': result.page,
            'items': items,
            'auth': self.auth_dict
        }

        return marshaled_dict, 200
