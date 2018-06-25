"""
.. module: security_monkey.anchore
    :platform: Unix


.. version:: $$VERSION$$
.. moduleauthor:: Pritam D. Gautam @nuagedm

"""
from .datastore import AnchoreConfig
from security_monkey import app, db



class AnchoreManager(object):

    def __init__(self):
        pass

    def list_anchore_config(self):
        """
        :return: all anchore engine configuration records
        """
        anchore_results = AnchoreConfig.query.order_by(AnchoreConfig.id).all()

        output = []

        for anchore_result in anchore_results:

            anch = {
                'id': anchore_result.id,
                'username': anchore_result.username,
                'password': anchore_result.password,
                'url': anchore_result.url,
                'ssl_verify': anchore_result.ssl_verify,
                'name': anchore_result.name
                }
            output.append(anch)

        return output

    def get_anchore_config_item(self, id):
        """
        :param name: id of the anchore engine configuration item
        :return: config
        """
        anchore_result = AnchoreConfig.query.filter(AnchoreConfig.id == id).first()

        if not anchore_result:
            raise Exception("Anchore Entity with id [{}] not found.".format(id))

        output = {
            'id': anchore_result.id,
            'username': anchore_result.username,
            'password': anchore_result.password,
            'url': anchore_result.url,
            'ssl_verify': anchore_result.ssl_verify,
            'name': anchore_result.name
        }

        return output


    def create_anchore_config_item(self, name, username, password, url, ssl_verify=True):
        """
        Creates an anchore anchore engine configuration item in the database.
        """

        items = AnchoreConfig.query.filter(AnchoreConfig.name == name).first()
        if items:
            app.logger.error(
                'Another Anchore Engine configuration with same name {} exists!'.format(name))
            return None

        anch = AnchoreConfig()
        anch.name = name
        anch.password = password
        anch.username = username
        anch.ssl_verify = ssl_verify
        anch.url = url

        db.session.add(anch)
        db.session.commit()
        return anch


    def delete_anchore_config_item(self, id):
        """
        Creates an anchore engine configuration item in the database.
        """
        record = AnchoreConfig.query.filter(AnchoreConfig.id == id).first()
        if not record:
            app.logger.error(
                'Anchore Engine Configuration item with id {} does not exists!'.format(id))
            return None

        db.session.delete(record)
        db.session.commit()

    def update_anchore_config_item(self, id, name, username, password, url, ssl_verify=True):

        record = AnchoreConfig.query.filter(AnchoreConfig.id == id).first()
        if not record:
            app.logger.error(
                'Anchore Engine Configuration item with id {} does not exists!'.format(id))
            return None

        record.name = name
        record.username = username
        record.password = password
        record.url = url
        record.ssl_verify = ssl_verify
        db.session.commit()

        return record


