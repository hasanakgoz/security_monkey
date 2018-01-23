import boto3
import datetime
import json
import os

import requests

def gd_events_handler(event, context):
    if event:
        print event

        s3 = boto3.resource('s3')

        eventid = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")
        filename = eventid + '.json'
        filepath = '/tmp/' + filename

        g = open(filepath, 'w')
        g.write(json.dumps(event))
        g.close()

        s3.Object('sa-gd-data', filename).put(Body=open(filepath, 'rb'))

        url_base = os.environ.get('URL_BASE', 'https://34.239.115.118')
        endpoint = '/api/1/gde'
        url = '{}{}'.format(url_base, endpoint)

        headers = {
            'Authentication-Token': os.environ.get('USER_TOKEN', 'dummytoken'),
            'Content-Type': 'application/json',
        }

        print "Sending POST request to {}".format(url)
        response = requests.post(url, headers=headers, data=json.dumps(event))

        print "Response: "
        print response.content

    else:
        print "No Event"
