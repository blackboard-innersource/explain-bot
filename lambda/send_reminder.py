import boto3
import os
from datetime import datetime

# Get the service resource.
dynamodb = boto3.resource('dynamodb')
table_name = os.environ['TABLE_NAME']
table = dynamodb.Table(table_name)

TO_MINUTES = 1000*60
REQUEST_TIMESTAMP = 'RequestTimestamp'
SENT_REMINDERS = 'Reminders'

def send_reminder(event):
    return

def lambda_handler(event, context):

    results = table.query(KeyConditionExpression=Key("Approval").eq('pending'))
    if len(results['Items']) > 0:
    items = results['Items']

    for item in items:
        print(item.get('Acronym'))
        request_time = item.get(REQUEST_TIMESTAMP)/TO_MINUTES
        current_time = datetime.utcnow().timestamp()/TO_MINUTES

        """
        if current_time - request_time > 10 and item.get(SENT_REMINDERS) == 0:
            send_reminder()
        """

