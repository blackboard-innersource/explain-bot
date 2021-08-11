import json
from urllib import parse as urlparse
import os
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
import urllib3
from datetime import datetime
from datetime import date
from add_meaning import update_form_closed, get_approval_form
from explain import attachment_color

http = urllib3.PoolManager()
# Get the service resource.
dynamodb = boto3.resource('dynamodb')
table_name = os.environ['TABLE_NAME']
table = dynamodb.Table(table_name)
APPROVERS = os.environ['APPROVERS'].split(',')
OAUTH_TOKEN = os.environ['OAUTH_TOKEN']

TO_DAYS = 60 * 60 * 24
REQUEST_TIMESTAMP = 'RequestTimestamp'
APPROVERS_STR = 'Approvers'
DENIERS_STR = 'Deniers'


def send_reminder(item):
    approvers_with_answer = item.get(APPROVERS_STR, []) + item.get(DENIERS_STR, [])
    approvers_missing = [approver for approver in APPROVERS if approver not in approvers_with_answer]
    approver_messages = item['ApproverMessages']
    team_domain = item['TeamDomain']
    acronym = item['Acronym']

    for message in approver_messages:
        approver = message['approver']
        if approver in approvers_missing:
            channel = message['channel']
            ts = message['ts']
            block = get_reminder_block(acronym, team_domain, approver, channel, ts)
            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + OAUTH_TOKEN
            }
            print("headers: " + str(headers))

            response = http.request('POST', 'https://slack.com/api/chat.postMessage', body=json.dumps(block),
                                    headers=headers)
            print("response: " + str(response.status) + " " + str(response.data))


def get_reminder_block(acronym, team_domain, approver, channel, ts):
    return {
        "attachments": [
            {
                "color": attachment_color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "Reminder"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"You have a pending request for the acronym: *{acronym}*."
                        },
                        "accessory": {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "Approve or Deny"
                            },
                            "value": "click_me_123",
                            "url": f"https://{team_domain}.slack.com/archives/{channel}/p{ts.replace('.','')}",
                            "action_id": "button-action"
                        }
                    }
                ]
            }
        ],
        "channel": approver
    }


def lambda_handler(event, context):
    results = table.query(IndexName="approval_index", KeyConditionExpression=Key("Approval").eq('pending'))
    if len(results['Items']) > 0:
        items = results['Items']
        for item in items:
            request_time = float(item.get(REQUEST_TIMESTAMP))
            current_time = float(datetime.utcnow().timestamp())
            diff_time = (current_time - request_time) // TO_DAYS
            acronym = item.get('Acronym')

            if diff_time == 30:
                send_reminder(item)
            elif diff_time == 60:
                update_form_closed(item)
                response = table.delete_item(
                    Key={
                        'Acronym': acronym
                    }
                )
