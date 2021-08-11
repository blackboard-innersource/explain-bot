import json
from urllib import parse as urlparse
import os
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
import urllib3
from datetime import datetime
from datetime import date



http = urllib3.PoolManager()
# Get the service resource.
dynamodb = boto3.resource('dynamodb')
table_name = os.environ['TABLE_NAME']
table = dynamodb.Table(table_name)
APPROVERS = os.environ['APPROVERS'].split(',')
OAUTH_TOKEN = os.environ['OAUTH_TOKEN']

TO_MINUTES = 60
REQUEST_TIMESTAMP = 'RequestTimestamp'
SENT_REMINDERS = 'Reminders'
APPROVERS_STR = 'Approvers'
DENIERS_STR = 'Deniers'


def update_form_closed(item):
    try:
        approvers_message_list = item['ApproverMessages']
        acronym = item['Acronym']
        for reg in approvers_message_list:
            modal = {
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*The request for: " + acronym  + " is completed. Thanks for contributing, the voting is closed!*\n"
                        }
                    }
                ],
                "channel": reg['channel'],
                "ts": reg['ts']
            }

            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + OAUTH_TOKEN
            }
            print("headers: " + str(headers))

            response = http.request('POST', 'https://slack.com/api/chat.update', body=json.dumps(modal), headers=headers)
            print("response: " + str(response.status) + " " + str(response.data))
    except:
        print( "Error")

def send_reminder(acronym, definition, meaning, notes, user_id, user_name, team_domain, approvers_with_answer):
    print('Got to send reminder')
    approvers_missing = [approver for approver in APPROVERS if approver not in approvers_with_answer ]
    print(approvers_missing)
    create_approval_request(acronym, definition, meaning, notes, team_domain, user_id, user_name, approvers_missing)
        

def get_approval_form(acronym, definition, meaning, notes, team_domain, user_id, user_name, date_requested, approver, ts, update):
    return {
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*You have a new request:*\n<https://" + team_domain + ".slack.com/team/" + user_id + "|" + user_name + " - New acronym request>"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": "*Acronym:*\n " + acronym
                            },
                            {
                                "type": "mrkdwn",
                                "text": "*When:*\nSubmitted " + date_requested
                            },
                            {
                                "type": "mrkdwn",
                                "text": "*Definition:*\n" + definition
                            },
                            {
                                "type": "mrkdwn",
                                "text": "*Meaning:*\n" + meaning
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Notes:*\n" + notes
                        }
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "emoji": True,
                                    "text": "Approve"
                                },
                                "style": "primary",
                                "value": "Approve"
                            },
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "emoji": True,
                                    "text": "Deny"
                                },
                                "style": "danger",
                                "value": "Deny"
                            }
                        ]
                    } if update == False else 
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": ":white_check_mark: *Your choice has been saved successfully!*\n"
                        }
                    }
                ],
                "channel": approver,
                "ts": ts if update == True else None
            }

def create_approval_request(acronym, definition, meaning, notes, team_domain, user_id, user_name, approvers):

    user_name_capitalized = " ".join(user_name)
    date_requested = date.today().strftime("%d/%m/%Y")
    approver_messages = []

    if meaning is "":
        meaning = "-"

    for approver in approvers:
        print('iterate approvers')
        print(approver)
        if approver == user_id:
            print('Send my own ')
            #Send approval request
            modal = get_approval_form(acronym, definition, meaning, notes, team_domain, user_id, user_name_capitalized, date_requested, approver, None, False)

            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + OAUTH_TOKEN
            }
            print("headers: " + str(headers))

            response = http.request('POST', 'https://slack.com/api/chat.postMessage', body=json.dumps(modal), headers=headers)
            print("response: " + str(response.status) + " " + str(response.data))

            data = json.loads(response.data.decode('utf-8'))

            if data.get('ok'):
                message_data = {
                    'channel': data.get('channel'),
                    'ts': data.get('ts')
                }
                approver_messages.append(message_data)

        else:
            print("Skip approver due to approver sent acronym request")

    table.update_item(
        Key={
            'Acronym': acronym
        },
        UpdateExpression=f"set ApproverMessages=:a",
        ExpressionAttributeValues={
            ':a': approver_messages,
        },
        ReturnValues="UPDATED_NEW"
    )

def lambda_handler(event, context):

    results = table.query(IndexName="approval_index", KeyConditionExpression=Key("Approval").eq('pending'))
    print(results)
    if len(results['Items']) > 0:
        items = results['Items']
        print(items)
        for item in items:
            request_time = float(item.get(REQUEST_TIMESTAMP))
            current_time = float(datetime.utcnow().timestamp())
            diff_time  = (current_time - request_time)//TO_MINUTES

            acronym = item.get('Acronym')
            print(acronym)
            definition = item.get('Definition')
            meaning = item.get('Meaning')
            notes = item.get('Notes')
            user_id = item.get('Requester')
            user_name = item.get('RequesterName')
            team_domain = item.get('TeamDomain')
            approvers_with_answer = item.get(APPROVERS_STR, []) + item.get(DENIERS_STR, [])

            if diff_time == 1:
                send_reminder(acronym, definition, meaning, notes, user_id, user_name, team_domain, approvers_with_answer)
            elif diff_time == 2:
                update_form_closed(item)
                response = table.delete_item(
                    Key={
                        'Acronym': acronym
                    }
                )

