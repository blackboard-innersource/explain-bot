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


http = urllib3.PoolManager()
# Get the service resource.
dynamodb = boto3.resource('dynamodb')
table_name = os.environ['TABLE_NAME']
table = dynamodb.Table(table_name)
APPROVERS = os.environ['APPROVERS'].split(',')
OAUTH_TOKEN = os.environ['OAUTH_TOKEN']

# Change to TO_DAYS = 60*60*24
TO_MINUTES = 60
REQUEST_TIMESTAMP = 'RequestTimestamp'
APPROVERS_STR = 'Approvers'
DENIERS_STR = 'Deniers'


def send_reminder(acronym, definition, meaning, notes, user_id, user_name, team_domain, approvers_with_answer):
    approvers_missing = [approver for approver in APPROVERS if approver not in approvers_with_answer ]
    print(approvers_missing)
    create_approval_request(acronym, definition, meaning, notes, team_domain, user_id, user_name, approvers_missing)

def create_approval_request(acronym, definition, meaning, notes, team_domain, user_id, user_name, approvers):

    user_name_capitalized = " ".join(user_name)
    date_requested = date.today().strftime("%d/%m/%Y")
    approver_messages = []

    if meaning is "":
        meaning = "-"

    for approver in approvers:
        if approver == user_id:

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

    if len(results['Items']) > 0:
        items = results['Items']

        for item in items:
            request_time = float(item.get(REQUEST_TIMESTAMP))
            current_time = float(datetime.utcnow().timestamp())
            # Change to TO_DAYS
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

            # Change to 30 
            if diff_time == 1:
                send_reminder(acronym, definition, meaning, notes, user_id, user_name, team_domain, approvers_with_answer)
            # Change to 60
            elif diff_time == 2:
                update_form_closed(item)
                response = table.delete_item(
                    Key={
                        'Acronym': acronym
                    }
                )

