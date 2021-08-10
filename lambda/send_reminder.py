import boto3
import os
from datetime import datetime
from boto3.dynamodb.conditions import Key

# Get the service resource.
dynamodb = boto3.resource('dynamodb')
table_name = os.environ['TABLE_NAME']
table = dynamodb.Table(table_name)
APPROVERS = os.environ['APPROVERS'].split(',')
OAUTH_TOKEN = os.environ['OAUTH_TOKEN']

TO_MINUTES = 1000*60
REQUEST_TIMESTAMP = 'RequestTimestamp'
SENT_REMINDERS = 'Reminders'
APPROVERS_STR = 'Approvers'
DENIERS_STR = 'Deniers'


def update_form_closed(item):
    try:
        approvers_message_list = item['ApproverMessages']

        for item in approvers_message_list:
            modal = {
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*The request for: " + acronym + " is completed. Thanks for contributing, the voting is closed!*\n"
                        }
                    }
                ],
                "channel": item['channel'],
                "ts": item['ts']
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

def send_reminder(acronym, definition, meaning, notes, user_id, user_name, team_domain, approvers_with_answer, delete):
    approvers_missing = [approver for approver in approvers_with_answer if item not in APPROVERS ]
    create_approval_request(acronym, definition, meaning, notes, team_domain, user_id, user_name, approvers_missing)
    if delete:
        response = table.delete_item(
                Key={
                    'Acronym': acronym
                }
        )
        # update_form_closed()

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
        if approver != user_id:

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

    results = table.query(KeyConditionExpression=Key("Approval").eq('pending'))
    if len(results['Items']) > 0:
        items = results['Items']

        for item in items:
            request_time = item.get(REQUEST_TIMESTAMP)//TO_MINUTES
            current_time = datetime.utcnow().timestamp()//TO_MINUTES
            diff_time  = current_time - request_time

            acronym = item.get('Acronym')
            print(acronym)
            definition = item.get('Definition')
            meaning = item.get('Meaning')
            notes = item.get('Notes')
            user_id = item.get('Requester')
            user_name = item.get('RequesterName')
            team_domain = item.get('TeamDomain')
            approvers_with_answer = item.get(APPROVERS_STR, []) + item.get(DENIERS_STR, [])

            if diff_time == 5:
                send_reminder(acronym, definition, meaning, notes, user_id, user_name, team_domain, approvers_with_answer, False)
            elif diff_time == 10:
                send_reminder(acronym, definition, meaning, notes, user_id, user_name, team_domain, approvers_with_answer, True)
            else:
                print('Should have been deleted')

