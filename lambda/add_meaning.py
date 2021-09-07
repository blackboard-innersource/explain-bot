import json
from urllib import parse as urlparse
import base64
from functools import lru_cache
import math
import hmac
import hashlib
import os
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
import urllib3
from datetime import datetime
from datetime import date
from explain import attachment_color, explain
import re

# Get the service resource.
dynamodb = boto3.resource('dynamodb')

# set environment variable
TABLE_NAME = os.environ['TABLE_NAME']
DENIED_TABLE_NAME = os.environ['TABLE_DENIED_NAME']
stage = os.environ['STAGE'].lower()

APPROVERS_STR = 'Approvers'
DENIERS_STR = 'Deniers'
REQUESTER_STR = 'Requester'
APPROVAL_STR = 'Approval'
APPROVAL_STATUS_PENDING = 'pending'
APPROVAL_STATUS_APPROVED = 'approved'
REQUEST_TIMESTAMP = 'RequestTimestamp'
REVIEWERS_MAX = 3

table = dynamodb.Table(TABLE_NAME)
denied_table = dynamodb.Table(DENIED_TABLE_NAME)
http = urllib3.PoolManager()

ssm = boto3.client('ssm', region_name='us-east-2')

sss = ssm.get_parameter(Name='/explainbot/parameters/'+stage+'/slack_signing_secret', WithDecryption=True)
slack_signing_secret = sss['Parameter']['Value']

oauth = ssm.get_parameter(Name='/explainbot/parameters/'+stage+'/oauth_token', WithDecryption=True)
OAUTH_TOKEN = oauth['Parameter']['Value']

approver_str = ssm.get_parameter(Name='/explainbot/parameters/'+stage+'/approvers')
APPROVERS = approver_str['Parameter']['Value'].split(',')

def get_body(event):
    return base64.b64decode(str(event['body'])).decode('ascii')


@lru_cache(maxsize=60)
def define(acronym, definition, meaning, notes, response_url, user_id, user_name, team_domain):
    results = table.put_item(
        Item={
            'Acronym': acronym,
            'Definition': definition,
            'Meaning': meaning,
            'Notes': notes,
            REQUESTER_STR: user_id,
            'RequesterName': user_name,
            APPROVAL_STR: APPROVAL_STATUS_PENDING,
            REQUEST_TIMESTAMP: int(datetime.utcnow().timestamp()),
            'TeamDomain': team_domain
        }
    )

    print(str(results))

    result = results['ResponseMetadata']['HTTPStatusCode']
    print("Result: " + str(result))

    headers = {
        'Content-Type': 'application/plain-text',
        'Authorization': 'Bearer ' + OAUTH_TOKEN
    }
    print("headers: " + str(headers))

    if result != 200:
        body = {
            "response_type": "in_channel",
            "text": 'Error (' + str(result) + ') defining ' + acronym,
        }
        print("body: " + str(body))

        response = http.request('POST', response_url, body=json.dumps(body), headers=headers)
        print("response: " + str(response.status) + " " + str(response.data))

    return result


def get_approval_form(acronym, definition, meaning, notes, team_domain, user_id, user_name, 
    date_requested, approver, ts, update, feedback):
    return {
        "attachments": [
            {
                "color": attachment_color,
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
                                "text": "*Details:*\n" + meaning
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
                        "type": "input",
                        "block_id": "feedbak_block",
                        "optional": True,
                        "element": {
                            "max_length": 500,
                            "type": "plain_text_input",
                            "action_id": "plain_text_feedback-action",
                            "multiline": True,
                            "placeholder": {
                                "type": "plain_text",
                                "text": "Provide some feedback to the user"
                            }
                        },
                        "label": {
                            "type": "plain_text",
                            "text": "Feedback:"
                        }
                    } if update == False else
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Feedback from approvers:*\n" + "feedback_msgs"
                        }
                    }
                    ,{
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "Approve"
                                },
                                "style": "primary",
                                "value": "Approve"
                            },
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
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
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Feedback from approvers:*\n" + (feedback if feedback != None and feedback != "" else "There is no feedback yet")
                        }
                    }
                ]
            }
        ],
        "channel": approver,
        "ts": ts
    }



def create_approval_request(acronym, definition, meaning, notes, team_domain, user_id, user_name, approvers):
    user_name_capitalized = " ".join(user_name)
    date_requested = date.today().strftime("%d/%m/%Y")
    approver_messages = []
    ts = None
    update = False
    feedback = None

    if meaning == "":
        meaning = "-"

    if notes == "":
        notes = "-"

    for approver in approvers:
        if approver != user_id:

            # Send approval request
            modal = get_approval_form(acronym, definition, meaning, notes, team_domain, user_id, 
                user_name_capitalized, date_requested, approver, ts, update, feedback)

            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + OAUTH_TOKEN
            }
            print("headers: " + str(headers))

            response = http.request('POST', 'https://slack.com/api/chat.postMessage', body=json.dumps(modal),
                                    headers=headers)
            print("response: " + str(response.status) + " " + str(response.data))

            data = json.loads(response.data.decode('utf-8'))

            if data.get('ok'):
                message_data = {
                    'approver': approver,
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


def build_feedback_messages_list(approver_messages, team_domain):
    feedback_msgs = ""
    for feedback in approver_messages:
        print( "ApproverFeedbackMessages: ", feedback['message'] )
        feedback_msgs += "• *<https://" + team_domain + ".slack.com/team/" + feedback['approverId'] + "|" + feedback['approverUsername'] + ":>* " + feedback['message'] + "\n"
    return feedback_msgs


def notify_approval_response(acronym, approved, requester_id, team_domain):
    print("Sending approval response...")
    blocks = []

    if approved == True:
        message = f"Your submission for *{acronym}* was approved. Thanks for contributing!"
        blocks = [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": message
                        }
                    }
                ]
    else:
        result = table.query(KeyConditionExpression=Key("Acronym").eq(acronym))

        if len(result['Items']) == 0:
            return { "statusCode": 404 }

        item = result['Items'][0]
        approver_messages = item.get("ApproverFeedbackMessages", [])
        feedback = build_feedback_messages_list(approver_messages, team_domain)
        message = f"Sorry, your submission for *{acronym}* has not been approved at this time."
        blocks = [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": message
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Feedback from approvers:*\n" + (feedback if feedback != None and feedback != "" else "There is no feedback")
                        }
                    }
                ]

    body = {
        "channel": requester_id,
        "attachments": [
            {
                "color": attachment_color,
                "blocks": blocks
            }
        ]
    }

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + OAUTH_TOKEN
    }
    print("headers: " + str(headers))

    response = http.request('POST', 'https://slack.com/api/chat.postMessage', body=json.dumps(body), headers=headers)
    print("response: " + str(response.status) + " " + str(response.data))

    data = json.loads(response.data.decode('utf-8'))
    notification_data = {}

    if data.get('ok'):
        notification_data = {
            'channel': data.get('channel'),
            'ts': data.get('ts')
        }

        table.update_item(
            Key={
                'Acronym': acronym
            },
            UpdateExpression=f"set NotificationMessage=:a",
            ExpressionAttributeValues={
                ':a': notification_data,
            },
            ReturnValues="UPDATED_NEW"
        )

def notify_pending_approval(user_id, acronym):
    print("Sending pending approval notification...")
    body = {
        "channel": user_id,
        "attachments": [
            {
                "color": attachment_color,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Submission successful!*\n Your submission for *{acronym}* has been received and is being reviewed."
                        }
                    }
                ]
            }
        ]
    }

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + OAUTH_TOKEN
    }
    print("headers: " + str(headers))

    response = http.request('POST', 'https://slack.com/api/chat.postMessage', body=json.dumps(body), headers=headers)
    print("response: " + str(response.status) + " " + str(response.data))

def notify_invalid_acronym(user_id, acronym):
    print("Sending invalid acronym notification...")
    body = {
        "channel": user_id,
        "attachments": [
            {
                "color": attachment_color,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Invalid request:* The acronym " + acronym + " is already defined."
                        }
                    }
                ]
            }
        ]
    }

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + OAUTH_TOKEN
    }
    print("headers: " + str(headers))

    response = http.request('POST', 'https://slack.com/api/chat.postMessage', body=json.dumps(body), headers=headers)
    print("response: " + str(response.status) + " " + str(response.data))


def delete_message(response_url):
    body = {
        "delete_original": "true"
    }
    headers = {
        'Content-Type': 'application/json'
    }
    print("headers: " + str(headers))
    
    try:

        response = http.request('POST', response_url, body=json.dumps(body),
                                headers=headers)
        print("delete response: " + str(response.status) + " " + str(response.data))
        
    except:
        print("Error deleting message to post in channel")
        

def post_message_in_channel(channel, acronym):
    body = {
        "channel": channel,
        "attachments": [
            {
                "color": attachment_color,
                "blocks": explain(acronym)
            }
        ]
    }
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + OAUTH_TOKEN
    }
    print("headers: " + str(headers))
    
    response = http.request('POST', 'https://slack.com/api/chat.postMessage', body=json.dumps(body), headers=headers)
    print("response: " + str(response.status) + " " + str(response.data))


def cleanup_acronym(acronym):
    return re.sub("[^0-9a-zA-Z]+", "", acronym.upper())


def get_data_from_payload(payload):
    acronym = ""
    definition = ""
    meaning = ""
    notes = ""
    team_domain = ""
    user_name = ""
    user_id = ""

    actions = payload.get('actions')

    if actions is None:
        # Obtain the data from submit payload structure
        acronym = payload['view']['state']['values']['acronym_block']['acronym_input']['value']
        definition = payload['view']['state']['values']['definition_block']['definition_input']['value']
        meaning = payload['view']['state']['values']['meaning_block']['meaning_input']['value']
        notes = payload['view']['state']['values']['notes_block']['notes_input']['value']
        team_domain = payload['team']['domain']
        user_name = [word.capitalize() for word in payload['user']['name'].split(".")]
        user_id = payload['user']['id']
    else:
        # Obtain the data from approve/deny payload structure
        acronym = payload['message']['attachments'][0]['blocks'][1]['fields'][0]['text'][12:]
        definition = payload['message']['attachments'][0]['blocks'][1]['fields'][2]['text'][14:]
        meaning = payload['message']['attachments'][0]['blocks'][1]['fields'][3]['text'][11:]
        notes = payload['message']['attachments'][0]['blocks'][2]['text']['text'][9:]
        team_domain = payload['team']['domain']
        user_name_block = payload['message']['attachments'][0]['blocks'][0]['text']['text']
        user_name = user_name_block[user_name_block.index("|") + 1:user_name_block.index(" - New acronym request")]
        user_id = user_name_block[user_name_block.index("/team/") + 6:user_name_block.index("|")]

    # Remove special characters
    acronym = cleanup_acronym(acronym)

    print("acronym: " + acronym)
    print("definition: " + definition)

    if meaning is not None:
        print("meaning: " + meaning)
    else:
        print("no meaning")
        meaning = ""

    if notes is not None:
        print("notes: " + notes)
    else:
        print("no notes")
        notes = ""

    print("team_domain: " + team_domain)
    print("user_name: " + " ".join(user_name))
    print('user id:' + user_id)

    return acronym, definition, meaning, notes, team_domain, user_name, user_id


def update_approvers_feedback_section(item, approver_messages, payload):
    acronym = item['Acronym']
    definition = item['Definition']
    meaning = item['Meaning']
    notes = item['Notes']
    team_domain = payload['team']['domain']
    user_id = payload['user']['id']
    user_name = [word.capitalize() for word in payload['user']['name'].split(".")]
    user_name_capitalized = " ".join(user_name)
    date_requested = datetime.fromtimestamp(item['RequestTimestamp']).strftime("%d/%m/%Y")
    feedback = build_feedback_messages_list(approver_messages, team_domain)
    approvers_message_list = item['ApproverMessages']

    for message in approvers_message_list:
        approver_channel = message['channel']
        ts = message['ts']

        approver_id = message['approver']
        approvers = item.get('Approvers', [])
        deniers = item.get('Deniers', [])

        # <update> is true for the approvers that already voted
        update = (approver_id in approvers or approver_id in deniers)

        modal = get_approval_form(acronym, definition, meaning, notes, team_domain, user_id, 
            user_name_capitalized, date_requested, approver_channel, ts, update, feedback)

        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + OAUTH_TOKEN
        }
        print("headers: " + str(headers))

        response = http.request('POST', 'https://slack.com/api/chat.update', body=json.dumps(modal), headers=headers)
        print("response: " + str(response.status) + " " + str(response.data))


def lambda_handler(event, context):
    print("add_meaning: " + str(event))

    if check_hash(event) == False:
        print('Signature check failed')
        print('event: ' + str(event))
        return

    body = dict(urlparse.parse_qsl(get_body(event)))  # data comes b64 and also urlencoded name=value& pairs
    print("Body: " + str(body))

    payload = json.loads(body.get('payload', "no-payload"))
    print("Payload: " + str(payload))

    actions = payload.get('actions')
    print("Actions: " + str(actions))

    event_type = payload.get('type')
    print( "Event type: " + str(event_type) )

    # Check which action was sent
    if event_type == "block_actions" and actions is not None:
        # Obtain the channel id
        channel = payload['channel']['id']
        
        action_id = actions[0]['action_id']
        
        if action_id == 'post_in_channel':
            response_url = payload['response_url']
            acronym = str(actions[0]['value'])
            delete_message(response_url)
            return post_message_in_channel(channel, acronym)
            
         # Obtain required data
        acronym, definition, meaning, notes, team_domain, user_name, user_id = get_data_from_payload(payload)

        value = actions[0]['value']

        # Obtain the date when acronym was requested
        print("Submitted: " + str(payload['message']['attachments'][0]['blocks'][1]['fields'][1]['text']))
        date_requested = payload['message']['attachments'][0]['blocks'][1]['fields'][1]['text'][18:]

        # Obtain the message's timestamp to be updated
        message_ts = payload['message']['ts']

        # Obtain the appover id
        approver_id = payload['user']['id']

        if value == 'Approve':
            update_approval_form(acronym, definition, meaning, notes, team_domain, user_id, 
                user_name, date_requested, channel, message_ts)
            return persistDecision(acronym, approver_id, True, team_domain)
        if value == 'Deny':
            trigger_id = payload['trigger_id']
            persist_feedback_from_approver(payload)
            update_approval_form(acronym, definition, meaning, notes, team_domain, user_id, user_name, date_requested,
                                 channel, False, message_ts)
            return persistDecision(acronym, approver_id, False, team_domain)

    status_code = '200'
    if event_type == "view_submission":
        callback_id = payload['view']['callback_id'
        acronym, definition, meaning, notes, team_domain, user_name, user_id = get_data_from_payload(payload)

        # Define acronym (persist in DB) and send approval request to approvers
        return_url = payload['response_urls'][0]['response_url']

        user_name_capitalized = " ".join(user_name)
        status_code = '200'
        results = table.query(KeyConditionExpression=Key("Acronym").eq(acronym))

        
        if len( results['Items'] ) == 0:
            status_code = define(acronym, definition, meaning, notes, return_url, user_id,user_name_capitalized,team_domain)
            create_approval_request(acronym, definition, meaning, notes, team_domain, user_id, user_name, APPROVERS)
            notify_pending_approval(user_id,acronym)
        else:
            notify_invalid_acronym(user_id,acronym)

    return {
        "statusCode": status_code
    }

def persist_feedback_from_approver(payload):
    feedback = payload['state']['values']['feedback_block']['plain_text_feedback-action']['value']
    print( "Feedback: ", feedback )

    acronym = payload['view']['blocks'][0]['element']['initial_value']
    print( "Acronym: ", acronym )

    result = table.query(KeyConditionExpression=Key("Acronym").eq(acronym))

    if len(result['Items']) == 0:
        return { "statusCode": 404 }

    item = result['Items'][0]
    approver_messages = item.get("ApproverFeedbackMessages", [])

    message_data = {
        'approverId': payload['user']['id'],
        'approverUsername': payload['user']['username'],
        'message': payload['view']['state']['values']['feedback_block']['plain_text_feedback-action']['value'],
    }
    approver_messages.append(message_data)
    
    table.update_item(
        Key={
            'Acronym': acronym
        },
        UpdateExpression=f"set ApproverFeedbackMessages=:a",
        ExpressionAttributeValues={
            ':a': approver_messages,
        },
        ReturnValues="UPDATED_NEW"
    )

def update_form_closed(item, team_domain):
    try:
        approvers_message_list = item['ApproverMessages']
        acronym = item['Acronym']
        approver_messages = item.get("ApproverFeedbackMessages", [])
        feedback = build_feedback_messages_list(approver_messages, team_domain)
        for element in approvers_message_list:
            modal = {
                "attachments": [
                    {
                        "color": attachment_color,
                        "blocks": [
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": f"*The request for {acronym} is completed.*\n Thanks for contributing, the voting is closed!"
                                }
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "*Feedback from approvers:*\n" + (feedback if feedback != None and feedback != "" else "There is no feedback")
                                }
                            }
                        ]
                    }
                ],
                "channel": element['channel'],
                "ts": element['ts']
            }

            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + OAUTH_TOKEN
            }
            print("headers: " + str(headers))

            response = http.request('POST', 'https://slack.com/api/chat.update', body=json.dumps(modal),
                                    headers=headers)
            print("response: " + str(response.status) + " " + str(response.data))
    except:
        print("Error in update_form_closed")


def update_approval_form(acronym, definition, meaning, notes, team_domain, user_id, user_name, 
    date_requested, channel, message_ts):
    update = True
    feedback = None

    if meaning == "":
        meaning = "-"

    if notes == "":
        notes = "-"

    # Update approval message form
    modal = get_approval_form(acronym, definition, meaning, notes, team_domain, user_id, user_name, date_requested,
                              channel, message_ts, update, feedback)

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + OAUTH_TOKEN
    }
    print("headers: " + str(headers))

    response = http.request('POST', 'https://slack.com/api/chat.update', body=json.dumps(modal), headers=headers)
    print("response: " + str(response.status) + " " + str(response.data))

def persistDecision(acronym, userId, decision, team_domain):
    result = table.query(KeyConditionExpression=Key("Acronym").eq(acronym))

    if len(result['Items']) == 0:
        return {"statusCode": 404}

    item = result['Items'][0]

    decisionStr = APPROVERS_STR if decision else DENIERS_STR
    reviewers = item.get(decisionStr, [])
    approval_status = item.get(APPROVAL_STR)
    requester_id = item.get(REQUESTER_STR)

    # TODO: Ignore approval action
    if checkAlreadyReviewed(result, userId) or approval_status == APPROVAL_STATUS_APPROVED:
        return {"statusCode": 400}

    reviewers.append(userId)

    if decision and len(reviewers) >= REVIEWERS_MAX:
        table.update_item(
            Key={
                'Acronym': acronym
            },
            UpdateExpression=f"set {APPROVAL_STR}=:d",
            ExpressionAttributeValues={
                ':d': APPROVAL_STATUS_APPROVED,
            },
            ReturnValues="UPDATED_NEW"
        )
        response = update_reviewers(acronym, reviewers, decisionStr)
        update_form_closed(item, team_domain)
    else:
        if not decision and len(reviewers) >= REVIEWERS_MAX:
            result = table.query(KeyConditionExpression=Key("Acronym").eq(acronym))

            if len(result['Items']) == 0:
                return {"statusCode": 404}

            item = result['Items'][0]
            results = denied_table.put_item(
                Item={
                    'Acronym': item.get("Acronym", ""),
                    'Deleted_at': str(datetime.utcnow().timestamp()),
                    'Definition': item.get("Definition", ""),
                    'Meaning': item.get("Meaning", ""),
                    'Notes': item.get("Notes", ""),
                    REQUESTER_STR: item.get("Requester", ""),
                    'RequesterName': item.get("RequesterName", ""),
                    APPROVAL_STR: item.get("Approval", "Denied"),
                    REQUEST_TIMESTAMP: item.get("RequestTimestamp", ""),
                    'TeamDomain': item.get("TeamDomain", "")
                }
            )

            print(str(results))

            result = results['ResponseMetadata']['HTTPStatusCode']
            print("Result: " + str(result))
            
            response = table.delete_item(
                Key={
                    'Acronym': acronym
                }
            )
            update_form_closed(item, team_domain)
        else:
            response = update_reviewers(acronym, reviewers, decisionStr)

    if len(reviewers) >= REVIEWERS_MAX:
        notify_approval_response(acronym, decision, requester_id, team_domain)

    return {
        "statusCode": response['ResponseMetadata']['HTTPStatusCode']
    }


def update_reviewers(acronym, reviewers, decisionStr):
    response = table.update_item(
        Key={
            'Acronym': acronym
        },
        UpdateExpression=f"set {decisionStr}=:d",
        ExpressionAttributeValues={
            ':d': reviewers,
        },
        ReturnValues="UPDATED_NEW"
    )

    return response


def checkAlreadyReviewed(result, userId):
    approvers = result['Items'][0].get(APPROVERS_STR, [])
    denyers = result['Items'][0].get(DENIERS_STR, [])

    return userId in approvers or userId in denyers


def check_hash(event):
  body = get_body(event)
  timestamp = event["headers"]['x-slack-request-timestamp']
  sig_basestring = 'v0:' + timestamp + ':' + body
  my_signature = 'v0=' + hmac.new(
    bytes(slack_signing_secret, 'UTF-8'),
    msg=bytes(sig_basestring, 'UTF-8'),
    digestmod=hashlib.sha256
  ).hexdigest()
  print("Generated signature: " + my_signature)
  slack_signature = event['headers']['x-slack-signature']
  print("Slack signature: " + slack_signature)

  return hmac.compare_digest(my_signature, slack_signature)