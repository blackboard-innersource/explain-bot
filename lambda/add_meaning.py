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
from explain import attachment_color

# Get the service resource.
dynamodb = boto3.resource('dynamodb')

# set environment variable
TABLE_NAME = os.environ['TABLE_NAME']
OAUTH_TOKEN = os.environ['OAUTH_TOKEN']
APPROVERS = os.environ['APPROVERS'].split(',')
APPROVERS_STR = 'Approvers'
DENIERS_STR = 'Deniers'
REQUESTER_STR = 'Requester'
APPROVAL_STR = 'Approval'
APPROVAL_STATUS_PENDING = 'pending'
APPROVAL_STATUS_APPROVED = 'approved'
REQUEST_TIMESTAMP = 'RequestTimestamp'
REVIEWERS_MAX = 3

table = dynamodb.Table(TABLE_NAME)
http = urllib3.PoolManager()


def get_body(event):
    return base64.b64decode(str(event['body'])).decode('ascii')


@lru_cache(maxsize=60)
def explain(acronym):
    results = table.query(KeyConditionExpression=Key("Acronym").eq(acronym))

    try:
        item = results['Items'][0]

        retval = item['Acronym'] + " - " + item['Definition'] + "\n---\n*Meaning*: " + item['Meaning'] + "\n*Notes*: " + \
                 item['Notes']

    except:
        retval = f'Acronym *{acronym}* is not defined.'

    return retval


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


def get_approval_form(acronym, definition, meaning, notes, team_domain, user_id, user_name, date_requested, approver,
                      ts, update):
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
                    }
                ]
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

            # Send approval request
            modal = get_approval_form(acronym, definition, meaning, notes, team_domain, user_id, user_name_capitalized,
                                      date_requested, approver, None, False)

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


def notify_approval_response(acronym, approved, requester_id):
    print("Sending approval response...")

    if approved == True:
        message = f"Your submission for *{acronym}* was approved. Thanks for contributing!"
    else:
        message = f"Sorry, your submission for *{acronym}* was denied."

    body = {
        "channel": requester_id,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": message
                }
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
                            "text": f"*Thanks for contributing!*\n We have received your submission for *{acronym}*.\nNow it's pending approval."
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
                            "text": "The acronym for" + acronym + "is already defined."
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

    # Obtain required data
    acronym, definition, meaning, notes, team_domain, user_name, user_id = get_data_from_payload(payload)

    # Check which action was sent
    if actions is not None:
        # Obtain the date when acronym was requested
        print("Submitted: " + str(payload['message']['attachments'][0]['blocks'][1]['fields'][1]['text']))
        date_requested = payload['message']['attachments'][0]['blocks'][1]['fields'][1]['text'][18:]

        # Obtain the channel id i.e approver id
        channel = payload['channel']['id']

        # Obtain the message's timestamp to be updated
        message_ts = payload['message']['ts']

        # Obtain the appover id
        approver_id = payload['user']['id']

        value = actions[0]['value']

        if value == 'Approve':
            update_approval_form(acronym, definition, meaning, notes, team_domain, user_id, user_name, date_requested,
                                 channel, True, message_ts)
            return persistDecision(acronym, approver_id, True)
        if value == 'Deny':
            update_approval_form(acronym, definition, meaning, notes, team_domain, user_id, user_name, date_requested,
                                 channel, False, message_ts)
            return persistDecision(acronym, approver_id, False)

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


def update_form_closed(item):
    try:
        approvers_message_list = item['ApproverMessages']
        acronym = item['Acronym']
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
                                    "text": f"*The request for *{acronym}* is completed.*\n Thanks for contributing, the voting is closed!"
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


def update_approval_form(acronym, definition, meaning, notes, team_domain, user_id, user_name, date_requested, channel,
                         decision, message_ts):
    if meaning is "":
        meaning = "-"

    # Update approval message form
    modal = get_approval_form(acronym, definition, meaning, notes, team_domain, user_id, user_name, date_requested,
                              channel, message_ts, True)

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + OAUTH_TOKEN
    }
    print("headers: " + str(headers))

    response = http.request('POST', 'https://slack.com/api/chat.update', body=json.dumps(modal), headers=headers)
    print("response: " + str(response.status) + " " + str(response.data))


def persistDecision(acronym, userId, decision):
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
        update_form_closed(item)
    else:
        if not decision and len(reviewers) >= REVIEWERS_MAX:
            response = table.delete_item(
                Key={
                    'Acronym': acronym
                }
            )
            update_form_closed(item)
        else:
            response = update_reviewers(acronym, reviewers, decisionStr)

    if len(reviewers) >= REVIEWERS_MAX:
        notify_approval_response(acronym, decision, requester_id)

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
    slack_signing_secret = os.environ['SLACK_SIGNING_SECRET']
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

