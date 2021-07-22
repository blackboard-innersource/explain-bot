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
from datetime import date

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
        
        retval = item['Acronym'] + " - " + item['Definition'] + "\n---\n*Meaning*: " + item['Meaning'] +  "\n*Notes*: " + item['Notes']
        
    except:
        retval = f'{acronym} is not defined.'

    return retval
    
@lru_cache(maxsize=60)
def define(acronym, definition, meaning, notes, response_url, user_id):
    
    results = table.put_item(
        Item={
            'Acronym': acronym,
            'Definition': definition,
            'Meaning': meaning,
            'Notes': notes,
            REQUESTER_STR: user_id,
            APPROVAL_STR: APPROVAL_STATUS_PENDING
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
    
    
    if result == 200:
        
        body={
            "response_type": "in_channel",
            "text": acronym + ' successfully defined.',
            "attachments": [
                {
                    "text": explain(acronym)
                }
            ]
        }
        print("body: " + str(body))
        
        response = http.request('POST', response_url, body=json.dumps(body), headers=headers)
        print("response: " + str(response.status) + " " + str(response.data))
    else:
        body={
            "response_type": "in_channel",
            "text": 'Error (' + str(result) + ') defining ' + acronym,
        }
        print("body: " + str(body))
        
        response = http.request('POST', response_url, body=json.dumps(body), headers=headers)
        print("response: " + str(response.status) + " " + str(response.data))

    return result

def create_approval_request(acronym, definition, meaning, team_domain, user_id, user_name):

    user_name_capitalized = " ".join(user_name)
    date_requested = date.today().strftime("%d/%m/%Y")

    if meaning is None:
        meaning = "-"

    for approver in APPROVERS:
        if approver != user_id:
            
            #Send approval request
            modal={
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*You have a new request:*\n<https://" + team_domain + ".slack.com/team/" + user_id + "|" + user_name_capitalized + " - New acronym request>"
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
                                "text": "*Meaning:*\n" + definition
                            },
                            {
                                "type": "mrkdwn",
                                "text": "*Notes:*\n" + meaning
                            }
                        ]
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
                    }
                ],
                "channel": approver
            }

            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + OAUTH_TOKEN
            }
            print("headers: " + str(headers))
            
            response = http.request('POST', 'https://slack.com/api/chat.postMessage', body=json.dumps(modal), headers=headers)
            print("response: " + str(response.status) + " " + str(response.data))

        else:
            print("Skip approver due to approver sent acronym request")


def check_approval_status(acronym):
    result = table.query(KeyConditionExpression=Key("Acronym").eq(acronym))
    item = result['Items'][0]

    approvers = item.get(APPROVERS_STR, [])
    deniers = item.get(DENIERS_STR, [])
    requester_id = item.get(REQUESTER_STR)

    if len(approvers) >= REVIEWERS_MAX:
        approved = True
        # Update approval status
        response = table.update_item(
            Key={
                'Acronym': acronym
            },
            UpdateExpression=f"set {APPROVAL_STR}=:d",
            ExpressionAttributeValues={
                ':d': APPROVAL_STATUS_APPROVED,
            },
            ReturnValues="UPDATED_NEW"
        )
        print("response: " + str(response))
    else:
        if len(deniers) >= REVIEWERS_MAX:
            approved = False
            # TODO: Remove item from DB
        else:
            return

    notify_approval_response(acronym,approved,requester_id)


def notify_approval_response(acronym, approved, requester_id):
    print("Sending approval response...")

    if approved == True:
        message = "Your submission for *" + acronym + "* was approved. Thanks for contributing!"
    else:
        message = "Sorry, your submission for *" + acronym + "* was denied."

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


def lambda_handler(event, context):
    print("add_meaning: " + str(event))
    
    if check_hash(event) == False:
        print('Signature check failed')
        print('event: ' + str(event))
        return
    
    body = dict(urlparse.parse_qsl(get_body(event)))  # data comes b64 and also urlencoded name=value& pairs
    print("Body: " + str(body))
    
    payload = json.loads(body.get('payload',"no-payload"))
    print("Payload: " + str(payload) )

    user_id = payload['user']['id']
    print('user id:' + user_id)

    actions = payload.get('actions')
    if actions is not None:
        # Obtain acronim from payload structure, if a new action is added
        # this should be refactored to avoid an error
        acronym = payload['message']['blocks'][1]['fields'][0]['text'][12:]
        value = actions[0]['value']
        if value == 'Approve':
            return persistDecision(acronym, user_id, True)
        if value == 'Deny':
            return persistDecision(acronym, user_id, False)

    # Obtain required data
    acronym = payload['view']['state']['values']['acronym_block']['acronym_input']['value']
    print("acronym: " + acronym)

    definition = payload['view']['state']['values']['definition_block']['definition_input']['value']
    print("definition: " + definition)
    
    meaning = payload['view']['state']['values']['meaning_block']['meaning_input']['value']
        
    if meaning is not None:
        print("meaning: " + meaning)
    else:
        print("no meaning")
        meaning = ""
    
    notes = payload['view']['state']['values']['notes_block']['notes_input']['value']
    
    if notes is not None:
        print("notes: " + notes)
    else:
        print("no notes")
        notes = ""

    team_domain = payload['team']['domain']
    print("team_domain: " + team_domain)

    user_name = [word.capitalize() for word in payload['user']['name'].split(".") ]
    print("user_name: " + " ".join(user_name))

    # Define acronym (persist in DB) and send approval request to approvers
    return_url = payload['response_urls'][0]['response_url']
    
    status_code = define(acronym,definition,meaning,notes,return_url,user_id)
    create_approval_request(acronym,definition,meaning,team_domain,user_id,user_name)
    
    return {
        "statusCode" : status_code
    }

def persistDecision(acronym, userId, decision):
    result = table.query(KeyConditionExpression=Key("Acronym").eq(acronym))
    
    decisionStr = APPROVERS_STR if decision else DENIERS_STR
    reviewers = result['Items'][0].get(decisionStr, [])
    approval_status = result['Items'][0].get(APPROVAL_STR)

    # TODO: Ignore approval action
    if checkAlreadyReviewed(result, userId) or approval_status == APPROVAL_STATUS_APPROVED:
        return {"statusCode": 400}
    
    reviewers.append(userId)

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

    if len(reviewers) >= REVIEWERS_MAX:
        check_approval_status(acronym)

    return {
        "statusCode" : response['ResponseMetadata']['HTTPStatusCode']
    }

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
