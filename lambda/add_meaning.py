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
def define(acronym, definition, meaning, notes, response_url):
    
    results = table.put_item(
        Item={
            'Acronym': acronym,
            'Definition': definition,
            'Meaning': meaning,
            'Notes': notes
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

def get_approval_form(acronym, definition, meaning, team_domain, user_id, user_name, date_requested, approver, ts, update):
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
                    } if update == False else 
                    {
                        "type": "divider"
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": ":white_check_mark: *Your choice has been saved successfully!*"
                        }
                    }
                ],
                "channel": approver,
                "ts": ts if update == True else None
            }

def create_approval_request(acronym, definition, meaning, team_domain, user_id, user_name):

    user_name_capitalized = " ".join(user_name)
    date_requested = date.today().strftime("%d/%m/%Y")

    if meaning is "":
        meaning = "-"

    for approver in APPROVERS:
        if approver != user_id:

            #Send approval request
            modal = get_approval_form(acronym, definition, meaning, team_domain, user_id, user_name_capitalized, date_requested, approver, None, False)

            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + OAUTH_TOKEN
            }
            print("headers: " + str(headers))

            response = http.request('POST', 'https://slack.com/api/chat.postMessage', body=json.dumps(modal), headers=headers)
            print("response: " + str(response.status) + " " + str(response.data))

        else:
            print("Skip approver due to approver sent acronym request")


def notify_pending_approval(user_id, acronym):
    print("Sending pending approval notification...")
    body = {
        "channel": user_id,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Thanks for contributing! We have received your submission for '{acronym}'. Now it's pending approval."
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

def get_data_from_payload(payload,actions):
    acronym = ""
    definition = ""
    meaning = ""
    notes = ""
    team_domain = ""
    user_name = ""
    user_id = ""
    

    if actions is None:
        # Obtain the data from submit payload structure
        acronym = payload['view']['state']['values']['acronym_block']['acronym_input']['value']
        definition = payload['view']['state']['values']['definition_block']['definition_input']['value']
        meaning = payload['view']['state']['values']['meaning_block']['meaning_input']['value']
        notes = payload['view']['state']['values']['notes_block']['notes_input']['value']
        team_domain = payload['team']['domain']
        user_name = [word.capitalize() for word in payload['user']['name'].split(".") ]
        user_id = payload['user']['id']
    else:
        # Obtain the data from approve/deny payload structure
        acronym = payload['message']['blocks'][1]['fields'][0]['text'][12:]
        definition = payload['message']['blocks'][1]['fields'][2]['text'][13:]
        meaning = payload['message']['blocks'][1]['fields'][3]['text'][11:]
        team_domain = payload['team']['domain']
        user_name_block = payload['message']['blocks'][0]['text']['text']
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
    
    payload = json.loads(body.get('payload',"no-payload"))
    print("Payload: " + str(payload))

    actions = payload.get('actions')
    print("Actions: " + str(actions))

    # Obtain required data
    acronym, definition, meaning, notes, team_domain, user_name, user_id = get_data_from_payload(payload,actions)

    # Check which action was sent
    if actions is not None:
        # Obtain the date when acronym was requested
        date_requested = payload['message']['blocks'][1]['fields'][1]['text'][20:]

        # Obtain the channel id i.e approver id
        channel = payload['channel']['id']

        # Obtain the message's timestamp to be updated
        message_ts = payload['message']['ts']

        value = actions[0]['value']

        if value == 'Approve':
            update_approval_form(acronym,definition,meaning,team_domain,user_id,user_name,date_requested,channel,True,message_ts)
            return persistDecision(acronym, user_id, True)
        if value == 'Deny':
            update_approval_form(acronym,definition,meaning,team_domain,user_id,user_name,date_requested,channel,False,message_ts)
            return persistDecision(acronym, user_id, False)

    # Define acronym (persist in DB) and send approval request to approvers
    return_url = payload['response_urls'][0]['response_url']
    
    status_code = define(acronym,definition,meaning,notes,return_url)
    create_approval_request(acronym,definition,meaning,team_domain,user_id,user_name)
    notify_pending_approval(user_id,acronym)
    
    return {
        "statusCode" : status_code
    }

def update_approval_form(acronym, definition, meaning, team_domain, user_id, user_name, date_requested, channel, decision, message_ts):

    if meaning is "":
        meaning = "-"

    #Update approval message form
    modal = get_approval_form(acronym, definition, meaning, team_domain, user_id, user_name, date_requested, channel, message_ts, True)

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + OAUTH_TOKEN
    }
    print("headers: " + str(headers))

    response = http.request('POST', 'https://slack.com/api/chat.update', body=json.dumps(modal), headers=headers)
    print("response: " + str(response.status) + " " + str(response.data))
    

def persistDecision(acronym, userId, decision):
    result = table.query(KeyConditionExpression=Key("Acronym").eq(acronym))

    decisionStr = APPROVERS_STR if decision else DENIERS_STR

    if len(result['Items']) == 0:
        return {"statusCode": 404}
    
    reviewers = result['Items'][0].get(decisionStr, [])

    if checkAlreadyReviewed(result, userId):
        return {"statusCode": 400}

    reviewers.append(userId)

    if not decision and len(reviewers) >= 3:
        response = table.delete_item(
            Key={
                'Acronym': acronym
            }
        )
    else:
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