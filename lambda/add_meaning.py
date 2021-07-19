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

def notify_pending_approval(user_name, acronym):
    """Sends a direct message to notify acronym is pending approvals"""
    body = {
        "channel": user_name,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": ":thankyou: We have received your submission for '" + acronym + "'. Now it's pending approval."
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
    
    user_id = payload['user']['id']
    print("user_id: " + user_id)

    user_name = [word.capitalize() for word in payload['user']['name'].split(".") ]
    print("user_name: " + " ".join(user_name))

    # Define acronym (persist in DB) and send approval request to approvers
    return_url = payload['response_urls'][0]['response_url']
    
    status_code = define(acronym,definition,meaning,notes,return_url)
    notify_pending_approval(user_name, acronym)
    create_approval_request(acronym,definition,meaning,team_domain,user_id,user_name)
    
    return {
        "statusCode" : status_code
    }

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