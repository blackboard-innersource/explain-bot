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


# Get the service resource.
dynamodb = boto3.resource('dynamodb')

# set environment variable
TABLE_NAME = os.environ['TABLE_NAME']
OAUTH_TOKEN = os.environ['OAUTH_TOKEN']

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

def create_modal(acronym,definition,user_name,channel_name,team_domain,trigger_id):

    results = table.query(KeyConditionExpression=Key("Acronym").eq(acronym))
    
    try:
        item = results['Items'][0]
        
        return item['Acronym'] + " is already defined as  " + item['Definition']
        
    except:
        
        initial_notes = 'Added by ' + user_name + ' from #' + channel_name + ' on ' + team_domain + '.slack.com'
        
        modal={
            "trigger_id": trigger_id,
            "view" : {
                "title": {
                    "type": "plain_text",
                    "text": "Define an Acronym"
                },
                "submit": {
                    "type": "plain_text",
                    "text": "Submit"
                },
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Define the acronym using the form below."
                        }
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "input",
                        "block_id": "acronym_block",
                        "element": {
                            "type": "plain_text_input",
                            "action_id": "acronym_input",
                            "multiline": False,
                            "initial_value": acronym
                        },
                        "label": {
                            "type": "plain_text",
                            "text": "Acronym"
                        }
                    },
                    {
                        "type": "input",
                        "block_id": "definition_block",
                        "element": {
                            "type": "plain_text_input",
                            "action_id": "definition_input",
                            "multiline": False,
                            "initial_value": definition
                        },
                        "label": {
                            "type": "plain_text",
                            "text": "Definition"
                        }
                    },
                    {
                        "type": "input",
                        "block_id": "meaning_block",
                        "optional": True,
                        "element": {
                            "type": "plain_text_input",
                            "action_id": "meaning_input",
                            "multiline": True,
                            "placeholder": {
                                "type": "plain_text",
                                "text": "What does this acronym actually mean?"
                            }
                        },
                        "label": {
                            "type": "plain_text",
                            "text": "Acronym Meaning"
                        }
                    },
                    {
                        "type": "input",
                        "block_id": "notes_block",
                        "optional": True,
                        "element": {
                            "type": "plain_text_input",
                            "action_id": "notes_input",
                            "multiline": True,
                            "initial_value": initial_notes
                        },
                        "label": {
                            "type": "plain_text",
                            "text": "Any notes to help make it clearer?"
                        }
                    },
                    {
                        "block_id": "response_url_block",
                        "type": "input",
                        "optional": True,
                        "label": {
                            "type": "plain_text",
                            "text": "Select a channel to post the result on",
                        },
                        "element": {
                            "action_id": "response_url_input",
                            "type": "conversations_select",
                            "default_to_current_conversation": True,
                            "response_url_enabled": True,
                        },
                    }
                ],
                "type": "modal"
            }
        }

        print("modal: " + str(modal))
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + OAUTH_TOKEN
        }

        print("headers: " + str(headers))
        
        response = http.request('POST', 'https://slack.com/api/views.open', body=json.dumps(modal), headers=headers)
        
        print("response: " + str(response.status) + " " + str(response.data))

    return f'Launching definition modal...'


def lambda_handler(event, context):
    print("explain")
    
    if check_hash(event) == False:
        print('Signature check failed')
        print('event: ' + str(event))
        return
    
    msg_map = dict(urlparse.parse_qsl(get_body(event)))  # data comes b64 and also urlencoded name=value& pairs
    print(str(msg_map))

    command = msg_map.get('command','err')  # will be /command name
    text = msg_map.get('text','').split(" ")
    user_name = msg_map.get('user_name','err')
    channel_name = msg_map.get('channel_name','err')
    team_domain = msg_map.get('team_domain','err')
    trigger_id = msg_map.get('trigger_id','err')

    if (len(text) >= 2):
        acronym = text[0].upper()
        definition = ""
        i=1
        for i in range(1,len(text)):
            definition += text[i]
            if i != len(text):
                definition += ' '
                
        response = create_modal(acronym,definition,user_name,channel_name,team_domain,trigger_id)

    elif (len(text) == 1):
        acronym = text[0].upper()
        
        response = explain(acronym)

    else:
        response = f'Usage: /define <acronym> or /define <acronym> <definition>'

    # logging
    print (str(command) + ' ' + str(text) +' -> '+ str(response) + ',original: '+ str(msg_map))

    return  {
        "response_type": "in_channel",
        "text": command + ' ' + " ".join(text),
        "attachments": [
            {
                "text": response
            }
        ]
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