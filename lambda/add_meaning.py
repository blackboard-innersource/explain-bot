import base64
import hashlib
import hmac
import json
import os
import re
from datetime import date, datetime
from functools import lru_cache
from urllib import parse as urlparse

import boto3
import urllib3
from boto3.dynamodb.conditions import Key
from explain import attachment_color, explain

# Get the service resource.
dynamodb = boto3.resource("dynamodb")

# set environment variable
TABLE_NAME = os.environ["TABLE_NAME"]
DENIED_TABLE_NAME = os.environ["TABLE_DENIED_NAME"]
stage = os.environ["STAGE"].lower()

APPROVERS_STR = "Approvers"
DENIERS_STR = "Deniers"
REQUESTER_STR = "Requester"
APPROVAL_STR = "Approval"
APPROVAL_STATUS_PENDING = "pending"
APPROVAL_STATUS_APPROVED = "approved"
REQUEST_TIMESTAMP = "RequestTimestamp"
REVIEWERS_MAX = 3

table = dynamodb.Table(TABLE_NAME)
denied_table = dynamodb.Table(DENIED_TABLE_NAME)
http = urllib3.PoolManager()

ssm = boto3.client("ssm", region_name="us-east-2")

sss = ssm.get_parameter(
    Name="/explainbot/parameters/" + stage + "/slack_signing_secret",
    WithDecryption=True,
)
slack_signing_secret = sss["Parameter"]["Value"]

oauth = ssm.get_parameter(
    Name="/explainbot/parameters/" + stage + "/oauth_token", WithDecryption=True
)
OAUTH_TOKEN = oauth["Parameter"]["Value"]

approver_str = ssm.get_parameter(Name="/explainbot/parameters/" + stage + "/approvers")
APPROVERS = approver_str["Parameter"]["Value"].split(",")


def get_body(event):
    return base64.b64decode(str(event["body"])).decode("ascii")


@lru_cache(maxsize=60)
def define(
    acronym, definition, meaning, notes, response_url, user_id, user_name, team_domain
):
    results = table.put_item(
        Item={
            "Acronym": acronym,
            "Definition": definition,
            "Meaning": meaning,
            "Notes": notes,
            REQUESTER_STR: user_id,
            "RequesterName": user_name,
            APPROVAL_STR: APPROVAL_STATUS_PENDING,
            REQUEST_TIMESTAMP: int(datetime.utcnow().timestamp()),
            "TeamDomain": team_domain,
        }
    )

    print(str(results))

    result = results["ResponseMetadata"]["HTTPStatusCode"]
    print("Result: " + str(result))

    headers = {
        "Content-Type": "application/plain-text",  # TODO: Not using json
        "Authorization": "Bearer " + OAUTH_TOKEN,
    }
    print("headers: " + str(headers))

    if result != 200:
        body = {
            "response_type": "in_channel",
            "text": "Error (" + str(result) + ") defining " + acronym,
        }
        print("body: " + str(body))

        response = http.request(
            "POST", response_url, body=json.dumps(body), headers=headers
        )
        print("response: " + str(response.status) + " " + str(response.data))

    return result


def get_approval_form(
    acronym,
    definition,
    meaning,
    notes,
    team_domain,
    user_id,
    user_name,
    date_requested,
    approver,
    ts,
    update,
    feedback,
):
    if feedback is None or feedback == "":
        feedback = "There is no feedback yet"
    return {
        "attachments": [
            {
                "color": attachment_color,
                "blocks": [
                    add_simple_section(
                        "*You have a new request:*\n<https://"
                        + team_domain
                        + ".slack.com/team/"
                        + user_id
                        + "|"
                        + user_name
                        + " - New acronym request>",
                    ),
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": "*Acronym:*\n " + acronym},
                            {
                                "type": "mrkdwn",
                                "text": "*When:*\nSubmitted " + date_requested,
                            },
                            {"type": "mrkdwn", "text": "*Definition:*\n" + definition},
                            {"type": "mrkdwn", "text": "*Details:*\n" + meaning},
                        ],
                    },
                    add_simple_section("*Notes:*\n" + notes),
                    {"type": "divider"},
                    {
                        "type": "input",
                        "block_id": "feedback_block",
                        "optional": True,
                        "element": {
                            "type": "plain_text_input",
                            "action_id": "plain_text_feedback-action",
                            "multiline": False,
                            "placeholder": {
                                "type": "plain_text",
                                "text": "Provide some feedback to the user",
                            },
                        },
                        "label": {"type": "plain_text", "text": "Feedback:"},
                    }
                    if update is False
                    else add_simple_section("*Feedback from reviewers:*\n" + feedback),
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "Approve"},
                                "style": "primary",
                                "value": "Approve",
                            },
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "Deny"},
                                "style": "danger",
                                "value": "Deny",
                            },
                        ],
                    }
                    if update is False
                    else add_simple_section(
                        ":white_check_mark: *Your choice has been saved successfully!*\n"
                    ),
                ],
            }
        ],
        "channel": approver,
        "ts": ts,
    }


def create_approval_request(
    acronym, definition, meaning, notes, team_domain, user_id, user_name, approvers
):
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
            modal = get_approval_form(
                acronym,
                definition,
                meaning,
                notes,
                team_domain,
                user_id,
                user_name_capitalized,
                date_requested,
                approver,
                ts,
                update,
                feedback,
            )
            response = http_request("https://slack.com/api/chat.postMessage", modal)

            data = json.loads(response.data.decode("utf-8"))

            if data.get("ok"):
                message_data = {
                    "approver": approver,
                    "channel": data.get("channel"),
                    "ts": data.get("ts"),
                }
                approver_messages.append(message_data)

        else:
            print("Skip approver due to approver sent acronym request")

    table.update_item(
        Key={"Acronym": acronym},
        UpdateExpression="set ApproverMessages=:a",
        ExpressionAttributeValues={
            ":a": approver_messages,
        },
        ReturnValues="UPDATED_NEW",
    )


def build_feedback_messages_list(approver_messages, team_domain):
    feedback_msgs = ""
    for feedback in approver_messages:
        user_name = [
            word.capitalize() for word in feedback["approverUsername"].split(".")
        ]
        user_name_capitalized = " ".join(user_name)
        print("ApproverFeedbackMessages: ", feedback["message"])
        feedback_msgs += (
            "• *<https://"
            + team_domain
            + ".slack.com/team/"
            + feedback["approverId"]
            + "|"
            + user_name_capitalized
            + ":>* "
            + feedback["message"]
            + "\n"
        )
    return feedback_msgs


def notify_approval_response(
    acronym, approved, requester_id, team_domain, feedback_msgs
):
    print("Sending approval response...")
    blocks = []
    feedback = build_feedback_messages_list(feedback_msgs, team_domain)

    if approved is True:
        message = (
            f"Your submission for *{acronym}* was approved. Thanks for contributing!"
        )
    else:
        message = f"Sorry, your submission for *{acronym}* has not been approved at this time."

    blocks = [
        add_simple_section(message),
        add_simple_section(
            "*Feedback from approvers:*\n"
            + (
                feedback
                if feedback is not None and feedback != ""
                else "There is no feedback"
            ),
        ),
    ]

    body = {
        "channel": requester_id,
        "attachments": [{"color": attachment_color, "blocks": blocks}],
    }
    http_request("https://slack.com/api/chat.postMessage", body)


def notify_pending_approval(user_id, acronym):
    print("Sending pending approval notification...")
    body = {
        "channel": user_id,
        "attachments": [
            {
                "color": attachment_color,
                "blocks": [
                    add_simple_section(
                        f"*Submission successful!*\n Your submission for *{acronym}* has been received and is being reviewed."
                    ),
                ],
            }
        ],
    }
    http_request("https://slack.com/api/chat.postMessage", body)


def notify_invalid_acronym(user_id, acronym):
    print("Sending invalid acronym notification...")
    body = {
        "channel": user_id,
        "attachments": [
            {
                "color": attachment_color,
                "blocks": [
                    add_simple_section(
                        f"*Invalid request:* The acronym {acronym} is already defined."
                    ),
                ],
            }
        ],
    }
    http_request("https://slack.com/api/chat.postMessage", body)


def delete_message(response_url):
    body = {"delete_original": "true"}
    headers = {"Content-Type": "application/json"}  # TODO: Not using authorization
    print("headers: " + str(headers))

    try:
        response = http.request(
            "POST", response_url, body=json.dumps(body), headers=headers
        )
        print("delete response: " + str(response.status) + " " + str(response.data))
    except:
        print("Error deleting message to post in channel")


def post_message_in_channel(channel, acronym):
    body = {
        "channel": channel,
        "attachments": [{"color": attachment_color, "blocks": explain(acronym, False)}],
    }
    response = http_request("https://slack.com/api/chat.postMessage", body)
    return response


def get_data_from_payload(payload):
    acronym = ""
    definition = ""
    meaning = ""
    notes = ""
    team_domain = ""
    user_name = ""
    user_id = ""

    actions = payload.get("actions")

    if actions is None:
        # Obtain the data from submit payload structure
        acronym = payload["view"]["state"]["values"]["acronym_block"]["acronym_input"][
            "value"
        ]
        definition = payload["view"]["state"]["values"]["definition_block"][
            "definition_input"
        ]["value"]
        meaning = payload["view"]["state"]["values"]["meaning_block"]["meaning_input"][
            "value"
        ]
        notes = payload["view"]["state"]["values"]["notes_block"]["notes_input"][
            "value"
        ]
        team_domain = payload["team"]["domain"]
        user_name = [word.capitalize() for word in payload["user"]["name"].split(".")]
        user_id = payload["user"]["id"]
    else:
        # Obtain the data from approve/deny payload structure
        acronym = payload["message"]["attachments"][0]["blocks"][1]["fields"][0][
            "text"
        ][12:]
        definition = payload["message"]["attachments"][0]["blocks"][1]["fields"][2][
            "text"
        ][14:]
        meaning = payload["message"]["attachments"][0]["blocks"][1]["fields"][3][
            "text"
        ][11:]
        notes = payload["message"]["attachments"][0]["blocks"][2]["text"]["text"][9:]
        team_domain = payload["team"]["domain"]
        user_name_block = payload["message"]["attachments"][0]["blocks"][0]["text"][
            "text"
        ]
        user_name = user_name_block[
            user_name_block.index("|")
            + 1 : user_name_block.index(" - New acronym request")
        ]
        user_id = user_name_block[
            user_name_block.index("/team/") + 6 : user_name_block.index("|")
        ]

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
    print("user id:" + user_id)

    return acronym, definition, meaning, notes, team_domain, user_name, user_id


def update_approvers_feedback_section(
    acronym,
    definition,
    meaning,
    notes,
    team_domain,
    user_id,
    user_name,
    date_requested,
    approver_messages,
):
    feedback = build_feedback_messages_list(approver_messages, team_domain)

    result = table.query(KeyConditionExpression=Key("Acronym").eq(acronym))

    if len(result["Items"]) == 0:
        return {"statusCode": 404}

    item = result["Items"][0]
    approvers_message_list = item.get("ApproverMessages", [])

    for message in approvers_message_list:
        approver_channel = message["channel"]
        ts = message["ts"]

        approver_id = message["approver"]
        approvers = item.get("Approvers", [])
        deniers = item.get("Deniers", [])

        # 'update' is true for the approvers that already voted
        update = approver_id in approvers or approver_id in deniers

        modal = get_approval_form(
            acronym,
            definition,
            meaning,
            notes,
            team_domain,
            user_id,
            user_name,
            date_requested,
            approver_channel,
            ts,
            update,
            feedback,
        )
        http_request("https://slack.com/api/chat.update", modal)

    return {"statusCode": 200}


def lambda_handler(event, context):
    print("add_meaning: " + str(event))

    if check_hash(event) is False:
        print("Signature check failed")
        print("event: " + str(event))
        return

    body = dict(
        urlparse.parse_qsl(get_body(event))
    )  # data comes b64 and also urlencoded name=value& pairs
    print("Body: " + str(body))

    payload = json.loads(body.get("payload", "no-payload"))
    print("Payload: " + str(payload))

    actions = payload.get("actions")
    print("Actions: " + str(actions))

    event_type = payload.get("type")
    print("Event type: " + str(event_type))

    # Check which action was sent
    if event_type == "block_actions" and actions is not None:
        # Obtain the channel id
        channel = payload["channel"]["id"]

        action_id = actions[0]["action_id"]

        if action_id == "post_in_channel":
            response_url = payload["response_url"]
            acronym = str(actions[0]["value"])
            post_response = post_message_in_channel(channel, acronym)
            data = json.loads(post_response.data.decode("utf-8"))
            if data.get("ok"):
                return delete_message(response_url)
            else:
                print("Not able to post message in channel")
                return

        # Obtain required data
        (
            acronym,
            definition,
            meaning,
            notes,
            team_domain,
            user_name,
            user_id,
        ) = get_data_from_payload(payload)

        value = actions[0]["value"]

        # Obtain the date when acronym was requested
        print(
            "Submitted: "
            + str(
                payload["message"]["attachments"][0]["blocks"][1]["fields"][1]["text"]
            )
        )
        date_requested = payload["message"]["attachments"][0]["blocks"][1]["fields"][1][
            "text"
        ][18:]

        # Obtain the message's timestamp to be updated
        # message_ts = payload["message"]["ts"]

        # Obtain the appover id
        approver_id = payload["user"]["id"]

        if value == "Approve":
            approver_messages = persist_feedback_from_approver(payload)
            persistDecision(acronym, approver_id, True, team_domain)
            return update_approvers_feedback_section(
                acronym,
                definition,
                meaning,
                notes,
                team_domain,
                user_id,
                user_name,
                date_requested,
                approver_messages,
            )
        if value == "Deny":
            # trigger_id = payload["trigger_id"]
            approver_messages = persist_feedback_from_approver(payload)
            persistDecision(acronym, approver_id, False, team_domain)
            return update_approvers_feedback_section(
                acronym,
                definition,
                meaning,
                notes,
                team_domain,
                user_id,
                user_name,
                date_requested,
                approver_messages,
            )

    status_code = "200"
    if event_type == "view_submission":
        (
            acronym,
            definition,
            meaning,
            notes,
            team_domain,
            user_name,
            user_id,
        ) = get_data_from_payload(payload)

        # Define acronym (persist in DB) and send approval request to approvers
        return_url = payload["response_urls"][0]["response_url"]

        user_name_capitalized = " ".join(user_name)
        status_code = "200"
        results = table.query(KeyConditionExpression=Key("Acronym").eq(acronym))

        if len(results["Items"]) == 0:
            status_code = define(
                acronym,
                definition,
                meaning,
                notes,
                return_url,
                user_id,
                user_name_capitalized,
                team_domain,
            )
            create_approval_request(
                acronym,
                definition,
                meaning,
                notes,
                team_domain,
                user_id,
                user_name,
                APPROVERS,
            )
            notify_pending_approval(user_id, acronym)
        else:
            notify_invalid_acronym(user_id, acronym)

    return {"statusCode": status_code}


def persist_feedback_from_approver(payload):
    feedback = payload["state"]["values"]["feedback_block"][
        "plain_text_feedback-action"
    ]["value"]
    print("Feedback: ", feedback)

    if feedback is None or feedback == "":
        return []

    acronym = payload["message"]["attachments"][0]["blocks"][1]["fields"][0]["text"][
        12:
    ]
    print("Acronym: ", acronym)

    result = table.query(KeyConditionExpression=Key("Acronym").eq(acronym))

    if len(result["Items"]) == 0:
        return {"statusCode": 404}

    item = result["Items"][0]
    approver_messages = item.get("ApproverFeedbackMessages", [])

    message_data = {
        "approverId": payload["user"]["id"],
        "approverUsername": payload["user"]["username"],
        "message": feedback,
    }
    approver_messages.append(message_data)

    table.update_item(
        Key={"Acronym": acronym},
        UpdateExpression="set ApproverFeedbackMessages=:a",
        ExpressionAttributeValues={
            ":a": approver_messages,
        },
        ReturnValues="UPDATED_NEW",
    )

    return approver_messages


def update_form_closed(item, team_domain, decision):
    try:
        approvers_message_list = item["ApproverMessages"]
        acronym = item["Acronym"]
        approver_messages = item.get("ApproverFeedbackMessages", [])
        feedback = build_feedback_messages_list(approver_messages, team_domain)
        approval_message = (
            f"{acronym} has been approved."
            if decision is True
            else f"{acronym} has not been approved."
        )
        for element in approvers_message_list:
            modal = {
                "attachments": [
                    {
                        "color": attachment_color,
                        "blocks": [
                            add_simple_section(
                                f"*The request for {acronym} is completed.*\n{approval_message}\nThanks for contributing, the voting is closed!"
                            ),
                            add_simple_section(
                                "*Feedback from approvers:*\n"
                                + (
                                    feedback
                                    if feedback is not None and feedback != ""
                                    else "There is no feedback"
                                )
                            ),
                        ],
                    }
                ],
                "channel": element["channel"],
                "ts": element["ts"],
            }
            http_request("https://slack.com/api/chat.update", modal)
    except:
        print("Error in update_form_closed")


def update_approval_form(
    acronym,
    definition,
    meaning,
    notes,
    team_domain,
    user_id,
    user_name,
    date_requested,
    channel,
    message_ts,
    feedback_msgs,
):
    update = True
    feedback = build_feedback_messages_list(feedback_msgs, team_domain)

    if meaning == "":
        meaning = "-"

    if notes == "":
        notes = "-"

    # Update approval message form
    modal = get_approval_form(
        acronym,
        definition,
        meaning,
        notes,
        team_domain,
        user_id,
        user_name,
        date_requested,
        channel,
        message_ts,
        update,
        feedback,
    )
    http_request("https://slack.com/api/chat.update", modal)


def persistDecision(acronym, userId, decision, team_domain):
    result = table.query(KeyConditionExpression=Key("Acronym").eq(acronym))

    if len(result["Items"]) == 0:
        return {"statusCode": 404}

    item = result["Items"][0]

    decisionStr = APPROVERS_STR if decision else DENIERS_STR
    reviewers = item.get(decisionStr, [])
    approval_status = item.get(APPROVAL_STR)
    requester_id = item.get(REQUESTER_STR)
    feedback_msgs = item.get("ApproverFeedbackMessages", [])

    # TODO: Ignore approval action
    if (
        checkAlreadyReviewed(result, userId)
        or approval_status == APPROVAL_STATUS_APPROVED
    ):
        return {"statusCode": 400}

    reviewers.append(userId)

    if decision and len(reviewers) >= REVIEWERS_MAX:
        table.update_item(
            Key={"Acronym": acronym},
            UpdateExpression=f"set {APPROVAL_STR}=:d",
            ExpressionAttributeValues={
                ":d": APPROVAL_STATUS_APPROVED,
            },
            ReturnValues="UPDATED_NEW",
        )
        response = update_reviewers(acronym, reviewers, decisionStr)
        update_form_closed(item, team_domain, decision)
    else:
        if not decision and len(reviewers) >= REVIEWERS_MAX:
            result = table.query(KeyConditionExpression=Key("Acronym").eq(acronym))

            if len(result["Items"]) == 0:
                return {"statusCode": 404}

            item = result["Items"][0]
            results = denied_table.put_item(
                Item={
                    "Acronym": item.get("Acronym", ""),
                    "Deleted_at": str(datetime.utcnow().timestamp()),
                    "ApproverMessages": item.get("ApproverMessages", []),
                    "ApproverFeedbackMessages": item.get(
                        "ApproverFeedbackMessages", []
                    ),
                    "Definition": item.get("Definition", ""),
                    "Meaning": item.get("Meaning", ""),
                    "Notes": item.get("Notes", ""),
                    REQUESTER_STR: item.get("Requester", ""),
                    "RequesterName": item.get("RequesterName", ""),
                    APPROVAL_STR: item.get("Denied", "Denied"),
                    REQUEST_TIMESTAMP: item.get("RequestTimestamp", ""),
                    "TeamDomain": item.get("TeamDomain", ""),
                }
            )

            print(str(results))

            result = results["ResponseMetadata"]["HTTPStatusCode"]
            print("Result: " + str(result))

            response = table.delete_item(Key={"Acronym": acronym})
            update_form_closed(item, team_domain, decision)
        else:
            response = update_reviewers(acronym, reviewers, decisionStr)

    if len(reviewers) >= REVIEWERS_MAX:
        notify_approval_response(
            acronym, decision, requester_id, team_domain, feedback_msgs
        )

    return {"statusCode": response["ResponseMetadata"]["HTTPStatusCode"]}


def update_reviewers(acronym, reviewers, decisionStr):
    response = table.update_item(
        Key={"Acronym": acronym},
        UpdateExpression=f"set {decisionStr}=:d",
        ExpressionAttributeValues={
            ":d": reviewers,
        },
        ReturnValues="UPDATED_NEW",
    )
    return response


def checkAlreadyReviewed(result, userId):
    approvers = result["Items"][0].get(APPROVERS_STR, [])
    denyers = result["Items"][0].get(DENIERS_STR, [])
    return userId in approvers or userId in denyers


def check_hash(event):
    body = get_body(event)
    timestamp = event["headers"]["x-slack-request-timestamp"]
    sig_basestring = "v0:" + timestamp + ":" + body
    my_signature = (
        "v0="
        + hmac.new(
            bytes(slack_signing_secret, "UTF-8"),
            msg=bytes(sig_basestring, "UTF-8"),
            digestmod=hashlib.sha256,
        ).hexdigest()
    )
    print("Generated signature: " + my_signature)
    slack_signature = event["headers"]["x-slack-signature"]
    print("Slack signature: " + slack_signature)

    return hmac.compare_digest(my_signature, slack_signature)


def cleanup_acronym(acronym):
    return re.sub("[^0-9a-zA-Z]+", "", acronym.upper())


def add_simple_section(text):
    return {"type": "section", "text": {"type": "mrkdwn", "text": text}}


def http_request(url, body):
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + OAUTH_TOKEN,
    }
    # print("headers: " + str(headers))
    response = http.request(
        "POST",
        url,
        body=json.dumps(body),
        headers=headers,
    )
    print("response: " + str(response.status) + " " + str(response.data))
    return response
