import csv
import os

import boto3

# Get the service resource.
dynamodb = boto3.resource("dynamodb")
table_name = os.environ["TABLE_NAME"]
table = dynamodb.Table(table_name)

stage = os.environ["STAGE"].lower()

s3 = boto3.client("s3")


def lambda_handler(event, context):

    bucket = "explainbot-initial-data-" + stage
    file_key = "acronyms.csv"

    csvfile = s3.get_object(Bucket=bucket, Key=file_key)
    csvcontent = csvfile["Body"].read().decode("utf-8").split("\n")

    dataset = csv.DictReader(csvcontent)

    for row in dataset:
        table.put_item(
            Item={
                "Acronym": row["Acronym"],
                "Definition": row["Definition"],
                "Meaning": row["Meaning"],
                "Notes": row["Notes"],
            }
        )
