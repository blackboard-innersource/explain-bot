import boto3
import os
import csv

# Get the service resource.
dynamodb = boto3.resource('dynamodb')
table_name = os.environ['TABLE_NAME']
table = dynamodb.Table(table_name)

def lambda_handler(event, context):

    with open('acronyms.csv') as csvfile:
        dataset = csv.DictReader(csvfile)

        for row in dataset:
            results = table.put_item(
                Item={
                    'Acronym': row['Acronym'],
                    'Definition': row['Definition'],
                    'Meaning': row['Meaning'],
                    'Notes': row['Notes']
                }
            )