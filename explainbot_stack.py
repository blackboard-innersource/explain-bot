from aws_cdk import (
    core as cdk, 
    aws_lambda as _lambda, 
    aws_apigateway as _apigw, 
    aws_apigatewayv2 as _apigw2, 
    aws_apigatewayv2_integrations as _a2int,
    aws_dynamodb as _dynamo,
    custom_resources as _resources,
)

import csv

class ExplainSlackBotStack(cdk.Stack):

    def get_initial_data(self):

        with open('acronyms.csv') as csvfile:
            dataset = csv.DictReader(csvfile)
        
            data = []

            for row in dataset:
                data.append({
                    'Acronym': { 'S': row['Acronym'] },
                    'Definition': { 'S': row['Definition'] },
                    'Meaning': { 'S': row['Meaning'] },
                    'Notes': { 'S': row['Notes'] }
                })
        
        return data

    def __init__(self, scope: cdk.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Define Lambda function
        slack_signing_secret=cdk.SecretValue.secrets_manager('SLACK_SIGNING_SECRET').to_string()
        oauth_token=cdk.SecretValue.secrets_manager('OAUTH_TOKEN').to_string()
        approvers=cdk.SecretValue.secrets_manager('APPROVERS').to_string()

        explain_bot_lambda = _lambda.Function(
            self, "ExplainHandler",
            runtime=_lambda.Runtime.PYTHON_3_8,
            code=_lambda.Code.asset('lambda'),
            handler='explain.lambda_handler',
            environment = {
                'SLACK_SIGNING_SECRET': slack_signing_secret,
                'OAUTH_TOKEN' : oauth_token,
                'APPROVERS' : approvers
            }
        )
        
        add_meaning_lambda = _lambda.Function(
            self, "AddMeaningHandler",
            runtime=_lambda.Runtime.PYTHON_3_8,
            code=_lambda.Code.asset('lambda'),
            handler='add_meaning.lambda_handler',
            environment = {
                'SLACK_SIGNING_SECRET': slack_signing_secret,
                'OAUTH_TOKEN' : oauth_token,
                'APPROVERS' : approvers
            }
        )

        # Define API Gateway and HTTP API
        explain_bot_api = _apigw2.HttpApi(
            self, 'ExplainSlackBotApi'
        )

        self.url_output = cdk.CfnOutput(self, 'Url',
            value=explain_bot_api.url)

        # Set up proxy integrations
        explain_bot_entity_lambda_integration = _a2int.LambdaProxyIntegration(
            handler=explain_bot_lambda,
        )

        explain_bot_entity = explain_bot_api.add_routes(
            path="/", 
            methods=[_apigw2.HttpMethod.POST], 
            integration=explain_bot_entity_lambda_integration
        )

        add_meaning_lambda_integration = _a2int.LambdaProxyIntegration(
            handler=add_meaning_lambda,
        )

        add_meaning_entity = explain_bot_api.add_routes(
            path="/add_meaning", 
            methods=[_apigw2.HttpMethod.ANY], 
            integration=add_meaning_lambda_integration
        )


        # Define dynamoDb table
        acronym_table = _dynamo.Table(
            self, id="explainAcronymTable",
            table_name="explainacronymtable",
            partition_key=_dynamo.Attribute(name="Acronym", type=_dynamo.AttributeType.STRING),
            removal_policy=cdk.RemovalPolicy.DESTROY
        )

        # Add the table name as an environment variable
        explain_bot_lambda.add_environment("TABLE_NAME", acronym_table.table_name)
        add_meaning_lambda.add_environment("TABLE_NAME", acronym_table.table_name)

        # Give lambdas the ability to read and write to the database table
        acronym_table.grant_full_access(explain_bot_lambda)
        acronym_table.grant_full_access(add_meaning_lambda)

        # Set up the custom resource policy so we can populate the database upon creation
        policy = _resources.AwsCustomResourcePolicy.from_sdk_calls(
            resources=['*']
        )

        # Get the data to be added to the new table
        data = self.get_initial_data()

        # Create and execute custom resources to add data to the new table
        for i in range(0,len(data)):
            acronym_resource = _resources.AwsCustomResource (
                self, 'initDBResource' + str(i), 
                policy=policy,
                on_create=_resources.AwsSdkCall(
                    service='DynamoDB',
                    action='putItem',
                    parameters={ 'TableName': acronym_table.table_name, 'Item': data[i] },
                    physical_resource_id=_resources.PhysicalResourceId.of('initDBData' + str(i)),
                ),
            )
