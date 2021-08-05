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

# Define constants
INITIAL_DATA_FILE = 'acronyms.csv'

class ExplainBotLambdaStack(cdk.Stack):

    explain_bot_lambda: _lambda.Function
    add_meaning_lambda: _lambda.Function

    def __init__(self, scope: cdk.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Define Lambda function
        slack_signing_secret=cdk.SecretValue.secrets_manager('SLACK_SIGNING_SECRET').to_string()
        oauth_token=cdk.SecretValue.secrets_manager('OAUTH_TOKEN').to_string()
        approvers=cdk.SecretValue.secrets_manager('APPROVERS').to_string()

        self.explain_bot_lambda = _lambda.Function(
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
        
        self.add_meaning_lambda = _lambda.Function(
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


class ExplainBotApiStack(cdk.Stack):
    def __init__(
            self, 
            scope: cdk.Construct, 
            construct_id: str, 
            explain_bot_lambda: _lambda.Function,
            add_meaning_lambda: _lambda.Function,
            **kwargs
            ) -> None:
        super().__init__(scope, construct_id, **kwargs)

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


def get_initial_data(file):

    with open(file) as csvfile:
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

def fill_initial_data(self, begin: int, end: int, data, table_name: str, policy: _resources.AwsCustomResourcePolicy ):

    for i in range(begin, end):
        acronym_resource = _resources.AwsCustomResource (
            self, 'initDBResource' + str(i), 
            policy=policy,
            on_create=_resources.AwsSdkCall(
                service='DynamoDB',
                action='putItem',
                parameters={ 'TableName': table_name, 'Item': data[i] },
                physical_resource_id=_resources.PhysicalResourceId.of('initDBData' + str(i)),
            ),
        )

class ExplainBotDatabaseStack(cdk.Stack):

    table_name: str
    policy: _resources.AwsCustomResourcePolicy

    def __init__(
            self, 
            scope: cdk.Construct, 
            construct_id: str,
            explain_bot_lambda: _lambda.Function,
            add_meaning_lambda: _lambda.Function,
            **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

                # Define dynamoDb table
        acronym_table = _dynamo.Table(
            self, id="explainAcronymTable",
            table_name="explainacronymtable",
            partition_key=_dynamo.Attribute(name="Acronym", type=_dynamo.AttributeType.STRING),
            removal_policy=cdk.RemovalPolicy.DESTROY
        )

        self.table_name = acronym_table.table_name

        # Add the table name as an environment variable
        explain_bot_lambda.add_environment("TABLE_NAME", acronym_table.table_name)
        add_meaning_lambda.add_environment("TABLE_NAME", acronym_table.table_name)

        # Give lambdas the ability to read and write to the database table
        acronym_table.grant_full_access(explain_bot_lambda)
        acronym_table.grant_full_access(add_meaning_lambda)

        # Set up the custom resource policy so we can populate the database upon creation
        self.policy = _resources.AwsCustomResourcePolicy.from_sdk_calls(
            resources=['*']
        )

        # Get the data to be added to the new table
        data = get_initial_data(INITIAL_DATA_FILE)
        # Create and execute custom resources to add data to the new table
        fill_initial_data(self, 0, len(data)//2, data, acronym_table.table_name, self.policy)

class ExplainBotFillNextDatabaseStack(cdk.Stack):
    def __init__(
            self, 
            scope: cdk.Construct, 
            construct_id: str, 
            table_name: str,
            policy: _resources.AwsCustomResourcePolicy,
            **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        data = get_initial_data(INITIAL_DATA_FILE)
        fill_initial_data(self, len(data)//2, len(data), data, table_name, policy)


class ExplainSlackBotStack(cdk.Stack):

    def __init__(self, scope: cdk.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        lambda_stack = ExplainBotLambdaStack(self, "LambdaStack")
        api_stack = ExplainBotApiStack(
            self, "ApiStack", 
            explain_bot_lambda=lambda_stack.explain_bot_lambda, 
            add_meaning_lambda=lambda_stack.add_meaning_lambda
            )
        self.url_output = api_stack.url_output

        database_stack = ExplainBotDatabaseStack(
            self, "DatabaseStack",
            explain_bot_lambda=lambda_stack.explain_bot_lambda, 
            add_meaning_lambda=lambda_stack.add_meaning_lambda
        )

        ExplainBotFillNextDatabaseStack(
            self, "FillNextDatabase",
            table_name = database_stack.table_name,
            policy =  database_stack.policy
        )





