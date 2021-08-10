from aws_cdk import (
    core as cdk, 
    aws_lambda as _lambda, 
    aws_apigateway as _apigw, 
    aws_apigatewayv2 as _apigw2, 
    aws_apigatewayv2_integrations as _a2int,
    aws_dynamodb as _dynamo,
    aws_logs as logs,
    aws_iam as iam,
    aws_events as _events,
    aws_events_targets as _events_targets,
    custom_resources as _resources,
)

class ExplainBotLambdaStack(cdk.Stack):

    explain_bot_lambda: _lambda.Function
    add_meaning_lambda: _lambda.Function
    approvers: str
    slack_signing_secret: str
    oauth_token: str

    def __init__(self, scope: cdk.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Define Lambda function
        self.slack_signing_secret=cdk.SecretValue.secrets_manager('SLACK_SIGNING_SECRET').to_string()
        self.oauth_token=cdk.SecretValue.secrets_manager('OAUTH_TOKEN').to_string()
        self.approvers=cdk.SecretValue.secrets_manager('APPROVERS').to_string()

        self.explain_bot_lambda = _lambda.Function(
            self, "ExplainHandler",
            runtime=_lambda.Runtime.PYTHON_3_8,
            code=_lambda.Code.asset('lambda'),
            handler='explain.lambda_handler',
            environment = {
                'SLACK_SIGNING_SECRET': self.slack_signing_secret,
                'OAUTH_TOKEN' : self.oauth_token,
                'APPROVERS' : self.approvers
            }
        )
        
        self.add_meaning_lambda = _lambda.Function(
            self, "AddMeaningHandler",
            runtime=_lambda.Runtime.PYTHON_3_8,
            code=_lambda.Code.asset('lambda'),
            handler='add_meaning.lambda_handler',
            environment = {
                'SLACK_SIGNING_SECRET': self.slack_signing_secret,
                'OAUTH_TOKEN' : self.oauth_token,
                'APPROVERS' : self.approvers
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

class ExplainBotDatabaseStack(cdk.Stack):

    table: _dynamo.Table

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

        acronym_table.add_global_secondary_index( 
           partition_key=Attribute(name='Approval', type=_dynamo.AttributeType.STRING),
           index_name='approval_index')

        self.table = acronym_table

        # Add the table name as an environment variable
        explain_bot_lambda.add_environment("TABLE_NAME", acronym_table.table_name)
        add_meaning_lambda.add_environment("TABLE_NAME", acronym_table.table_name)

        # Give lambdas the ability to read and write to the database table
        acronym_table.grant_full_access(explain_bot_lambda)
        acronym_table.grant_full_access(add_meaning_lambda)

class ExplainBotInitialDataStack(cdk.Stack):
    def __init__(
            self, 
            scope: cdk.Construct, 
            construct_id: str, 
            table: _dynamo.Table,
            **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        initial_data_role = iam.Role(
            self, "InitialDataRole",
            assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole")]
        )

        initial_data_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name('AWSLambdaInvocation-DynamoDB'))
        initial_data_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name('AmazonDynamoDBFullAccess'))

        on_event = _lambda.Function(
            self, "DataHandler",
            runtime=_lambda.Runtime.PYTHON_3_8,
            code=_lambda.Code.asset('lambda'),
            handler='initial_data.lambda_handler',
            timeout=cdk.Duration.minutes(5),
            environment = {
                'TABLE_NAME': table.table_name
            },
        )

        table.grant_full_access(on_event)

        initial_data_provider = _resources.Provider(
            self, "InitialDataProvider",
            on_event_handler=on_event,
            log_retention=logs.RetentionDays.ONE_DAY,
            role=initial_data_role
        )

        cdk.CustomResource(
            self, "InitialDataResource", 
            service_token=initial_data_provider.service_token
        )

class ExplainBotCloudWatchStack(cdk.Stack):
    def __init__(
            self, 
            scope: cdk.Construct, 
            construct_id: str,
            table: _dynamo.Table,
            approvers: str,
            oauth_token: str,
            slack_signing_secret: str,
            **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        lambda_schedule = _events.Schedule.rate(cdk.Duration.minutes(1))

        reminder_lambda = _lambda.Function(
            self, "SendReminderHandler",
            runtime=_lambda.Runtime.PYTHON_3_8,
            code=_lambda.Code.asset('lambda'),
            handler='send_reminder.lambda_handler',
            timeout=cdk.Duration.minutes(5),
            environment = {
                'TABLE_NAME': table.table_name,
                'APPROVERS': approvers,
                'OAUTH_TOKEN': oauth_token,
                'SLACK_SIGNING_SECRET': slack_signing_secret
            },
        )

        table.grant_full_access(reminder_lambda)

        event_lambda_target = _events_targets.LambdaFunction(handler = reminder_lambda)
        lambda_cw_event = _events.Rule(self, "SendReminders",
            description = "Once per day CW event trigger for lambda",
            enabled = True,
            schedule = lambda_schedule,
            targets = [event_lambda_target]
        )

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

        ExplainBotInitialDataStack(
            self, "InitialDataStack",
            table = database_stack.table,
        )

        ExplainBotCloudWatchStack(
            self, "ReminderStack",
            table = database_stack.table,
            approvers = lambda_stack.approvers,
            oauth_token = lambda_stack.oauth_token,
            slack_signing_secret = lambda_stack.slack_signing_secret
        )





