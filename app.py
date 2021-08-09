#!/usr/bin/env python3
from aws_cdk import core as cdk

from explainbot_pipeline_stack import ExplainSlackBotPipelineStack
from explainbot_stack import ExplainSlackBotStack

explainbot_account=cdk.SecretValue.secrets_manager('EXPLAINBOT_ACCOUNT').to_string()

app = cdk.App()

ExplainSlackBotStack(app, "ExplainBotStack")
ExplainSlackBotPipelineStack(app, "ExplainBotPipelineStack", env={
    'account': explainbot_account,
    'region': 'us-east-1'
})

app.synth()
