#!/usr/bin/env python3
from aws_cdk import core as cdk

from explainbot_pipeline_stack import ExplainSlackBotPipelineStack

explainbot_account = cdk.SecretValue.secrets_manager("EXPLAINBOT_ACCOUNT").to_string()

app = cdk.App()
ExplainSlackBotPipelineStack(
    app,
    "ExplainBotPipelineStack",
    env={"account": explainbot_account, "region": "us-east-2"},
)

app.synth()
