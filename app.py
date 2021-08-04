#!/usr/bin/env python3
from aws_cdk import core as cdk

from explainbot_stack import ExplainSlackBotStack
from explainbot_pipeline_stack import ExplainSlackBotPipelineStack

app = cdk.App()
ExplainSlackBotStack(app, "ExplainSlackBotStack")
ExplainSlackBotPipelineStack(app, "ExplainBotPipelineStack", env={
    'account': '442001344127',
    'region': 'us-east-1'
})

app.synth()
