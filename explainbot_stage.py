from aws_cdk import core as cdk
from explainbot_stack import ExplainSlackBotStack

class ExplainSlackBotStage(cdk.Stage):
    def __init__(self, scope: cdk.Construct, id: str, **kwargs):
        super().__init__(scope, id, **kwargs)

        service = ExplainSlackBotStack(self, 'WebService')
        
        print("URL OUTPUT"+service.url_output)
        self.url_output = service.url_output