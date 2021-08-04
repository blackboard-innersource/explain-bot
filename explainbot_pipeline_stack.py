from aws_cdk import (
    core as cdk,
    aws_codepipeline as codepipeline,
    aws_codepipeline_actions as cpactions
)
 
from aws_cdk.pipelines import (
    CdkPipeline,
    SimpleSynthAction
)

from explainbot_stage import ExplainSlackBotStage
 
class ExplainSlackBotPipelineStack(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
 
        source_artifact = codepipeline.Artifact()
        cloud_assembly_artifact = codepipeline.Artifact()
 
        pipeline = CdkPipeline(self, 'Pipeline',
            pipeline_name='ExplainBotPipeline',
            cloud_assembly_artifact=cloud_assembly_artifact,
            source_action=cpactions.GitHubSourceAction(
                action_name='GitHub',
                output=source_artifact,
                oauth_token=cdk.SecretValue.secrets_manager('GITHUB_TOKEN_NAME'),
                owner='blackboard-innersource',
                repo='explain-bot',
                branch='feature/add_pipeline',
                trigger=cpactions.GitHubTrigger.POLL
            ),
            synth_action=SimpleSynthAction(
                    source_artifact=source_artifact,
                    cloud_assembly_artifact=cloud_assembly_artifact,
                    install_command='npm install -g aws-cdk && pip install -r requirements.txt',
                    synth_command='cdk synth'
            )
        )
        pipeline.add_application_stage(ExplainSlackBotStage(self, 'PreProd', env={
            'account': '442001344127',
            'region': 'us-east-1'
        }))