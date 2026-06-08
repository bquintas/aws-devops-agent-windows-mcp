"""CDK Stack for SSM-Based MCP Server — Windows Instance Diagnostics."""

import aws_cdk as cdk
from aws_cdk import (
    Aws,
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    aws_apigateway as apigw,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_logs as logs,
    aws_ssm as ssm,
)
from constructs import Construct


class SsmMcpServerStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- Parameters ---
        allowed_instance_ids = cdk.CfnParameter(
            self,
            "AllowedInstanceIds",
            type="CommaDelimitedList",
            default="none",
            description="Comma-separated list of EC2 instance IDs allowed as SSM targets (can be updated later via SSM Parameter Store without redeployment)",
        )

        # --- SSM Parameter Store for allowed instance IDs ---
        # This allows updating the allowlist without redeploying
        param_name = "/mcp-server/allowed-instance-ids"
        instance_ids_param = ssm.StringParameter(
            self,
            "AllowedInstanceIdsParam",
            parameter_name=param_name,
            string_value=cdk.Fn.join(",", allowed_instance_ids.value_as_list),
            description="Comma-separated allowed EC2 instance IDs for MCP SSM tools",
        )

        # --- Log Group ---
        log_group = logs.LogGroup(
            self,
            "McpLambdaLogGroup",
            log_group_name="/aws/lambda/ssm-mcp-server",
            retention=logs.RetentionDays.TWO_WEEKS,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # --- Lambda Function ---
        mcp_lambda = lambda_.Function(
            self,
            "McpServerFunction",
            function_name="ssm-mcp-server",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="handler.handler",
            code=lambda_.Code.from_asset("../lambda_code"),
            timeout=Duration.seconds(60),
            memory_size=256,
            environment={
                "ALLOWED_INSTANCE_IDS_PARAM": param_name,
                "SSM_COMMAND_TIMEOUT": "30",
                "MAX_OUTPUT_CHARS": "10000",
                "LOG_LEVEL": "INFO",
            },
            log_group=log_group,
        )

        # --- Lambda IAM Permissions ---

        # SSM SendCommand on the document — no tag condition (documents don't have tags)
        mcp_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=["ssm:SendCommand"],
                resources=[
                    "arn:aws:ssm:*::document/AWS-RunPowerShellScript",
                ],
            )
        )

        # SSM SendCommand on instances — scoped by tag condition
        mcp_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=["ssm:SendCommand"],
                resources=[
                    f"arn:aws:ec2:*:{Aws.ACCOUNT_ID}:instance/*",
                ],
                conditions={
                    "StringEquals": {
                        "ssm:resourceTag/AllowMcpAccess": "true",
                    }
                },
            )
        )

        mcp_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=["ssm:GetCommandInvocation"],
                resources=["*"],
            )
        )

        # Read allowed instance IDs from Parameter Store
        instance_ids_param.grant_read(mcp_lambda)

        # --- API Gateway (REST API with IAM Auth) ---
        api = apigw.RestApi(
            self,
            "McpApi",
            rest_api_name="ssm-mcp-server",
            description="MCP Server endpoint for DevOps Agent - Windows Instance Diagnostics",
            deploy_options=apigw.StageOptions(
                stage_name="prod",
                throttling_burst_limit=20,
                throttling_rate_limit=10,
                logging_level=apigw.MethodLoggingLevel.INFO,
            ),
            endpoint_types=[apigw.EndpointType.REGIONAL],
        )

        # /mcp resource with POST method (IAM auth)
        mcp_resource = api.root.add_resource("mcp")
        mcp_resource.add_method(
            "POST",
            apigw.LambdaIntegration(
                mcp_lambda,
                proxy=True,
            ),
            authorization_type=apigw.AuthorizationType.IAM,
        )

        # --- DevOps Agent Invocation Role ---
        invocation_role = iam.Role(
            self,
            "DevOpsAgentInvocationRole",
            role_name="ssm-mcp-devops-agent-role",
            assumed_by=iam.ServicePrincipal(
                "aidevops.amazonaws.com",
                conditions={
                    "StringEquals": {"aws:SourceAccount": Aws.ACCOUNT_ID},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:aidevops:{Aws.REGION}:{Aws.ACCOUNT_ID}:service/*"},
                },
            ),
            description="Role assumed by AWS DevOps Agent to invoke the MCP server API",
        )

        invocation_role.add_to_policy(
            iam.PolicyStatement(
                actions=["execute-api:Invoke"],
                resources=[
                    api.arn_for_execute_api("POST", "/mcp", "prod"),
                ],
            )
        )

        # --- Outputs ---
        CfnOutput(
            self,
            "McpEndpointUrl",
            value=f"{api.url}mcp",
            description="MCP Server endpoint URL for DevOps Agent registration",
        )

        CfnOutput(
            self,
            "InvocationRoleArn",
            value=invocation_role.role_arn,
            description="IAM Role ARN for DevOps Agent to assume",
        )

        CfnOutput(
            self,
            "LambdaFunctionArn",
            value=mcp_lambda.function_arn,
            description="Lambda function ARN",
        )

        CfnOutput(
            self,
            "AllowedInstanceIdsParameterName",
            value=param_name,
            description="SSM Parameter name storing allowed instance IDs (update without redeployment)",
        )
