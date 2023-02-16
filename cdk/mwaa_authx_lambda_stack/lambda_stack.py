
'''
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

from aws_cdk import (
    Stack,
    Aws,
    BundlingOptions,
    Duration,
    aws_ec2,
    aws_lambda,
    aws_iam,
    aws_dynamodb
)
from constructs import Construct
from utils.lambda_execution_role import LambdaExecutionRole
from utils.lambda_mwaa_rbac_role import LambdaMwaaRbacRole
from cdk_nag import NagSuppressions

class MwaaAuthxLambdaStack(Stack):

    def __init__(self, scope: Construct, id: str, vpc: aws_ec2.Vpc, **kwargs) -> None:
        super(MwaaAuthxLambdaStack, self).__init__(scope, id, **kwargs)
        
        NagSuppressions.add_stack_suppressions(self,  
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Need wildcard access"
                },
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": "Need managed policies"
                }
            ],
            True
        )

        airflow_permissions_table = aws_dynamodb.Table(self, "AirflowPermissions",
            partition_key=aws_dynamodb.Attribute(name="email", type=aws_dynamodb.AttributeType.STRING),
            sort_key=aws_dynamodb.Attribute(name="mwaa_env", type=aws_dynamodb.AttributeType.STRING)
        )

        mwaa_envs_context = self.node.try_get_context("MwaaEnvironments")
        alb_context = self.node.try_get_context("Alb")

        mwaa_env_names = []
        for mwaa_env_context in mwaa_envs_context:
            mwaa_env_names.append(mwaa_env_context.get("Name"))
       
        
        rbac_admin_role = LambdaMwaaRbacRole(self, "MwaaAdminRole",
            mwaa_env_names=mwaa_env_names, rbac_role_name="Admin")
        rbac_user_role = LambdaMwaaRbacRole(self, "MwaaUserRole", 
            mwaa_env_names=mwaa_env_names, rbac_role_name="User")
        rbac_viewer_role = LambdaMwaaRbacRole(self, "MwaaViewerRole", 
            mwaa_env_names=mwaa_env_names, rbac_role_name="Viewer")
        rbac_op_role = LambdaMwaaRbacRole(self, "MwaaOpRole", 
            mwaa_env_names=mwaa_env_names, rbac_role_name="Op")
        rbac_public_role = LambdaMwaaRbacRole(self, "MwaaPublicRole",  
            mwaa_env_names=mwaa_env_names, rbac_role_name="Public")

        assume_role_policy_statement = aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=[ 
                        "sts:AssumeRole"
                    ], 
                    resources=[
                        rbac_admin_role.role_arn,
                        rbac_user_role.role_arn,
                        rbac_viewer_role.role_arn,
                        rbac_op_role.role_arn,
                        rbac_public_role.role_arn
                    ])

        dynamodb_policy_statement = aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=[ "dynamodb:*"], 
                    resources=[airflow_permissions_table.table_arn])

        airflow_policy_statement = aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=[ "airflow:GetEnvironment"], 
                    resources=[f"arn:aws:airflow:{Aws.REGION}:{Aws.ACCOUNT_ID}:environment/*"])

        lambda_execution_role = LambdaExecutionRole(self, "AuthLambdaExecutionRole")
        
        lambda_execution_role.add_to_principal_policy(assume_role_policy_statement)
        lambda_execution_role.add_to_principal_policy(dynamodb_policy_statement)
        lambda_execution_role.add_to_principal_policy(airflow_policy_statement)

        alb_cookie_name = alb_context.get("SessionCookieName", "AWSELBAuthSessionCookie")
        lambda_env = {
            "RBAC_ADMIN_ROLE_ARN": rbac_admin_role.role_arn,
            "RBAC_USER_ROLE_ARN": rbac_user_role.role_arn,
            "RBAC_VIEWER_ROLE_ARN": rbac_viewer_role.role_arn,
            "RBAC_OP_ROLE_ARN": rbac_op_role.role_arn,
            "RBAC_PUBLIC_ROLE_ARN": rbac_public_role.role_arn,
            "PUBLIC_KEY_ENDPOINT": f"https://public-keys.auth.elb.{Aws.REGION}.amazonaws.com/",
            "PERMISSIONS_TABLE": airflow_permissions_table.table_name,
            "ALB_COOKIE_NAME": alb_cookie_name
        }

        self.__function = aws_lambda.Function(self, "MwaaAuthxFunction",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="mwaa_authx.lambda_handler",
            code=aws_lambda.Code.from_asset(
                path="mwaa_authx_lambda_code",
                bundling=BundlingOptions(
                    image=aws_lambda.Runtime.PYTHON_3_9.bundling_image,
                    command=[
                        "bash", "-c",
                        "pip install --no-cache -r requirements.txt -t /asset-output && cp -au . /asset-output"
                    ]
                )),
            role=lambda_execution_role,
            vpc=vpc,
            environment=lambda_env,
            timeout=Duration.millis(10000))

    def get_function(self):
        return self.__function
        