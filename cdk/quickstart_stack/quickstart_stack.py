
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
    Aws,
    Stack,
    SecretValue,
    BundlingOptions,
    Duration,
    aws_ec2,
    aws_s3,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as targets,
    aws_lambda,
    aws_iam,
    CfnOutput,
)
from utils.lambda_execution_role import LambdaExecutionRole
from utils.lambda_mwaa_rbac_role import LambdaMwaaRbacRole
from constructs import Construct
from cdk_nag import NagSuppressions

class QuickStartStack(Stack):

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super(QuickStartStack, self).__init__(scope, id, **kwargs)

        NagSuppressions.add_stack_suppressions(self,  
            [
                {
                    "id": "AwsSolutions-EC23",
                    "reason": "Private ALB"
                },
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
        
        self.__alb_context = self.node.try_get_context("Alb")
        self.__quickstart_context = self.node.try_get_context("QuickStart")

        vpc = aws_ec2.Vpc.from_lookup(self, "Vpc", vpc_id=self.__quickstart_context["VpcId"])

        mwaa_env_name = self.__quickstart_context.get("MwaaEnvironmentName")
        mwaa_env_names = [ mwaa_env_name ]
        
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

        airflow_policy_statement = aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=[ "airflow:GetEnvironment"], 
                    resources=[f"arn:aws:airflow:{Aws.REGION}:{Aws.ACCOUNT_ID}:environment/*"])

        lambda_execution_role = LambdaExecutionRole(self, "AuthLambdaExecutionRole")
        
        lambda_execution_role.add_to_principal_policy(assume_role_policy_statement)
        lambda_execution_role.add_to_principal_policy(airflow_policy_statement)

        alb_cookie_name = self.__alb_context.get("SessionCookieName", "AWSELBAuthSessionCookie")
        lambda_env = {
            "MWAA_ENVIRONMENT_NAME": mwaa_env_name,
            "RBAC_ROLE_NAME": self.__quickstart_context.get("RbacRoleName", "Admin"),
            "RBAC_ADMIN_ROLE_ARN": rbac_admin_role.role_arn,
            "RBAC_USER_ROLE_ARN": rbac_user_role.role_arn,
            "RBAC_VIEWER_ROLE_ARN": rbac_viewer_role.role_arn,
            "RBAC_OP_ROLE_ARN": rbac_op_role.role_arn,
            "RBAC_PUBLIC_ROLE_ARN": rbac_public_role.role_arn,
            "PUBLIC_KEY_ENDPOINT": f"https://public-keys.auth.elb.{Aws.REGION}.amazonaws.com/",
            "ALB_COOKIE_NAME": alb_cookie_name
        }

        function = aws_lambda.Function(self, "MwaaAuthxFunction",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            handler="mwaa_authx.lambda_handler",
            code=aws_lambda.Code.from_asset(
                path="quickstart_mwaa_authx_lambda_code",
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
       

        security_group_id = self.__quickstart_context.get("SecurityGroupId", "")
        if security_group_id:
            security_group = aws_ec2.SecurityGroup.from_lookup_by_id(self, "AlbSecurityGroup", security_group_id)
        else:
            security_group = aws_ec2.SecurityGroup(self, "AlbSecurityGroup", vpc=vpc, allow_all_outbound=False )
            security_group.connections.allow_from_any_ipv4(aws_ec2.Port.tcp(443), 'Allow inbound HTTPS')
            security_group.connections.allow_to_any_ipv4(aws_ec2.Port.tcp_range(443, 443), 'Allow outbound HTTPS')

        internet_facing = self.__alb_context.get("InternetFacing")
        subnet_ids = self.__quickstart_context["SubnetIds"]
        subnets = [ aws_ec2.Subnet.from_subnet_id(self, f"Subnet{i}", subnet_ids[i]) for i in range(len(subnet_ids))]
        subnet_selection = aws_ec2.SubnetSelection(subnets=subnets)
        alb = elbv2.ApplicationLoadBalancer(self, "Alb", 
            vpc=vpc, internet_facing=internet_facing, security_group=security_group, vpc_subnets=subnet_selection)
       
        log_bucket_arn = self.__alb_context.get("LogBucketArn")
        log_bucket_prefix = self.__alb_context.get("LogBucketPrefix")
        s3_log_bucket = aws_s3.Bucket.from_bucket_arn(self, "AlbLogBucket", log_bucket_arn)
        
        alb.log_access_logs(s3_log_bucket, prefix=log_bucket_prefix)

        lambda_target = targets.LambdaTarget(function)
        lambda_tg = elbv2.ApplicationTargetGroup(self, "LambdaTargetGroup",
            target_type=elbv2.TargetType.LAMBDA,
            targets=[lambda_target])
        lambda_tg.configure_health_check(enabled=False)
        lambda_tg.set_attribute(key="lambda.multi_value_headers.enabled", value="true")

        endpoint_ips = self.__quickstart_context.get("MwaaEndpointIps")
        mwaa_endpoint_ip_targets = [ targets.IpTarget(ip, 443) for ip in endpoint_ips ]
        mwaa_endpoint_tg = elbv2.ApplicationTargetGroup(self, "MwaaEndpointTargetGroup",
            port=443,
            vpc=vpc,
            target_type=elbv2.TargetType.IP,
            targets=mwaa_endpoint_ip_targets)
        mwaa_endpoint_tg.configure_health_check(port="443", 
                                                path="/aws_mwaa/aws-console-sso", 
                                                healthy_http_codes="200-499")
        
        function.add_permission("LambdaTgInvoke", 
            principal=aws_iam.ServicePrincipal("elasticloadbalancing.amazonaws.com"),
            action="lambda:InvokeFunction")

        self.__oidc_context = self.node.try_get_context("Oidc")
        oidc_client_secret_arn = self.__oidc_context.get("ClientSecretArn")
       
        certificate_arn = self.__alb_context.get("CertificateArn")
        certificate = elbv2.ListenerCertificate(certificate_arn=certificate_arn)
        https_listener = alb.add_listener("DefaultListener",
            port=443,
            certificates=[certificate],
            default_action=elbv2.ListenerAction.authenticate_oidc(
                authorization_endpoint=self.__oidc_context.get("AuthorizationEndpoint"),
                client_id=self.__oidc_context.get("ClientId"),
                client_secret=SecretValue.secrets_manager(oidc_client_secret_arn),
                issuer=self.__oidc_context.get("Issuer"),
                token_endpoint=self.__oidc_context.get("TokenEndpoint"),
                user_info_endpoint=self.__oidc_context.get("UserInfoEndpoint"),
                scope="openid email",
                session_cookie_name=self.__alb_context.get("SessionCookieName"),
                next=elbv2.ListenerAction.forward(target_groups=[mwaa_endpoint_tg])
            )
        )

        create_web_token_action = elbv2.ListenerAction.authenticate_oidc(
                authorization_endpoint=self.__oidc_context.get("AuthorizationEndpoint"),
                client_id=self.__oidc_context.get("ClientId"),
                client_secret=SecretValue.secrets_manager(oidc_client_secret_arn),
                issuer=self.__oidc_context.get("Issuer"),
                token_endpoint=self.__oidc_context.get("TokenEndpoint"),
                user_info_endpoint=self.__oidc_context.get("UserInfoEndpoint"),
                scope="openid email",
                session_cookie_name=self.__alb_context.get("SessionCookieName"),
                next=elbv2.ListenerAction.forward(target_groups=[lambda_tg])
            )

        login_web_token_action = elbv2.ListenerAction.authenticate_oidc(
                authorization_endpoint=self.__oidc_context.get("AuthorizationEndpoint"),
                client_id=self.__oidc_context.get("ClientId"),
                client_secret=SecretValue.secrets_manager(oidc_client_secret_arn),
                issuer=self.__oidc_context.get("Issuer"),
                token_endpoint=self.__oidc_context.get("TokenEndpoint"),
                user_info_endpoint=self.__oidc_context.get("UserInfoEndpoint"),
                scope="openid email",
                session_cookie_name=self.__alb_context.get("SessionCookieName"),
                next=elbv2.ListenerAction.forward(target_groups=[mwaa_endpoint_tg])
            )
        
        query_string_condition = elbv2.QueryStringCondition( key="login", value="true")
        https_listener.add_action(f"WebLoginToken", 
                action=login_web_token_action,
                conditions=[elbv2.ListenerCondition.path_patterns(["/aws_mwaa/aws-console-sso"]),
                            elbv2.ListenerCondition.query_strings([query_string_condition])],
                priority=1)
        
        https_listener.add_action(f"CreateWebLoginToken", 
                action=create_web_token_action,
                conditions=[elbv2.ListenerCondition.path_patterns(["/aws_mwaa/aws-console-sso"])],
                priority=2)

        alb_logout_action = elbv2.ListenerAction.forward(target_groups=[lambda_tg])
        https_listener.add_action(f"AlbLogout", 
                action=alb_logout_action,
                conditions=[elbv2.ListenerCondition.path_patterns(["/logout"])],
                priority=3)

        CfnOutput(self, "AlbDnsName", value=f"{alb.load_balancer_dns_name}")
        


      
      