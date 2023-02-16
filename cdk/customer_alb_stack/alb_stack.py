
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
    SecretValue,
    aws_ec2,
    aws_s3,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as targets,
    aws_lambda,
    aws_iam,
    CfnOutput,
)

from constructs import Construct
from cdk_nag import NagSuppressions

class CustomerAlbStack(Stack):

    def __init__(self, scope: Construct, id: str, vpc: aws_ec2.Vpc, 
        function: aws_lambda.Function, mwaa_private_access={}, **kwargs) -> None:
        super(CustomerAlbStack, self).__init__(scope, id, **kwargs)

        NagSuppressions.add_stack_suppressions(self,  
            [
                {
                    "id": "AwsSolutions-EC23",
                    "reason": "Private ALB"
                }
            ],
            True
        )
        
        self.__alb_context = self.node.try_get_context("Alb")
       
        security_group = aws_ec2.SecurityGroup(self, "CustomerAlbSecurityGroup", vpc=vpc)
        security_group.connections.allow_from_any_ipv4(aws_ec2.Port.tcp(443), 'Allow inbound HTTPS')
        security_group.connections.allow_to_any_ipv4(aws_ec2.Port.tcp_range(443, 443), 'Allow outbound HTTPS')

        internet_facing = self.__alb_context.get("InternetFacing")
        alb = elbv2.ApplicationLoadBalancer(self, "Alb", 
            vpc=vpc, internet_facing=internet_facing, security_group=security_group)
       
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
                next=elbv2.ListenerAction.fixed_response(200,
                    content_type="text/plain",
                    message_body="Single sign-on successful! To access MWAA Airflow console, use htps://#{host}/aws_mwaa/aws-console-sso?mwaa_env=env-name&rbac_role=role-name"
                )
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

        https_listener.add_action(f"CreateWebLoginToken", 
                action=create_web_token_action,
                conditions=[elbv2.ListenerCondition.path_patterns(["/aws_mwaa/aws-console-sso"])],
                priority=1)

        alb_logout_action = elbv2.ListenerAction.forward(target_groups=[lambda_tg])
        https_listener.add_action(f"AlbLogout", 
                action=alb_logout_action,
                conditions=[elbv2.ListenerCondition.path_patterns(["/logout"])],
                priority=2)

    
        for mwaa_env_name, mwaa_vpc in mwaa_private_access.items():
            self.__peer_mwaa_vpc(vpc=vpc,  peer_vpc=mwaa_vpc, mwaa_env_name=mwaa_env_name)

        CfnOutput(self, "AlbDnsName", value=f"{alb.load_balancer_dns_name}")
        

    def __peer_mwaa_vpc(self, vpc: aws_ec2.Vpc, peer_vpc: aws_ec2.IVpc, mwaa_env_name: str):

        vpc_peer_con = aws_ec2.CfnVPCPeeringConnection(self, f"{mwaa_env_name}VpcPeering",
            peer_vpc_id=peer_vpc.vpc_id,
            vpc_id=vpc.vpc_id)

        private_subnets = vpc.private_subnets
        index = 0
        for subnet in private_subnets:
            route_table = subnet.route_table
            aws_ec2.CfnRoute(self, f"Local{mwaa_env_name}Route{index}",
                    route_table_id = route_table.route_table_id,
                    vpc_peering_connection_id=vpc_peer_con.ref,
                    destination_cidr_block=peer_vpc.vpc_cidr_block)
            index += 1

        private_subnets = peer_vpc.private_subnets
        index = 0
        for subnet in private_subnets:
            route_table = subnet.route_table
            aws_ec2.CfnRoute(self, f"Peer{mwaa_env_name}Route{index}",
                    route_table_id = route_table.route_table_id,
                    vpc_peering_connection_id=vpc_peer_con.ref,
                    destination_cidr_block=vpc.vpc_cidr_block)
            index += 1



      
      