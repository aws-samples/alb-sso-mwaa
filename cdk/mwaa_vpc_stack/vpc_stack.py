
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
    aws_ec2,
    aws_iam
)
from constructs import Construct
from cdk_nag import NagSuppressions
from utils.secure_vpc import SecureVpc
from utils.secure_kms_key import SecureKmsKey

class MwaaVpcStack(Stack):

    def __init__(self, scope: Construct, id: str, vpc_context=None, **kwargs) -> None:
        super(MwaaVpcStack, self).__init__(scope, id, **kwargs)

        vpc_cidr = vpc_context.get("VpcCIDR")
        pub_mask = int(vpc_context.get("PublicSubnetMask"))
        pvt_mask = int(vpc_context.get("PrivateSubnetMask"))
       
        max_azs = int(vpc_context.get("MaxAZs"))
        nat_gateways = int(vpc_context.get("NatGateways"))

        public_subnet_config = aws_ec2.SubnetConfiguration(
                               subnet_type=aws_ec2.SubnetType.PUBLIC,
                               name="SecureVpcPublicSubnet",
                               cidr_mask=pub_mask)
        
        private_subnet_config = aws_ec2.SubnetConfiguration(
                               subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_NAT,
                               name="SecureVpcPrivateSubnet",
                               cidr_mask=pvt_mask)

        autoscaling_service_role_arn = vpc_context.get("AWSServiceRoleForAutoScalingArn")
        kms_key = SecureKmsKey(self, "SecureKmsKey", role_arns=[autoscaling_service_role_arn])
        vpc = SecureVpc(self, f"SecureVpc", kms_key=kms_key, cidr=vpc_cidr, max_azs=max_azs, 
            subnet_configuration=[public_subnet_config, private_subnet_config], 
            nat_gateways=nat_gateways)

        s3_endpoint = aws_ec2.GatewayVpcEndpoint(self, "SecureVpcS3Endppoint",
            service=aws_ec2.GatewayVpcEndpointAwsService.S3,
            vpc=vpc)

        s3_endpoint.add_to_policy(aws_iam.PolicyStatement(
                    actions=["s3:Get*", "s3:List*", "s3:PutObject*", "s3:DeleteObject*"], 
                    principals=[aws_iam.AnyPrincipal()], 
                    resources=["*"]))

        dynamodb_endpoint = aws_ec2.GatewayVpcEndpoint(self, "SecureVpcDynamodbEndppoint",
            service=aws_ec2.GatewayVpcEndpointAwsService.DYNAMODB,
            vpc=vpc)

        dynamodb_endpoint.add_to_policy(aws_iam.PolicyStatement(
                    actions=["dynamodb:*"], 
                    principals=[aws_iam.AnyPrincipal()], 
                    resources=["*"]))

        emr_endpoint = vpc.add_interface_endpoint("SecureVpcEmrEndpoint", 
            service=aws_ec2.InterfaceVpcEndpointAwsService(f"elasticmapreduce", port=443))
        
        emr_endpoint.add_to_policy(aws_iam.PolicyStatement(
                    actions=["elasticmapreduce:*"], 
                    principals=[aws_iam.AnyPrincipal()], 
                    resources=["*"]))

        sagemaker_endpoint = vpc.add_interface_endpoint("SecureVpcSageMakerEndpoint", 
            service=aws_ec2.InterfaceVpcEndpointAwsService.SAGEMAKER_API)
        sagemaker_endpoint.add_to_policy(aws_iam.PolicyStatement(
                    actions=["sagemaker:*"], 
                    principals=[aws_iam.AnyPrincipal()], 
                    resources=["*"]))

        ecr_api_endpoint = vpc.add_interface_endpoint("SecureVpcEcrApiEndpoint", 
            service=aws_ec2.InterfaceVpcEndpointAwsService.ECR)
        ecr_api_endpoint.add_to_policy(aws_iam.PolicyStatement(
                    actions=["ecr:*"], 
                    principals=[aws_iam.AnyPrincipal()], 
                    resources=["*"]))

        ecr_dkr_endpoint = vpc.add_interface_endpoint("SecureVpcEcrDkrEndpoint", 
            service=aws_ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER)
        ecr_dkr_endpoint.add_to_policy(aws_iam.PolicyStatement(
                    actions=["ecr:*"], 
                    principals=[aws_iam.AnyPrincipal()], 
                    resources=["*"]))

        secretsmanager_endpoint = vpc.add_interface_endpoint("SecureVpcSecretsManagerEndpoint", 
            service=aws_ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER)
        secretsmanager_endpoint.add_to_policy(aws_iam.PolicyStatement(
                    actions=["secretsmanager:*"], 
                    principals=[aws_iam.AnyPrincipal()], 
                    resources=["*"]))

        ecs_endpoint = vpc.add_interface_endpoint("SecureVpcEcsEndpoint", 
            service=aws_ec2.InterfaceVpcEndpointAwsService.ECS)
        ecs_endpoint.add_to_policy(aws_iam.PolicyStatement(
                    actions=["ecs:*"], 
                    principals=[aws_iam.AnyPrincipal()], 
                    resources=["*"]))

        ecsagent_endpoint = vpc.add_interface_endpoint("SecureVpcEcsAgentEndpoint", 
            service=aws_ec2.InterfaceVpcEndpointAwsService.ECS_AGENT)
        ecsagent_endpoint.add_to_policy(aws_iam.PolicyStatement(
                    actions=["ecs:*"], 
                    principals=[aws_iam.AnyPrincipal()], 
                    resources=["*"]))

        ecstel_endpoint = vpc.add_interface_endpoint("SecureVpcEcsTelemetryEndpoint", 
            service=aws_ec2.InterfaceVpcEndpointAwsService.ECS_TELEMETRY)
        ecstel_endpoint.add_to_policy(aws_iam.PolicyStatement(
                    actions=["ecs:*"], 
                    principals=[aws_iam.AnyPrincipal()], 
                    resources=["*"]))

        sqs_endpoint = vpc.add_interface_endpoint("SecureVpcSqsEndpoint", 
            service=aws_ec2.InterfaceVpcEndpointAwsService.SQS)
        sqs_endpoint.add_to_policy(aws_iam.PolicyStatement(
                    actions=["sqs:*"], 
                    principals=[aws_iam.AnyPrincipal()], 
                    resources=["*"]))
        
        kms_endpoint = vpc.add_interface_endpoint("SecureVpcKmsEndpoint", 
            service=aws_ec2.InterfaceVpcEndpointAwsService.KMS)
        kms_endpoint.add_to_policy(aws_iam.PolicyStatement(
                    actions=["kms:*"], 
                    principals=[aws_iam.AnyPrincipal()], 
                    resources=["*"]))

        airflow_api_endpoint = vpc.add_interface_endpoint("SecureVpcAirflowApiEndpoint", 
            service=aws_ec2.InterfaceVpcEndpointService(f"com.amazonaws.{Aws.REGION}.airflow.api", 443))
        airflow_api_endpoint.add_to_policy(aws_iam.PolicyStatement(
                    actions=["airflow:*"], 
                    principals=[aws_iam.AnyPrincipal()], 
                    resources=["*"]))

        airflow_env_endpoint = vpc.add_interface_endpoint("SecureVpcAirflowEnvEndpoint", 
            service=aws_ec2.InterfaceVpcEndpointService(f"com.amazonaws.{Aws.REGION}.airflow.env", 443))
        airflow_env_endpoint.add_to_policy(aws_iam.PolicyStatement(
                    actions=["airflow:*"], 
                    principals=[aws_iam.AnyPrincipal()], 
                    resources=["*"]))

        airflow_ops_endpoint = vpc.add_interface_endpoint("SecureVpcAirflowOpsEndpoint", 
            service=aws_ec2.InterfaceVpcEndpointService(f"com.amazonaws.{Aws.REGION}.airflow.ops", 443))
        airflow_ops_endpoint.add_to_policy(aws_iam.PolicyStatement(
                    actions=["airflow:*"], 
                    principals=[aws_iam.AnyPrincipal()], 
                    resources=["*"]))

        NagSuppressions.add_stack_suppressions(self,  
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Need wildcard access"
                }
            ],
            True
        )

        self.vpc = vpc

    def get_vpc(self):
        return self.vpc    