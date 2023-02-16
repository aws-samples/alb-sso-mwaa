
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
    aws_ec2,
    aws_mwaa
)
from constructs import Construct
from utils.mwaa_execution_role import MwaaExecutionRole
from cdk_nag import NagSuppressions

class MwaaStack(Stack):

    def __init__(self, scope: Construct, id: str, vpc: aws_ec2.Vpc, 
            environment_name: str, mwaa_env_context=None, **kwargs) -> None:
        super(MwaaStack, self).__init__(scope, id, **kwargs)
        
        customer_vpc_context = self.node.try_get_context("CustomerVpc")
        source_bucket_arn = mwaa_env_context.get("SourceBucketArn")

        NagSuppressions.add_stack_suppressions(self,  
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Need wildcard access"
                }
            ],
            True
        )

        private_subnet_ids = vpc.select_subnets(subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_NAT).subnet_ids
        environment_class = mwaa_env_context.get("EnnvironmentClass")

        security_group = aws_ec2.SecurityGroup(self, "MwaaSecurityGroup", vpc=vpc)
        security_group.connections.allow_internally(aws_ec2.Port.all_tcp())
        customer_vpc_cidr = customer_vpc_context.get("VpcCIDR")
        security_group.add_ingress_rule(peer=aws_ec2.Peer.ipv4(customer_vpc_cidr),
            connection=aws_ec2.Port.tcp(443), description="Allow HTTPS from Customer VPC")

        requirements_s3_path = mwaa_env_context.get("RequirementsS3Path")
        requirements_s3_object_version = mwaa_env_context.get("RequirementsS3ObjectVersion")

        mwaa_execution_role = MwaaExecutionRole(self, "MwaaExecutionRole", 
            environment_name=environment_name, 
            bucket_arn=source_bucket_arn)

        self.__mwaa_environment = aws_mwaa.CfnEnvironment(self, 
            "MwaaEnvironment",
            name=environment_name,
            airflow_configuration_options=mwaa_env_context.get("ConfigurationOptions"),
            dag_s3_path=mwaa_env_context.get("DagsS3Path"),
            environment_class=environment_class,
            execution_role_arn=mwaa_execution_role.role_arn,
            requirements_s3_path=requirements_s3_path,
            requirements_s3_object_version=requirements_s3_object_version,
            logging_configuration=aws_mwaa.CfnEnvironment.LoggingConfigurationProperty(
                dag_processing_logs=aws_mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                    enabled=True,
                    log_level=mwaa_env_context.get("DagProcessingLogsLevel")
                ),
                scheduler_logs=aws_mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                    enabled=True,
                    log_level=mwaa_env_context.get("SchedulerLogsLevel")
                ),
                task_logs=aws_mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                    enabled=True,
                    log_level=mwaa_env_context.get("TaskLogsLevel")
                ),
                webserver_logs=aws_mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                    enabled=True,
                    log_level=mwaa_env_context.get("WebserverLogsLevel")
                ),
                worker_logs=aws_mwaa.CfnEnvironment.ModuleLoggingConfigurationProperty(
                    enabled=True,
                    log_level=mwaa_env_context.get("WorkerLogsLevel")
                )
            ),
            max_workers=mwaa_env_context.get("MaxWorkers"),
            min_workers=mwaa_env_context.get("MinWorkers"),
            network_configuration=aws_mwaa.CfnEnvironment.NetworkConfigurationProperty(
                security_group_ids=[security_group.security_group_id],
                subnet_ids=private_subnet_ids
            ),
            schedulers=mwaa_env_context.get("Schedulers"),
            source_bucket_arn=source_bucket_arn,
            webserver_access_mode= mwaa_env_context.get("WebServerAccessMode")
        )

    def get_mwaa_environment(self):
        return self.__mwaa_environment