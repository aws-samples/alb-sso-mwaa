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
    aws_iam
)
from constructs import Construct

class MwaaExecutionRole(aws_iam.Role):

    def __init__(self, scope: Construct, id: str, 
        environment_name=None, bucket_arn=None, **kwargs) -> None:

        policy_document = aws_iam.PolicyDocument(
            statements=[
                aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=["airflow:PublishMetrics"], 
                    resources=[f"arn:aws:airflow:{Aws.REGION}:{Aws.ACCOUNT_ID}:environment/{environment_name}"]),
                aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.DENY,
                    actions=["s3:ListAllMyBuckets"], 
                    resources=[f"{bucket_arn}", f"{bucket_arn}/*"]),
                aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=["s3:GetObject*",  "s3:GetBucket*",  "s3:List*" ], 
                    resources=[f"{bucket_arn}", f"{bucket_arn}/*"]),
                aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=["logs:DescribeLogGroups" ], 
                    resources=["*"]),
                aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=[ "logs:CreateLogStream", 
                        "logs:CreateLogGroup", 
                        "logs:PutLogEvents",
                        "logs:GetLogEvents",
                        "logs:GetLogRecord",
                        "logs:GetLogGroupFields",
                        "logs:GetQueryResults",
                        "logs:DescribeLogGroups"
                    ], 
                    resources=[f"arn:aws:logs:{Aws.REGION}:{Aws.ACCOUNT_ID}:log-group:airflow-{environment_name}*"]),
                aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=["cloudwatch:PutMetricData"], 
                    resources=["*"]),
                aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=[
                            "sqs:ChangeMessageVisibility",
                            "sqs:DeleteMessage",
                            "sqs:GetQueueAttributes",
                            "sqs:GetQueueUrl",
                            "sqs:ReceiveMessage",
                            "sqs:SendMessage"], 
                        resources=[f"arn:aws:sqs:{Aws.REGION}:*:airflow-celery-*"]),
                aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=[ 
                        "kms:Decrypt", 
                        "kms:DescribeKey", 
                        "kms:GenerateDataKey*", 
                        "kms:Encrypt"], 
                    not_resources=[f"arn:aws:kms:*:{Aws.ACCOUNT_ID}:key/*"],
                    conditions={ "StringLike": 
                        { 
                            "kms:ViaService": f"sqs.{Aws.REGION}.amazonaws.com" 
                        } 
                    }),
                aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=[ 
                        "ecr:GetAuthorizationToken",
                        "ecr:BatchCheckLayerAvailability",
                        "ecr:GetDownloadUrlForLayer",
                        "ecr:GetRepositoryPolicy",
                        "ecr:DescribeRepositories",
                        "ecr:ListImages",
                        "ecr:DescribeImages",
                        "ecr:BatchGetImage",
                        "ecr:InitiateLayerUpload",
                        "ecr:UploadLayerPart",
                        "ecr:CompleteLayerUpload",
                        "ecr:PutImage",
                        "ecr:CreateRepository"
                    ], 
                    resources=["*"])
            ]
        )

        super(MwaaExecutionRole, self).__init__(scope, id,
            assumed_by=aws_iam.ServicePrincipal("airflow.amazonaws.com"),
            inline_policies={f"{id}Policy": policy_document}, path="/service-role/", **kwargs)
        
        self.assume_role_policy.add_statements(aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=["sts:AssumeRole"], 
                    principals=[aws_iam.ServicePrincipal("airflow-env.amazonaws.com")]))