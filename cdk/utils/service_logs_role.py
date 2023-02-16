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
    aws_iam,
    aws_logs
)
from constructs import Construct

class ServiceLogsRole(aws_iam.Role):

    def __init__(self, scope: Construct, id: str, 
        log_group: aws_logs.LogGroup, service: str,  **kwargs) -> None:
    
        log_policy = aws_iam.PolicyDocument(
            statements=[
                aws_iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogStream", 
                        "logs:PutLogEvents", 
                        "logs:DescribeLogGroups", 
                        "logs:DescribeLogStreams"
                    ], 
                    resources=[log_group.log_group_arn])
            ]
        )

        super(ServiceLogsRole, self).__init__(scope, id,
            assumed_by=aws_iam.ServicePrincipal(service),
            inline_policies={f"{id}Policy": log_policy}, **kwargs)