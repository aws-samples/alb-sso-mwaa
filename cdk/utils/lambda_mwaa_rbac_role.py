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
    aws_iam,
)
from constructs import Construct

class LambdaMwaaRbacRole(aws_iam.Role):

    def __init__(self, scope: Construct, id: str,
        rbac_role_name: str, mwaa_env_names=None,  **kwargs) -> None:

        policy_document = aws_iam.PolicyDocument(
            statements=[
                
                aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=[ 
                        "airflow:CreateWebLoginToken"
                    ], 
                    resources=[f"arn:aws:airflow:{Aws.REGION}:{Aws.ACCOUNT_ID}:role/{mwaa_env_name}/{rbac_role_name}" for mwaa_env_name in mwaa_env_names]),
            ]
        )

        super(LambdaMwaaRbacRole, self).__init__(scope, id,
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            inline_policies={f"{id}Policy": policy_document}, path="/service-role/", **kwargs)
        
        self.assume_role_policy.add_statements(aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=["sts:AssumeRole"], 
                    principals=[ aws_iam.AccountRootPrincipal()]))