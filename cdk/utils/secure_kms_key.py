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
    aws_kms
)
from constructs import Construct
class SecureKmsKey(aws_kms.Key):

    def __init__(self, scope: Construct, id: str, role_arns=None, **kwargs) -> None:
    
        kmskey_policy = aws_iam.PolicyDocument(
            statements=[
                aws_iam.PolicyStatement(
                    actions=["kms:*"], 
                    principals=[aws_iam.AccountRootPrincipal()], 
                    resources=["*"]),
                aws_iam.PolicyStatement(
                    actions=["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"], 
                    principals=[aws_iam.ServicePrincipal(f"logs.{Aws.REGION}.amazonaws.com")], 
                    resources=["*"]),
            ]
        )

        if isinstance(role_arns, list):
            for role_arn in role_arns:
                kmskey_policy.add_statements(
                    aws_iam.PolicyStatement(
                            actions=["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"], 
                            principals=[aws_iam.ArnPrincipal(role_arn)], 
                            resources=["*"]))
        super(SecureKmsKey, self).__init__(scope, id, enable_key_rotation=True, policy=kmskey_policy, **kwargs)
        