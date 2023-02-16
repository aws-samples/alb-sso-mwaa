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
    aws_iam
)
from constructs import Construct

class ManagedPolicyServiceRole(aws_iam.Role):

    def __init__(self, scope: Construct, id: str,  service: str, managed_policy_list, **kwargs) -> None:

        managed_policies = [aws_iam.ManagedPolicy.from_aws_managed_policy_name(managed_policy_name) 
            for managed_policy_name in managed_policy_list]

        super(ManagedPolicyServiceRole, self).__init__(scope, id,
            assumed_by=aws_iam.ServicePrincipal(service),
            managed_policies=managed_policies, **kwargs)