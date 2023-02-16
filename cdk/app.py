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

import logging

import aws_cdk
from aws_cdk import Aws
from cdk_nag import AwsSolutionsChecks
from mwaa_vpc_stack.vpc_stack import MwaaVpcStack
from mwaa_stacks.mwaa_stack import MwaaStack
from customer_vpc_stack.vpc_stack import CustomerVpcStack
from mwaa_authx_lambda_stack.lambda_stack import MwaaAuthxLambdaStack
from customer_alb_stack.alb_stack import CustomerAlbStack
import os

logger = logging.getLogger("mars_app")
logging.basicConfig(format='%(levelname)s:%(process)d:%(message)s',
            level=logging.INFO)

app = aws_cdk.App()
aws_cdk.Aspects.of(app).add(AwsSolutionsChecks())

app_name = app.node.try_get_context("AppName")
env=aws_cdk.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION'))

customer_vpc_stack = CustomerVpcStack(app, "CustomerVpc", 
    stack_name = f"{app_name}-CustomerVpc", env=env)
mwaa_lambda_authx_stack = MwaaAuthxLambdaStack(app, "MwaaAuthxLambda", 
    vpc=customer_vpc_stack.get_vpc(), 
    stack_name = f"{app_name}-MwaaAuthxLambda", env=env)

mwaa_envs_context = app.node.try_get_context("MwaaEnvironments")

mwaa_private_access = dict()
for mwaa_env_context in mwaa_envs_context:
    if len(mwaa_env_context) == 1:
        continue

    mwaa_env_name = mwaa_env_context.get("Name")
    mwaa_vpc_stack = MwaaVpcStack(app, f"MwaaVpc{mwaa_env_name}", 
        vpc_context=mwaa_env_context,
        stack_name = f"{app_name}-MwaaVpc-{mwaa_env_name}", env=env)
   
    mwaa_stack = MwaaStack(app, f"MwaaEnvironment{mwaa_env_name}", 
        vpc=mwaa_vpc_stack.get_vpc(), 
        environment_name=mwaa_env_name, 
        mwaa_env_context = mwaa_env_context,
        stack_name = f"{app_name}-MwaaEnvironment-{mwaa_env_name}", env=env)

    mwaa_access_mode = mwaa_env_context.get("WebServerAccessMode")
    if mwaa_access_mode == "PRIVATE_ONLY":
         mwaa_private_access[mwaa_env_name] = mwaa_vpc_stack.get_vpc()

alb_stack = CustomerAlbStack(app, "CustomerAlb", vpc=customer_vpc_stack.get_vpc(),
    function = mwaa_lambda_authx_stack.get_function(),
    mwaa_private_access = mwaa_private_access,
    stack_name = f"{app_name}-CustomerAlb", env=env)

app.synth()
