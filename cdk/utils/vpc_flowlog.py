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
    aws_kms,
    aws_ec2,
)
from constructs import Construct
from utils.secure_log_group import SecureLogGroup
from utils.service_logs_role import ServiceLogsRole

class VpcFlowLog(aws_ec2.FlowLog):

    def __init__(self, scope: Construct, id: str, kms_key: aws_kms.Key, **kwargs) -> None:
    
        log_group = SecureLogGroup(scope, f"{id}LogGroup", kms_key=kms_key)
        log_role = ServiceLogsRole(scope, f"{id}ServiceLogsRole", log_group=log_group,
            service="vpc-flow-logs.amazonaws.com")

        super(VpcFlowLog, self).__init__(scope, id,
            traffic_type=aws_ec2.FlowLogTrafficType.REJECT,
            destination=aws_ec2.FlowLogDestination.to_cloud_watch_logs(log_group, log_role),
            **kwargs)