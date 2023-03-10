# Application load balancer single-sign-on for Amazon MWAA

## Overview

This solution enables OpenID Connect (OIDC) single-sign-on (SSO) authentication and authorization for accessing [Apache Airflow](https://airflow.apache.org/docs/apache-airflow/stable/index.html) UI across multiple [Amazon Managed Workflows for Apache Airflow (MWAA)](https://aws.amazon.com/managed-workflows-for-apache-airflow/) Environments. Although not required, this solution can also be used to provision target MWAA Environments with `PUBLIC_ONLY` and  `PRIVATE_ONLY` access. 

In the following sections, we describe the [solution architecture](#solution-architecture), [system](#system-perspective) and [user](#user-perspective) perspectives for understanding the solution, [prerequisites](#prerequisites), and [step-by-step tutorial](#step-by-step-tutorial) for deploying and using the solution.

## Solution architecture

The central component of the solution architecture is an [Application Load Balancer (ALB)](https://aws.amazon.com/elasticloadbalancing/application-load-balancer/) setup with a fully-qualified domain name (FQDN) and public (internet), or private access. The ALB provides SSO access to multiple MWAA Environments. 

The user-agent (web browser) call flow for accessing an Apache Airflow console in the target MWAA environment is as follows:

1. User-agent resolves ALB DNS domain name from DNS resolver. 
2. User-agent sends login request to the ALB path `/aws_mwaa/aws-console-sso` with the target MWAA Environment and the [Apache Airflow role based access control (RBAC) role](https://airflow.apache.org/docs/apache-airflow/stable/administration-and-deployment/security/access-control.html) in the query parameters `mwaa_env` and `rbac_role`, respectively.
3. ALB redirects the user-agent to the OIDC identity provider (Idp) authentication endpoint, and the user-agent authenticates with the OIDC Idp.
4. If user authentication is successful, the OIDC Idp redirects the user-agent to the configured ALB `redirect_url` with authorization `code` included in the redirect URL.
5. ALB uses the authorization `code` to get `access_token` and OpenID JWT token with `"openid email"` scope from the OIDC Idp, and forwards the login request to the MWAA Authenticator Lambda target with the JWT token included in the request header `x-amzn-oidc-data`.
6.  MWAA Authenticator Lambda verifies the JWT token in the request header using ALB public keys, and [authorizes](#add-authorization-records-to-dynamodb-table) the authenticated user for the requested `mwaa_env` and `rbac_role` using a DynamoDB table. The use of DynamoDB for authorization is optional, and the [Lambda code](cdk/mwaa_authx_lambda_code/mwaa_authx.py) function `is_allowed` can be adapted to use other authorization mechanisms.
7. MWAA Authenticator Lambda redirects the user-agent to the Apache Airflow console in the requested MWAA Environment with `login` token included in the `redirect` URL.


This solution architecture assumes that the user-agent has network reachability to the AWS Application Load Balancer and Apache Airflow console endpoints used in this solution. If the endpoints are public, then reachability is over the internet, otherwise, the network reachability is assumed via an [AWS Direct Connect](https://aws.amazon.com/directconnect/), or [AWS Client VPN](https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/what-is.html).

The solution architecture diagram with numbered call flow sequence for internet network reachability is shown below:

![Internet Solution architecture](images/mwaa-sso-public-call-flow.png)

The solution architecture diagram for AWS Client VPN network reachability is shown below:

![VPN Solution architecture](images/mwaa-sso-private-call-flow.png)

**NOTE: This solution does not setup up AWS Client VPN.**

## System perspective

The system perspective is useful for building and deploying this solution. This solution comprises of three core CloudFormation stacks defined using AWS CDK: 

* CustomerVpc
* MwaaAuthxLambda
* CustomerAlb

Besides the core stacks, this solution supports building MWAA Environment stacks. For each MWAA Environment you want to use in this solution, you must add a dictionary entry in the  `MwaaEnvironments` array in [cdk.context.json](cdk/cdk.context.json). If the array entry contains *only* the `Name` key, this solution assumes such an MWAA Environment is being managed outside this solution, otherwise, two *logical stacks per MWAA Environment* are created in this solution:

* MwaaVpc
* MwaaEnvironment

The [cdk.context.json](cdk/cdk.context.json) file included in this project is configured to create two new MWAA Environments: `Env1` with `PUBLIC_ONLY` access, and `Env2` with `PRIVATE_ONLY` access, which means following CloudFormation stacks are defined in this solution, in addition to the core stacks:

* MwaaVpcEnv1
* MwaaEnvironmentEnv1
* MwaaVpcEnv2
* MwaaEnvironmentEnv2

## User perspective

The user perspective is useful for understanding how to access a target MWAA Environment assuming a specific Airflow RBAC role.

### MWAA Airflow console login and logout

For `login` into Apache Airflow console in the target MWAA Environment assuming a specific Apache Airflow RBAC role, we use following URL:

```
https://FQDN/aws_mwaa/aws-console-sso?mwaa_env=<MWAA-Environment-Name>&rbac_role=<Rbac-role-name>
```

For logout from an Apache Airflow console, we use the normal console logout. 

### SSO Logout

For SSO logout from ALB, we use following URL:

```
https://FQDN/logout
```

## Prerequisites

Before we can deploy this solution, we need to complete following prerequisites:

1. [AWS account access](#aws-account-access)
2. [CDK Build machine](#cdk-build-machine)
3. [DNS domain](#dns-domain)
4. [Fully-qualified-domain (FQDN) name](#fqdn-for-alb)
5. [SSL certificate](#ssl-certificate)
6. [Open Id connect (OIDC) identity provider](#oidc-idp)
7. [Service linked role for EC2 auto-scaling](#service-linked-role-for-ec2-auto-scaling)
8. [MWAA Environment source bucket](#mwaa-environment-source-bucket)
9. [Application load balancer (ALB) access logging bucket](#application-load-balancer-alb-access-logging-bucket)

### AWS account access

First, you need an AWS account. If needed, [create an AWS account](https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-creating.html). This solution assumes you have [system administrator job function](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html) access to the AWS Management Console.

### CDK build machine

Next, you need a build machine. This solution uses [AWS CDK](https://aws.amazon.com/cdk/) to build the required stacks. You may use any machine with NodeJS, Python, [Docker](https://www.docker.com/) and [AWS CDK for Typescript](https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html) installed as your build machine.  If you are new to AWS CDK, we recommend launching a fully-configured build machine in your target AWS region, as described below:

* Select your [AWS Region](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html). The AWS Regions supported by this solution include, us-east-1, us-east-2, us-west-2, eu-west-1, eu-central-1, ap-southeast-1, ap-southeast-2, ap-northeast-1, ap-northeast-2, and ap-south-1. 
* Subscribe to [Ubuntu Pro 22.04 LTS](https://aws.amazon.com/marketplace/pp/prodview-uy7jg4dds3qjw).
* If you do not already have an Amazon EC2 key pair, [create a new Amazon EC2 key pair](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#prepare-key-pair). You need the key pair name to specify the `KeyName` parameter when creating the AWS CloudFormation stack below. 
* Use the [public internet address](http://checkip.amazonaws.com/) of your laptop as the base value for the [CIDR](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html) to specify `SecurityGroupAccessCIDR` parameter in the CloudFormation template used below.  
* Using AWS Management console, create the build machine using [`cfn/ubuntu-developer-machine.yaml`](cfn/ubuntu-developer-machine.yaml) [AWS CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html) template. This template creates [AWS Identity and Access Management (IAM)](https://aws.amazon.com/iam/) resources, so when you [create the CloudFormation Stack using the console](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stack.html), in the **Review** step, you must check 
**I acknowledge that AWS CloudFormation might create IAM resources.**  
* Once the stack status in CloudFormation console is `CREATE_COMPLETE`, find the EC2 instance launched in your stack in the Amazon EC2 console, and [connect to the instance using SSH](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AccessingInstancesLinux.html) as user `ubuntu`, using your SSH key pair.
* When you connect to the instance using SSH, if you see the message `"Cloud init in progress."`, disconnect and try later after about 10 minutes. If you see the message `AWS developer machine is ready!`, your build machine is ready.

### DNS domain

Next, you need a DNS domain. You can use an existing DNS domain that you can administer, or create a new DNS domain using any DNS domain provider, e.g. [Amazon Route 53](https://aws.amazon.com/route53/).

### FQDN for ALB

As noted at the outset, the central component of this solution is an ALB. The ALB in this solution only supports HTTPS traffic. This means we need to create an [SSL certificate](#ssl-certificate), which requires us to first select a fully-qualified domain name (FQDN). For example, if your DNS domain is `example.com`, you may select a FQDN `alb-sso-mwaa.example.com`. 

You will need the FQDN for ALB while creating the [SSL Certificate](#ssl-certificate), and for [configuring a user-friendly alias](#post-deployment-configuration) for the ALB, once the ALB is created in the [step-by-step tutorial](#step-by-step-tutorial).

### SSL certificate

[Request an SSL certificate](https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-public.html) for the FQDN selected above. Later, you will set the [Amazon Resource Name (ARN)](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html) of the SSL certificate in `Alb` CDK context variable `CertificateArn` in [cdk.context.json](cdk/cdk.context.json) while configuring the [ALB stack](#customeralb-stack) in the [step-by-step tutorial](#step-by-step-tutorial).

### OIDC Idp

This solution requires configuration of an application client in an OIDC Idp. You must configure the application client in your OIDC Idp with a Client Secret. 

You must create an [AWS Secrets Manager secret](https://docs.aws.amazon.com/secretsmanager/latest/userguide/create_secret.html) to store your Client Secret in plain-text format (not JSON). Later, you will set the secret's ARN in `Oidc` context variable `ClientSecretArn` in [cdk.context.json](cdk/cdk.context.json) while configuring the [ALB stack](#customeralb-stack) in the [step-by-step tutorial](#step-by-step-tutorial).

The OIDC Idp must support scope of `"openid email"`. The `redirect_url` and `logout_url` for your OIDC Idp must be set to `https://FQDN/oauth2/idpresponse` and `https://FQDN/logout`, respectively.

### Service linked role for EC2 auto scaling

[Create a service linked role for EC2 auto scaling](https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-service-linked-role.html#create-service-linked-role). Later, you will set the ARN for this role in CDK context variable `AWSServiceRoleForAutoScalingArn` in [cdk.context.json](cdk/cdk.context.json) while configuring various VPC related stacks in the [step-by-step tutorial](#step-by-step-tutorial).

### MWAA Environment source bucket

If you plan to use this solution to automatically create MWAA Environments, create or use an existing Amazon S3 bucket with versioning enabled. Later, you will use the S3 bucket ARN in CDK context variable `SourceBucketArn` in various `MWAAEnvironments` array entries in [cdk.context.json](cdk/cdk.context.json) while configuring various MWAA Environment related stacks in the [step-by-step tutorial](#step-by-step-tutorial).

At this time, copy [requirements-mwaa.txt](cdk/requirements-mwaa.txt) to the `SourceBucketArn` bucket to the bucket path `mwaa/requirements-mwaa.txt`. Note the object version of the object you just copied and later use it in `RequirementsS3ObjectVersion` in various `MWAAEnvironments` array entries in [cdk.context.json](cdk/cdk.context.json) while configuring various MWAA Environment related stacks in the [step-by-step tutorial](#step-by-step-tutorial).

### Application load balancer (ALB) access logging bucket

Create or use an existing Amazon S3 bucket. Later you will use the S3 bucket ARN in `Alb`  CDK context variable `LogBucketArn` in [cdk.context.json](cdk/cdk.context.json) while configuring the [ALB stack](#customeralb-stack) in the [step-by-step tutorial](#step-by-step-tutorial). 

The access logging bucket must have [access logging bucket policy](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html#attach-bucket-policy) attached to it. An example access logging bucket policy for AWS Region `us-west-2` is shown below:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::797873946194:root"
            },
            "Action": "s3:PutObject",
            "Resource": "<your-s3-bucket-ARN>/customer-alb/AWSLogs/<your-AWS-account-id>/*"
        }
    ]
}
```

The `797873946194` above refers to the AWS account id for AWS load-balancing service running in `us-west-2`, and this value for other AWS regions can be found [here](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html#attach-bucket-policy).

## Step-by-step tutorial

To deploy the AWS CDK stacks in this solution, clone this github repository on your *build machine*. In the root directory of the cloned repository, execute following commands:

    python -m virtualenv .venv
    source ./.venv/bin/activate
    cd ./cdk
    pip install -r requirements-dev.txt
    
Below we describe the steps required to deploy this solution.

### Configure CDK context

Below we describe how to configure the CDK context for following stacks:

1. [Customer VPC stack](#customervpc-stack)
2. [MwaaAuthxLambda stack](#mwaaauthxlambda-stack)
3. [MwaaVpc stack](#mwaavpc-stack)
4. [MwaaEnvironment stack](#mwaaenvironment-stack)
5. [CustomerAlb stack](#customeralb-stack)

#### CustomerVpc stack

The `CustomerVpc` stack creates a secure VPC with private and public subnets for running an Application Load Balancer (ALB) that provides the user access endpoint. 

The public subnets have direct access to the Internet. The private subnets have outbound access to the Internet via a NAT Gateway. VPC is connected to the relevant AWS services using VPC endpoints. VPC Flow Logs are enabled. 

An example `CustomerVpc` CDK context defined in [cdk.context.json](cdk/cdk.context.json) is shown below:

    "CustomerVpc": {
        "AWSServiceRoleForAutoScalingArn": "...",
        "VpcCIDR": "192.168.0.0/16",
        "MaxAZs": 2,
        "NatGateways": 1,
        "PublicSubnetMask": 24,
        "PrivateSubnetMask": 18
    }

You are free to change the `CustomerVpc` context, as needed. 

**NOTE:** The `VpcCIDR `of the `CustomerVpc` must not overlap with the VPC of any MWAA Environment with `PRIVATE_ONLY` access. This is because, for this solution to work, we need to establish VPC peering connection and subnet routes between the `CustomerVpc` and the VPC of an MWAA Environment with `PRIVATE_ONLY` access. 

If the MWAA VPC is created by this solution, the required VPC peering connection and subnet routes are automatically configured. If you are directly managing an MWAA Environment with `PRIVATE_ONLY` access and want to access such an MWAA Environment through this solution, you must create VPC peering connection and subnet routes between `CustomerVpc` and your MWAA VPC.

#### MwaaAuthxLambda stack

This stack deploys the Lambda function used for authorization. The authorization function enables access to the various MWAA Environments' Apache Airflow UI consoles. 

This stack creates an Amazon DynamoDB table used for mapping users and MWAA Environments to allowed [Apache Airflow RBAC roles](https://airflow.apache.org/docs/apache-airflow/stable/security/access-control.html).

The CDK `Alb` context variable `SessionCookieName` defined in [cdk.context.json](cdk/cdk.context.json) is used by this stack. 

#### MwaaVpc stack

The `MwaaVpc` stack creates a secure VPC with private and public subnets for running an MWAA Environment. 

The public subnets have direct access to the Internet. The private subnets have outbound access to the Internet via a NAT Gateway. VPC is connected to the relevant AWS services using VPC endpoints. VPC Flow Logs are enabled. 

The CDK context for each `MwaaVpc` is defined in each `MwaaEnvironments` array entry, as shown in the example below for two MWAA Environments named `Env1` and `Env2`, respectively:

    "MwaaEnvironments": [
        {
            "Name": "Env1",
                ...
            "AWSServiceRoleForAutoScalingArn": "...",
            "VpcCIDR": "172.30.0.0/16",
            "MaxAZs": 2,
            "NatGateways": 1,
            "PublicSubnetMask": 24,
            "PrivateSubnetMask": 18
        },
        {
            "Name": "Env2",
                ...
            "AWSServiceRoleForAutoScalingArn": "...",
            "VpcCIDR": "172.16.0.0/16",
            "MaxAZs": 2,
            "NatGateways": 1,
            "PublicSubnetMask": 24,
            "PrivateSubnetMask": 18
        }
    ],

**NOTE:** The `VpcCIDR `of the `MwaaVpc` must not overlap with the `CustomerVpc` if the Environment has `PRIVATE_ONLY` access. This is because for this solution to work, we need to establish VPC peering connection and subnet routes between the `CustomerVpc` and the VPC of any MWAA Environment with `PRIVATE_ONLY` access.

#### MwaaEnvironment stack

Each `MwaaEnvironment` stack depends on the corresponding `MwaaVpc` stack. The CDK context for each `MwaaEnvironment` stack is defined in `MwaaEnvironments` array entry, as shown in the example below for two MWAA Environments named `Env1` and `Env2`, respectively:

    "MwaaEnvironments": [
        {
            "Name": "Env1",
            "EnvironmentClass": "mw1.large",
            "SourceBucketArn": "...",
            "DagsS3Path": "dags",
            "RequirementsS3Path": "mwaa/requirements-mwaa.txt",
            "RequirementsS3ObjectVersion": "...",
            "MinWorkers": 2,
            "MaxWorkers": 16,
            "Schedulers": 2,
            "DagProcessingLogsLevel": "INFO",
            "SchedulerLogsLevel": "INFO",
            "TaskLogsLevel": "INFO",
            "WorkerLogsLevel": "INFO",
            "WebserverLogsLevel": "INFO",
            "WebServerAccessMode": "PUBLIC_ONLY",
            "ConfigurationOptions": {
                "core.dag_run_conf_overrides_params": "True"
            },
            ...
        },
        {
            "Name": "Env2",
            "EnvironmentClass": "mw1.large",
            "SourceBucketArn": "...",
            "DagsS3Path": "dags",
            "RequirementsS3Path": "mwaa/requirements-mwaa.txt",
            "RequirementsS3ObjectVersion": "...",
            "MinWorkers": 2,
            "MaxWorkers": 16,
            "Schedulers": 2,
            "DagProcessingLogsLevel": "INFO",
            "SchedulerLogsLevel": "INFO",
            "TaskLogsLevel": "INFO",
            "WorkerLogsLevel": "INFO",
            "WebserverLogsLevel": "INFO",
            "WebServerAccessMode": "PRIVATE_ONLY",
            "ConfigurationOptions": {
                "core.dag_run_conf_overrides_params": "True"
            },
            ...
        }
    ]

`SourceBucketArn` must point to an existing S3 bucket, and `DagsS3Path` and `RequirementsS3Path` must be valid for your bucket. 

#### CustomerAlb stack

The `CustomerAlb` stack defines the following:

* Application load balancer (ALB) used for OIDC SSO authentication
* Authorization Lambda ALB target
* HTTPS listener
* Vpc peering connection and subnet Routes between `CustomerVpc` *private subnets*, and each MWAA Environment's VPC with `PRIVATE_ONLY` access. This is done only for MWAA Environments managed by this solution.

The CDK context for the `CustomerAlb` stack is defined in `Oidc` and `Alb` contexts in [cdk.context.json](cdk/cdk.context.json). The `Oidc` context specifies the configuration of your OIDC Idp. For example, for [Okta OIDC Idp](https://developer.okta.com/signup/), the configuration would be similar to shown below:

    "Oidc": {
        "ClientId": "...",
        "ClientSecretArn": "...",
        "Issuer": "https://xxx.okta.com/oauth2/default",
        "AuthorizationEndpoint":"https://xxx.okta.com/oauth2/default/v1/authorize",
        "TokenEndpoint":"https://xxx.okta.com/oauth2/default/v1/token",
        "UserInfoEndpoint":"https://xxx.okta.com/oauth2/default/v1/userinfo"
    },


The ALB may be internet facing, or private. By default, the **ALB is private**. Set `InternetFacing` to `true` below for internet facing ALB:

    "Alb": {
        "InternetFacing": false,
        "SessionCookieName": "AWSELBAuthSessionCookie",
        "LogBucketArn": "...",
        "LogBucketPrefix": "customer-alb",
        "CertificateArn": "..."
    },

### Deploy CDK stacks

If you have never [bootstrapped CDK](https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html) in your selected AWS region, run following command:

    cdk bootstrap

To list the stacks described above, execute following commands:

    cdk list

If the command is successful, you should see stack list *similar* to the example below (your stack list may be different based on your configuration):

* CustomerVpc
* MwaaVpcEnv1
* MwaaVpcEnv2
* MwaaAuthxLambda
* MwaaEnvironmentEnv1
* MwaaEnvironmentEnv2
* CustomerAlb

To interactively deploy all the available CDK stacks, execute:

    cdk deploy --all

To deploy the stacks one at a time, execute following commands in sequence:

    cdk deploy CustomerVpc
    cdk deploy MwaaVpcEnv1
    cdk deploy MwaaVpcEnv2
    cdk deploy MwaaAuthxLambda
    cdk deploy MwaaEnvironmentEnv1
    cdk deploy MwaaEnvironmentEnv2
    cdk deploy CustomerAlb

### Post deployment configuration

#### Configure Vpc peering and subnet routes for external PRIVATE_ONLY MWAA Environments

If you are externally managing an MWAA Environment with `PRIVATE_ONLY` access and want to access such an MWAA Environment through this solution, you must create VPC peering connection and subnet routes between `CustomerVpc` and your MWAA VPC.

#### Add ALB CNAME record in your Route 53 DNS domain

In your Route 53 DNS domain, add a [CNAME record](https://aws.amazon.com/premiumsupport/knowledge-center/route-53-create-alias-records/) for the ALB DNS name, which is available in the CDK output as `CustomerAlb.AlbDnsName`.

#### Add authorization records to DynamoDB table

In the DynamoDB table created in `MwaaAuthxLambda` stack, add entry for each user's email, MWAA Environment name, and allowed [Apache Airflow RBAC roles](https://airflow.apache.org/docs/apache-airflow/stable/security/access-control.html). 

For example, your Amazon DynamoDB table may look as below:

| email | mwaa_env | rbac_roles |
|-------|----------|------------|
| user1@example.com | Env1 | All |
| user1@example.com | Env2 | Viewer |
| user2@example.com | Env1 | User Viewer |
| user2@example.com | Env2 | User Public Op |

Valid values for `rbac_roles` column are  `Admin`, `User`, `Viewer`, `Op`, and `Public`. Multiple values in the `rbac_roles` column can be space-separated. The value `All` in `rbac_roles` means all RBAC roles are allowed.

#### Configure network connectivity to ALB and PRIVATE_ONLY MWAA Environments

If the `Alb` CDK context variable `InternetFacing` is set to `false` in [cdk.context.json](cdk/cdk.context.json) , configure network connectivity from your user-agent to the private ALB endpoint resolved by your DNS domain. Also, you must configure network connectivity from your user-agent to the Apache Airflow console in your target `PRIVATE_ONLY` access MWAA Environments. This can be done using [AWS Direct Connect](https://aws.amazon.com/directconnect/), or [AWS Client VPN](https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/what-is.html). This solution does not setup AWS Direct Connect, or AWS Client VPN.

### Login into MWAA Airflow console

Assuming your ALB FQDN is `alb-sso-mwaa.example.com`, you can login into your target MWAA Environment, e.g. `Env1`, assuming a specific Apache Airflow RBAC role, e.g. `Admin`, using the following URL:

```
https://alb-sso-mwaa.example.com/aws_mwaa/aws-console-sso?mwaa_env=Env1&rbac_role=Admin
```

Allowed values for `mwaa_env` query parameter above are the available MWAA environments configured with this solution. Allowed values for `rbac_role` query parameter above are  `Admin`, `User`, `Viewer`, `Op`, and `Public`. 


### Logout from MWAA Airflow console

For logout from an Apache Airflow Console, use the normal Airflow console logout. 

### Logout from ALB

Assuming your ALB FQDN is `alb-sso-mwaa.example.com`, logout from ALB using the following URL:

```
https://alb-sso-mwaa.example.com/logout
```

### Update CDK stacks

To interactively update the deployed stacks, make the configuration changes in [cdk.context.json](cdk/cdk.context.json) and run:

    cdk deploy --all

For some types of updates, you may need to destroy and redeploy at least some of the stacks.

### Destroy CDK stacks

To interactively destroy all the deployed stacks, execute:

    cdk destroy --all

To destroy the stacks one at a time, execute following commands in sequence:

    cdk destroy CustomerAlb
    cdk destroy MwaaEnvironmentEnv2
    cdk destroy MwaaEnvironmentEnv1
    cdk destroy MwaaAuthxLambda
    cdk destroy MwaaVpcEnv2
    cdk destroy MwaaVpcEnv1
    cdk destroy CustomerVpc

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) and [CODE OF CONDUCT](CODE_OF_CONDUCT.md) for more information.

## License

This solution is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.