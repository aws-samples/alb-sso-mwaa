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

import os
import json
import base64
import logging
import requests
import jwt
import boto3
from uuid import uuid4
from datetime import timezone, datetime
import re


sts = boto3.client('sts')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

PUBLIC_KEY_ENDPOINT = os.getenv('PUBLIC_KEY_ENDPOINT')
ALB_COOKIE_NAME = os.getenv('ALB_COOKIE_NAME','AWSELBAuthSessionCookie').strip()
AWS_REGION = os.getenv("AWS_REGION")

logger.info(PUBLIC_KEY_ENDPOINT)
logger.info(ALB_COOKIE_NAME)
logger.info(AWS_REGION)

def lambda_handler(event, context):
    """
    Lambda handler
    """
    logger.info(str(event))
    
    path = event['path']
    query_params = event.get("multiValueQueryStringParameters")
    user_claims = None
    headers = event['multiValueHeaders']
    if 'x-amzn-oidc-data' in headers:
        encoded_jwt = headers['x-amzn-oidc-data'][0]
        user_claims = get_jwt_claims(encoded_jwt)
    
        if path == '/aws_mwaa/aws-console-sso' and "rbac_role" in query_params and "mwaa_env" in query_params:
            redirect = login(headers=headers, query_params=query_params, user_claims=user_claims)
        else:
            redirect = close(headers, f"Bad request: {path}, {query_params}, {headers}", status_code=400)
    elif path == '/logout':
            redirect = logout(headers=headers, query_params=query_params)
    else:
        redirect = close(headers, f"Bad request: {path}, {query_params}, {headers}", status_code=400)

    if not redirect:
        redirect = close(headers, f"Runtime error", status_code=500)

    return redirect

def multivalue_to_singlevalue(headers):
    """
    Convert multi-value headers to single value
    """
    svheaders = {key: value[0] for (key, value) in
    headers.items()}
    return svheaders

def singlevalue_to_multivalue(headers):
    """
    Convert single value headers to multi-value headers
    """
    mvheaders = {key: [value] for (key, value) in
    headers.items()}
    return mvheaders

def is_allowed(email=None, rbac_role=None, mwaa_env=None):
    allowed = False
    try:
        rbac_role = rbac_role.lower()
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(os.environ['PERMISSIONS_TABLE'])
        response = table.get_item(Key={'email': email, "mwaa_env": mwaa_env})
        item = response['Item']
        rbac_roles = item['rbac_roles'].lower()
        allowed = rbac_role in rbac_roles or rbac_roles == "all"
        logger.info(f"checking {rbac_role} is in {rbac_roles}: {allowed}")
    except Exception as error:
        logger.error(str(error))

    return allowed


def logout(headers, query_params):
    """
    Function that returns a redirection to an appropriate
    URL that includes a web login token.
    """
    retval = ""

    try:
        alb_cookie_name = os.getenv("ALB_COOKIE_NAME", "AWSELBAuthSessionCookie")
        cookie = headers.get('cookie')
        if cookie:
            m=re.search(f"{alb_cookie_name}[^=]*", cookie[0])
            alb_cookie_name = m.group(0) if m else alb_cookie_name

            time_now = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
            headers['Set-Cookie'] = [ f"{alb_cookie_name}=deleted;Expires={time_now};Path=/", f"{alb_cookie_name}=deleted;Expires={time_now};Path=/" ]
            retval = close(headers, "Logout OK", status_code=200)
        else:
            retval = close(headers, "Logout failed", status_code=400)
    except Exception as error:
        logger.error(str(error))
        retval = close(headers, "Logout failed", status_code=500)
      
        
    return retval

def login(headers, query_params=None, user_claims=None):
    """
    Function that returns a redirection to an appropriate
    URL that includes a web login token.
    """
    redirect = ""

    try:
        # 'RBAC Role 'is in the request query param 'rbac_role'
        rbac_role_name = query_params.get("rbac_role")[0].upper()
        role_arn = os.getenv(f"RBAC_{rbac_role_name}_ROLE_ARN")
        logger.info(f"Rbac role name: {rbac_role_name}, role_arn: {role_arn}")
        email = user_claims.get('email', "") if user_claims else ""
        mwaa_env_name = query_params.get("mwaa_env")[0]
        if not is_allowed(email=email, rbac_role=rbac_role_name, mwaa_env=mwaa_env_name):
            return close(headers=headers, message=f"Not authorized: {mwaa_env_name}: {rbac_role_name}", status_code=403)

        mwaa = get_mwaa_client(role_arn)
        
        logger.info(f"Create Airflow web login token for environment: '{mwaa_env_name}'")
        if mwaa_env_name:
            response = mwaa.create_web_login_token(Name=mwaa_env_name)
            logger.info(str(response))
            mwaa_web_token = response.get("WebToken")
            host = response.get("WebServerHostname")
            logger.info('Redirecting with Amazon MWAA WebToken')
            redirect = {
                'statusCode': 302,
                'statusDescription': '302 Found',
                'multiValueHeaders': {
                    'Location':[f'https://{host}/aws_mwaa/aws-console-sso?login=true#{mwaa_web_token}']
                }
            }
        logger.info(f"Redirect: '{redirect}'")
    except Exception as error:
        logger.error(str(error))
        
    return redirect

def get_mwaa_client(role_arn):
    """
    Returns an Amazon MWAA client under the given IAM
    role
    """
    mwaa = None
    try:
        logger.info(f'Assuming role "{role_arn}"')
        response = sts.assume_role(RoleArn=role_arn, RoleSessionName=str(uuid4()), DurationSeconds=900)
        logger.info(str(response))
        credentials = response.get('Credentials')
  
        # create service client using the assumed role credentials, e.g. S3
        mwaa = boto3.client(
            'mwaa',
            aws_access_key_id=credentials.get('AccessKeyId'),
            aws_secret_access_key=credentials.get('SecretAccessKey'),
            aws_session_token=credentials.get('SessionToken'),
            region_name = AWS_REGION)
    except Exception as error:
        logger.error(str(error))
    return mwaa

def get_jwt_claims(encoded_jwt):
    payload = None
    try:
        jwt_fields = encoded_jwt.split('.')

        jwt_headers = jwt_fields[0]
        decoded_jwt_headers = base64.b64decode(jwt_headers)
        decoded_jwt_headers = decoded_jwt_headers.decode("utf-8")
        headers = json.loads(decoded_jwt_headers)
        logger.info(str(headers))

        # Step 2: Get the public key from regional endpoint
        kid = headers.get('kid')
        if PUBLIC_KEY_ENDPOINT[-1] == "/":
            url = f"{PUBLIC_KEY_ENDPOINT}{kid}"
        else:
            url = f"{PUBLIC_KEY_ENDPOINT}/{kid}"

        logger.info(f"Public key url: {url}")
        req = requests.get(url)
        pub_key = req.text
        logger.info(f"Public key: {pub_key}")

        # Step 3: Get the payload
        payload = jwt.decode(encoded_jwt, pub_key, algorithms=['ES256'])
        logger.info(str(payload))
    except Exception as error:
        logger.error(error)

    return payload

def close(headers, message, status_code=200):
    body = f'<html><body><h3>{message}</h3></body></html>'
    headers['Content-Type'] = ['text/html']
    return {
        'statusCode': status_code,
        'multiValueHeaders': headers,
        'body': body,
        'isBase64Encoded': False
    }
