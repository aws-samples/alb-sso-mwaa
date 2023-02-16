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

from aws_cdk import (
    Stack,
    RemovalPolicy,
    CfnOutput,
    aws_cognito,
    aws_secretsmanager
)
from constructs import Construct
from cdk_nag import NagSuppressions

class CognitoOktaUserPool(aws_cognito.UserPool):

    OKTA_FEDERATE = "OKTA"

    def __init__(self, scope: Construct, id: str, 
        app_client: str, callback_urls: str, 
        logout_urls: str, identity_pool_name=None, 
        cognito_context=None, **kwargs) -> None:

        self.logger = logging.getLogger("cdk_cognito_userpool")
        logging.basicConfig(
            format='%(levelname)s:%(process)d:%(message)s',
            level=logging.INFO)
        
        NagSuppressions.add_stack_suppressions(scope,  
            [
                {
                    "id": "AwsSolutions-COG1",
                    "reason": "Federated Okta"
                },
                {
                    "id": "AwsSolutions-COG2",
                    "reason": "Federated Okta"
                },
                {
                    "id": "AwsSolutions-COG3",
                    "reason": "Federated Okta"
                }
            ],
            True
        )

        okta_context = cognito_context.get("Okta")

        user_pool_name = cognito_context.get("UserPoolName")
        self.logger.info(f"Cognito user pool name: {user_pool_name}")
        # Create user pool with default attribute of username
        super(CognitoOktaUserPool, self).__init__(scope, id, user_pool_name=user_pool_name, removal_policy=RemovalPolicy.DESTROY)

        # create cognito domain
        cognito_domain_prefix = cognito_context.get("DomainPrefix")
        if cognito_domain_prefix is not None:
            self.logger.info(f"Cognito domain prefix: {cognito_domain_prefix}")
            self.__user_pool_domain = self.add_domain("CognitoDomain",
                    cognito_domain=aws_cognito.CognitoDomainOptions(domain_prefix=cognito_domain_prefix))

            CfnOutput(scope, "UserPoolDomainUrl", value=f"{self.__user_pool_domain.base_url()}")
            CfnOutput(scope, "UserPoolDomainRedirectUrl", value=f"{self.__user_pool_domain.base_url()}/oauth2/idpresponse")

        okta_client_id = okta_context.get("ClientId")
        okta_oidc_issuer = okta_context.get("OidcIssuer")
        okta_client_secret_arn = okta_context.get("ClientSecretArn")

        if okta_client_id and okta_oidc_issuer and okta_client_secret_arn:
            client_secret = aws_secretsmanager.Secret.from_secret_complete_arn(self, "ClientSecretArn", okta_client_secret_arn)

            self.__idp_oidc = aws_cognito.UserPoolIdentityProviderOidc(scope, "{id}IdpOidc",
                client_id=okta_client_id,
                client_secret=client_secret.secret_value.unsafe_unwrap(),
                issuer_url=okta_oidc_issuer,
                user_pool=self,
                attribute_mapping=aws_cognito.AttributeMapping(
                        custom={
                            "sub": aws_cognito.ProviderAttribute.other("userName")
                        }), 
                attribute_request_method=aws_cognito.OidcAttributeRequestMethod.GET,
                scopes=["openid"], 
                name=self.OKTA_FEDERATE)
 
            self.__add_app_client(app_client=app_client, 
                callback_urls=callback_urls, logout_urls=logout_urls, 
                identity_pool_name=identity_pool_name)
        
        CfnOutput(scope, "UserPoolId", value=self.user_pool_id, export_name=f"{Stack.of(scope).stack_name}-UserPoolId")

    def __add_app_client(self, app_client=None,  callback_urls=None, logout_urls=None, identity_pool_name=None):
     
        if app_client and callback_urls and logout_urls:
            self.__user_pool_client = self.add_client(app_client,
                generate_secret=True,
                o_auth=aws_cognito.OAuthSettings(
                    flows=aws_cognito.OAuthFlows(authorization_code_grant=True),
                    scopes=[aws_cognito.OAuthScope.OPENID],
                    callback_urls=callback_urls.split(","),
                    logout_urls=logout_urls.split(",")),
                supported_identity_providers=[aws_cognito.UserPoolClientIdentityProvider.custom(self.OKTA_FEDERATE)])

            self.__user_pool_client.node.add_dependency(self.__idp_oidc)
            if identity_pool_name:
                cognito_identity_provider = aws_cognito.CfnIdentityPool.CognitoIdentityProviderProperty(
                    client_id=self.__user_pool_client.user_pool_client_id,
                    provider_name=self.user_pool_provider_name,
                    server_side_token_check=False)

                aws_cognito.CfnIdentityPool(self, "IdentityPool",
                    identity_pool_name=identity_pool_name,
                    cognito_identity_providers=[cognito_identity_provider],
                    allow_unauthenticated_identities=False)

        else:
            print(f"No app client: {app_client}, {callback_urls}, {logout_urls}, {identity_pool_name}")

    def get_user_pool_client(self):
        return self.__user_pool_client

    def get_user_pool_domain(self):
        return self.__user_pool_domain