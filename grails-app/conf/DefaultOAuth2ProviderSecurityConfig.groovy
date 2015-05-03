/* Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import grails.plugin.springsecurity.SecurityFilterPosition
import grails.plugin.springsecurity.oauthprovider.UserApprovalSupport

security {
	oauthProvider {
		active = true

		filterStartPosition = SecurityFilterPosition.X509_FILTER.order
		clientFilterStartPosition = SecurityFilterPosition.DIGEST_AUTH_FILTER.order

        exceptionTranslationFilterStartPosition = SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order
        registerExceptionTranslationFilter = true

        statelessFilterStartPosition = SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order
        registerStatelessFilter = true

        basicAuthenticationFilterStartPosition = SecurityFilterPosition.BASIC_AUTH_FILTER.order
        registerBasicAuthenticationFilter = true

        realmName = 'Grails OAuth2 Realm'
        credentialsCharset = 'UTF-8'

        tokenServices {
			registerTokenEnhancers = true
			accessTokenValiditySeconds = 60 * 60 * 12       // default 12 hours
			refreshTokenValiditySeconds = 60 * 60 * 24 * 30 // default 30 days
			reuseRefreshToken = false
			supportRefreshToken = true
		}

		authorizationEndpointUrl = "/oauth/authorize"
		tokenEndpointUrl = "/oauth/token"
		userApprovalEndpointUrl = "/oauth/confirm_access"
		userApprovalParameter = "user_oauth_approval"
        errorEndpointUrl = "/oauth/error"

        // Decides which grant types are enabled or not
		grantTypes {
			authorizationCode = true
			implicit = true
			refreshToken = true
			clientCredentials = true
			password = true
		}

        authorization {
            // Should the authorization endpoint allow unregistered redirect_uri
            // to be specified in request if client has none registered
            requireRegisteredRedirectUri = true

            // Should each request be required to include the scope param
            requireScope = true
        }

        approval {
            // When revoking approvals, should they be expired or deleted outright
            handleRevocationAsExpiry = false

            // Method of auto-approval support to use
            auto = UserApprovalSupport.EXPLICIT

            // How long are stored approvals valid
            approvalValiditySeconds = 60 * 60 * 24 * 30 // default 30 days

            // Request parameter prefix for scope approval
            scopePrefix = 'scope.'
        }

		defaultClientConfig {
			resourceIds = []
			authorizedGrantTypes = []
            scope = []
            autoApproveScopes = []
			registeredRedirectUri = null
			authorities = []
			accessTokenValiditySeconds = null
			refreshTokenValiditySeconds = null
            additionalInformation = [:]
		}

        authorizationCodeLookup {
            className = null
            authenticationPropertyName = 'authentication'
            codePropertyName = 'code'
        }

        accessTokenLookup {
            className = null
            authenticationKeyPropertyName = 'authenticationKey'
            authenticationPropertyName = 'authentication'
            usernamePropertyName = 'username'
            clientIdPropertyName = 'clientId'
            valuePropertyName = 'value'
            tokenTypePropertyName = 'tokenType'
            expirationPropertyName = 'expiration'
            refreshTokenPropertyName = 'refreshToken'
            scopePropertyName = 'scope'
            additionalInformationPropertyName = 'additionalInformation'
        }

        refreshTokenLookup {
            className = null
            authenticationPropertyName = 'authentication'
            valuePropertyName = 'value'
            expirationPropertyName = 'expiration'
        }

        clientLookup {
            className = null
            clientIdPropertyName = 'clientId'
            clientSecretPropertyName = 'clientSecret'
            accessTokenValiditySecondsPropertyName = 'accessTokenValiditySeconds'
            refreshTokenValiditySecondsPropertyName = 'refreshTokenValiditySeconds'
            authoritiesPropertyName = 'authorities'
            authorizedGrantTypesPropertyName = 'authorizedGrantTypes'
            resourceIdsPropertyName = 'resourceIds'
            scopesPropertyName = 'scopes'
            autoApproveScopesPropertyName = 'autoApproveScopes'
            redirectUrisPropertyName = 'redirectUris'
            additionalInformationPropertyName = 'additionalInformation'
        }

        approvalLookup {
            className = null
            usernamePropertyName = 'username'
            clientIdPropertyName = 'clientId'
            scopePropertyName = 'scope'
            approvedPropertyName = 'approved'
            expirationPropertyName = 'expiration'
            lastModifiedPropertyName = 'lastModified'
        }
	}
}