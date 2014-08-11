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

security {
	oauthProvider {
		active = true
		filterStartPosition = SecurityFilterPosition.X509_FILTER.order
		clientFilterStartPosition = SecurityFilterPosition.DIGEST_AUTH_FILTER.order

        realmName = 'Grails OAuth2 Realm'

        // Configuration for the token endpoint's filter chain
        tokenEndpointFilterChain {
            // Defines the URL pattern for the filter chain to "inherit" as the base
            baseUrlPattern = '/**'
            // Should the stateless filter be injected
            disabled = false
        }

		tokenServices {
			accessTokenValiditySeconds = 60 * 60 * 12 //default 12 hours
			refreshTokenValiditySeconds = 60 * 10 //default 10 minutes
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

		defaultClientConfig {
			resourceIds = []
			authorizedGrantTypes = []
			scope = []
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
        }

        refreshTokenLookup {
            className = null
            authenticationPropertyName = 'authentication'
            valuePropertyName = 'value'
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
            redirectUrisPropertyName = 'redirectUris'
            additionalInformationPropertyName = 'additionalInformation'
        }
	}
}