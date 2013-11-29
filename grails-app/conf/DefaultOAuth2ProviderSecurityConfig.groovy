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

		tokenServices {
			accessTokenValiditySeconds = 60 * 60 * 12 //default 12 hours
			refreshTokenValiditySeconds = 60 * 10 //default 10 minutes
			reuseRefreshToken = true
			supportRefreshToken = true
		}
		authorizationEndpointUrl = "/oauth/authorize"
		tokenEndpointUrl = "/oauth/token"
		userApprovalEndpointUrl = "/oauth/confirm"
		userApprovalParameter = "user_oauth_approval"
		
		// Decides which grant types are enabled or not
		grantTypes {
			authorizationCode = true
			implicit = true
			refreshToken = true
			clientCredentials = true
			password = true
		}
		defaultClientConfig {
			resourceIds = []
			authorizedGrantTypes = ["authorization_code", "refresh_token"]
			scope = []
			registeredRedirectUri = null
			authorities = []
			accessTokenValiditySeconds = null
			refreshTokenValiditySeconds = null
		}
		clients = []
	}
}

environments {
	test {
		security.oauthProvider.active = false
	}
}