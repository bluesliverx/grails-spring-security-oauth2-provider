/* Copyright 2006-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityFilterPosition
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService
import org.springframework.security.oauth2.common.DefaultThrowableAnalyzer
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices

import org.springframework.security.oauth2.provider.BaseClientDetails
import org.springframework.security.oauth2.provider.InMemoryClientDetailsService
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore
import org.springframework.security.oauth2.provider.token.RandomValueTokenServices
import org.springframework.security.oauth2.provider.filter.OAuth2ExceptionHandlerFilter
import org.springframework.security.oauth2.provider.filter.OAuth2ProtectedResourceFilter

class SpringSecurityOauth2ProviderGrailsPlugin {
	def version = "1.0.0.M5-SNAPSHOT"
	String grailsVersion = '1.2.2 > *'
	
	List pluginExcludes = [
		'docs/**',
		'src/docs/**',
		// Domains
		'test/**',
		// Controllers
		'grails-app/controllers/**',
		'grails-app/domain/**',
		'grails-app/i18n/**',
		// Views
		'web-app/**',
		'grails-app/views/login/**',
		'grails-app/views/secured/**',
		'grails-app/views/index.gsp',
	]

	//Map dependsOn = [springSecurityCore: '1.0 > *']
	def loadAfter = ["springSecurityCore"]

	def license = "APACHE"
	def organization = [ name:"Adaptive Computing", url:"http://adaptivecomputing.com" ]
	def issueManagement = [ system:"GitHub", url:"http://github.com/adaptivecomputing/grails-spring-security-oauth2-provider/issues" ]
	def scm = [ url:"http://github.com/adaptivecomputing/grails-spring-security-oauth2-provider" ]

	String author = 'Brian Saville'
	String authorEmail = 'bsaville@adaptivecomputing.com'
	String title = 'OAuth2 Provider support for the Spring Security plugin.'
	String description = '''\
OAuth2 Provider support for the Spring Security plugin.  Based on Burt Beckwith\'s OAuth 1 Provider plugin
'''

	String documentation = 'http://grails.org/plugin/spring-security-oauth2-provider'

	def doWithSpring = {

		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		SpringSecurityUtils.loadSecondaryConfig 'DefaultOAuth2ProviderSecurityConfig'
		// have to get again after overlaying DefaultOAuthProviderSecurityConfig
		conf = SpringSecurityUtils.securityConfig
		
		if (!conf.oauthProvider.active)
			return

		println 'Configuring Spring Security OAuth2 Provider ...'
		
		clientDetailsService(InMemoryClientDetailsService)
		tokenStore(InMemoryTokenStore)
		tokenServices(RandomValueTokenServices) {
			tokenStore = ref("tokenStore")
			accessTokenValiditySeconds = conf.oauthProvider.tokenServices.accessTokenValiditySeconds
			refreshTokenValiditySeconds = conf.oauthProvider.tokenServices.refreshTokenValiditySeconds
			reuseRefreshToken = conf.oauthProvider.tokenServices.reuseRefreshToken
			supportRefreshToken = conf.oauthProvider.tokenServices.supportRefreshToken
		}
		authorizationCodeServices(InMemoryAuthorizationCodeServices)
		
		// Oauth namespace
		xmlns oauth:"http://www.springframework.org/schema/security/oauth2"
		
		oauth.'authorization-server'(
				'client-details-service-ref':"clientDetailsService",
				'token-services-ref':"tokenServices",
				'authorization-endpoint-url':conf.oauthProvider.authorizationEndpointUrl,
				'token-endpoint-url':conf.oauthProvider.tokenEndpointUrl) {
			
			oauth.'authorization-code'(
				'services-ref':"authorizationCodeServices",
				'disabled':!conf.oauthProvider.grantTypes.authorizationCode,
				'user-approval-page':conf.oauthProvider.userApprovalEndpointUrl,
				'approval-parameter-name':conf.oauthProvider.authorizationCode.approvalParameterName)
			
			oauth.'implicit'(
				'disabled':!conf.oauthProvider.grantTypes.implicit
			)
			oauth.'refresh-token'(
				'disabled':!conf.oauthProvider.grantTypes.refreshToken
			)
			oauth.'client-credentials'(
				'disabled':!conf.oauthProvider.grantTypes.clientCredentials
			)
			oauth.'password'(
				'authentication-manager-ref':'authenticationManager',
				'disabled':!conf.oauthProvider.grantTypes.password
			)
		}
			
		// Register endpoint URL filter since we define the URLs above
		SpringSecurityUtils.registerFilter 'oauth2EndpointUrlFilter',
				conf.oauthProvider.filterStartPosition + 1
				
		oauth2ExceptionHandlerFilter(OAuth2ExceptionHandlerFilter)
		SpringSecurityUtils.registerFilter 'oauth2ExceptionHandlerFilter',
				conf.oauthProvider.filterStartPosition + 2
		oauth2ProtectedResourceFilter(OAuth2ProtectedResourceFilter) {
			tokenServices = ref("tokenServices")
		}
		SpringSecurityUtils.registerFilter 'oauth2ProtectedResourceFilter',
				conf.oauthProvider.filterStartPosition + 3
		
	}
}
