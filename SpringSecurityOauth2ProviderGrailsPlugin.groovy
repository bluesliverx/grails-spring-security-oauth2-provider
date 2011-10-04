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
import org.springframework.security.oauth.common.signature.CoreOAuthSignatureMethodFactory
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService
import org.springframework.security.oauth2.common.DefaultThrowableAnalyzer
import org.springframework.security.oauth2.provider.AccessGrantAuthenticationProvider
import org.springframework.security.oauth2.provider.BaseClientDetails
import org.springframework.security.oauth2.provider.InMemoryClientDetailsService
import org.springframework.security.oauth2.provider.OAuth2AuthorizationFilter
import org.springframework.security.oauth2.provider.OAuth2AuthorizationSuccessHandler
import org.springframework.security.oauth2.provider.OAuth2ExceptionHandlerFilter
import org.springframework.security.oauth2.provider.OAuth2ProtectedResourceFilter
import org.springframework.security.oauth2.provider.password.ClientPasswordAuthenticationProvider
import org.springframework.security.oauth2.provider.client.ClientCredentialsAuthenticationProvider
import org.springframework.security.oauth2.provider.refresh.RefreshAuthenticationProvider
import org.springframework.security.oauth2.provider.token.InMemoryOAuth2ProviderTokenServices
import org.springframework.security.oauth2.provider.verification.BasicUserApprovalFilter
import org.springframework.security.oauth2.provider.verification.DefaultClientAuthenticationCache
import org.springframework.security.oauth2.provider.verification.InMemoryVerificationCodeServices
import org.springframework.security.oauth2.provider.verification.VerificationCodeAuthenticationProvider
import org.springframework.security.oauth2.provider.verification.VerificationCodeFilter

class SpringSecurityOauth2ProviderGrailsPlugin {
	def version = "0.3-SNAPSHOT"
	String grailsVersion = '1.2.2 > *'
	
	List pluginExcludes = [
		'docs/**',
		'src/docs/**',
		'test/**',
	]

	//Map dependsOn = [springSecurityCore: '1.0 > *']
	def loadAfter = ["core", "springSecurityCore"]

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
		
		SpringSecurityUtils.registerProvider 'oauthVerificationAuthenticationProvider'
		SpringSecurityUtils.registerProvider 'oauthAccessGrantAuthenticationProvider'
		SpringSecurityUtils.registerProvider 'oauthRefreshAuthenticationProvider'
		SpringSecurityUtils.registerProvider 'oauthClientPasswordAuthenticationProvider'
		SpringSecurityUtils.registerProvider 'oauthClientCredentialsAuthenticationProvider'
		SpringSecurityUtils.registerFilter 'oauthExceptionHandlerFilter',
				SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order + 1
		SpringSecurityUtils.registerFilter 'verificationCodeFilter',
				SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order + 2
		SpringSecurityUtils.registerFilter 'oauthAuthorizationFilter',
				SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order + 3
		SpringSecurityUtils.registerFilter 'oauthProtectedResourceFilter',
				SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order + 4
		SpringSecurityUtils.registerFilter 'oauthUserApprovalFilter', 1
		
		// Providers
		oauthAccessGrantAuthenticationProvider(AccessGrantAuthenticationProvider) {
			clientDetailsService = ref('clientDetailsService')
		}
		oauthVerificationAuthenticationProvider(VerificationCodeAuthenticationProvider) {
			verificationServices = ref('oauthVerificationCodeServices')
		}
		oauthRefreshAuthenticationProvider(RefreshAuthenticationProvider)
		oauthClientPasswordAuthenticationProvider(ClientPasswordAuthenticationProvider)
		oauthClientCredentialsAuthenticationProvider(ClientCredentialsAuthenticationProvider)
		
		
		// Filters
		oauthUserApprovalFilter(BasicUserApprovalFilter) {
			approvalParameter = conf.oauthProvider.user.approvalParameter	// user_oauth_approval
			approvalParameterValue = conf.oauthProvider.user.approvalParameterValue	// true
		}
		verificationCodeFilter(VerificationCodeFilter) {
			allowSessionCreation = conf.apf.allowSessionCreation // true
			authenticationCache = ref(conf.oauthProvider.verificationCode.clientAuthenticationCache)	// oauthClientAuthenticationCache
			clientDetailsService = ref('clientDetailsService')
			continueChainBeforeSuccessfulAuthentication = conf.apf.continueChainBeforeSuccessfulAuthentication // false
			filterProcessesUrl = conf.oauthProvider.user.authUrl // /oauth/user/authorize'
			userApprovalHandler = ref('oauthUserApprovalFilter')
			verificationServices = ref('oauthVerificationCodeServices')
			unapprovedAuthenticationHandler = ref('oauthUnapprovedAuthenticationHandler')
		}
		oauthAuthorizationFilter(OAuth2AuthorizationFilter) {
			allowSessionCreation = conf.apf.allowSessionCreation // true
			authenticationManager = ref('authenticationManager')
			authenticationSuccessHandler = ref('oauthSuccessfulAuthenticationHandler')
			continueChainBeforeSuccessfulAuthentication = conf.apf.continueChainBeforeSuccessfulAuthentication // false
			filterProcessesUrl = conf.oauthProvider.client.authUrl	// /oauth/client/authorize'
		}
		oauthExceptionHandlerFilter(OAuth2ExceptionHandlerFilter)
		oauthProtectedResourceFilter(OAuth2ProtectedResourceFilter) {
			tokenServices = ref('oauthTokenServices')
		}
		
		
		// Handlers
		oauthSuccessfulAuthenticationHandler(OAuth2AuthorizationSuccessHandler) {
			tokenServices = ref('oauthTokenServices')
		}
		oauthUnapprovedAuthenticationHandler(SimpleUrlAuthenticationFailureHandler) {
			defaultFailureUrl = conf.oauthProvider.user.confirmUrl 	// /login/confirm
		}
		
		
		// Services
		clientDetailsService(InMemoryClientDetailsService)
		oauthClientAuthenticationCache(DefaultClientAuthenticationCache)
		oauthTokenServices(InMemoryOAuth2ProviderTokenServices) {
			reuseRefreshToken = conf.oauthProvider.tokenServices.reuseRefreshToken	// true
			supportRefreshToken = conf.oauthProvider.tokenServices.supportRefreshToken	// true
			tokenSecretLengthBytes = conf.oauthProvider.tokenServices.tokenSecretLengthBytes // 80
			refreshTokenValiditySeconds = conf.oauthProvider.tokenServices.refreshTokenValiditySeconds // 10 minutes
			accessTokenValiditySeconds = conf.oauthProvider.tokenServices.accessTokenValiditySeconds // 12 hours
		}
		oauthVerificationCodeServices(InMemoryVerificationCodeServices)
		
		// TODO Implement oauth2ProtectedResourceDetails bean to give permissions to resources based on annotations?
		//oauth2ProtectedResourceDetails()
	}
}
