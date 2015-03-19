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


import grails.plugin.springsecurity.SecurityFilterPosition
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.oauthprovider.DefaultOAuth2AuthenticationSerializer
import grails.plugin.springsecurity.oauthprovider.UserApprovalSupport
import grails.plugin.springsecurity.oauthprovider.endpoint.RequiredRedirectResolver
import grails.plugin.springsecurity.oauthprovider.endpoint.WrappedAuthorizationEndpoint
import grails.plugin.springsecurity.oauthprovider.endpoint.WrappedTokenEndpoint
import grails.plugin.springsecurity.oauthprovider.provider.GrailsOAuth2RequestFactory
import grails.plugin.springsecurity.oauthprovider.provider.GrailsOAuth2RequestValidator
import grails.plugin.springsecurity.oauthprovider.servlet.OAuth2AuthorizationEndpointExceptionResolver
import grails.plugin.springsecurity.oauthprovider.servlet.OAuth2TokenEndpointExceptionResolver
import grails.plugin.springsecurity.oauthprovider.filter.StatelessSecurityContextPersistenceFilter
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.converter.ByteArrayHttpMessageConverter
import org.springframework.http.converter.FormHttpMessageConverter
import org.springframework.http.converter.StringHttpMessageConverter
import org.springframework.http.converter.json.MappingJacksonHttpMessageConverter
import org.springframework.http.converter.xml.SourceHttpMessageConverter
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.oauth2.provider.CompositeTokenGranter
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler
import org.springframework.security.oauth2.provider.approval.DefaultUserApprovalHandler
import org.springframework.security.oauth2.provider.approval.TokenStoreUserApprovalHandler
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter
import org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpointHandlerMapping
import org.springframework.security.oauth2.provider.error.DefaultOAuth2ExceptionRenderer
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator
import org.springframework.security.oauth2.provider.token.DefaultTokenServices
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint
import org.springframework.security.web.savedrequest.NullRequestCache
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter

import static grails.plugin.springsecurity.oauthprovider.UserApprovalSupport.*

class SpringSecurityOauth2ProviderGrailsPlugin {
	static final Logger log = LoggerFactory.getLogger(this)

	def version = "2.0-RC3"
	def grailsVersion = '2.3 > *'

	List pluginExcludes = [
		'docs/**',
		'src/docs/**',
		'examples/**',
		'test/**',
		'grails-app/controllers/test/**',
		'grails-app/domain/**',
		'grails-app/i18n/**',
		'web-app/**',
		'grails-app/views/login/**',
        'grails-app/views/logout/**',
		'grails-app/views/securedOAuth2Resources/**',
        'grails-app/views/redirect/**',
		'grails-app/views/index.gsp',
		'grails-app/views/error.gsp',
        'scripts/CreateOauth2TestApps.groovy',
        'scripts/PublishGithub.groovy',
	]

	def loadAfter = ["springSecurityCore"]

	def license = "APACHE"
	def organization = [ name:"Adaptive Computing", url:"http://adaptivecomputing.com" ]
	def issueManagement = [ system:"GitHub", url:"http://github.com/adaptivecomputing/grails-spring-security-oauth2-provider/issues" ]
	def scm = [ url:"http://github.com/adaptivecomputing/grails-spring-security-oauth2-provider" ]

	def developers = [
			[ name: "Brian Saville", email: "bksaville@gmail.com" ],
			[ name: "Bobby Vandiver", email: "bobby.vandiver88@gmail.com" ],
			[ name: "Roy Willemse", email: "roy.willemse@dynamind.nl" ]
	]
	def title = 'OAuth2 Provider support for the Spring Security plugin.'
	def description = 'OAuth2 Provider support for the Spring Security plugin.'

	def documentation = 'http://adaptivecomputing.github.io/grails-spring-security-oauth2-provider/'

    private List availableMessageConverters = [
            new StringHttpMessageConverter(writeAcceptCharset: false),
            new ByteArrayHttpMessageConverter(),
            new FormHttpMessageConverter(),
            new SourceHttpMessageConverter(),
            new MappingJacksonHttpMessageConverter()
    ]

    def doWithSpring = {
        def conf = loadSecurityConfig()
        if(!conf) {
            return
        }

		println 'Configuring Spring Security OAuth2 provider ...'

        // Required for list constructor arguments for versions < 2.2-RC1
        // GRAILS-4995: https://jira.grails.org/browse/GRAILS-4995
        xmlns util:"http://www.springframework.org/schema/util"

        /* Enable GORM backed implementations */
        configureGormSupport.delegate = delegate
        configureGormSupport()

        /* Establish baseline token support */
        configureTokenServices.delegate = delegate
        configureTokenServices(conf)

        /* Register OAuth2 request creation and validation support */
        configureOAuth2RequestSupport.delegate = delegate
        configureOAuth2RequestSupport(conf)

        /* Register token granters */
        configureTokenGranters.delegate = delegate
        configureTokenGranters(conf)

        /* Register redirect resolver */
        configureRedirectResolver.delegate = delegate
        configureRedirectResolver(conf)

        /* Register user approval handler to allow explicit approval or auto-approval */
        configureUserApprovalHandler.delegate = delegate
        configureUserApprovalHandler(conf)

        /* Register authorization and token endpoints */
        configureEndpoints.delegate = delegate
        configureEndpoints(conf)

        /* Register exception resolvers for integration with the endpoints' @ExceptionHandler methods */
        configureExceptionResolvers.delegate = delegate
        configureExceptionResolvers()

        /* Register details service, authentication provider and filter for client authentication */
        configureClientAuthentication.delegate = delegate
        configureClientAuthentication(conf)

        /* Ensure OAuth2 authentication entry point plays well with the one provided by the Core plugin */
        configureAuthenticationEntryPoints.delegate = delegate
        configureAuthenticationEntryPoints(conf)

        /* Ensure access tokens are extracted from incoming requests for access to protected resources */
        configureResourceProtection.delegate = delegate
        configureResourceProtection(conf)

        /* Access to OAuth2 resources and the token endpoint must be stateless */
        configureStatelessFilters.delegate = delegate
        configureStatelessFilters(conf)

		println "... done configuring Spring Security OAuth2 provider"
	}

    private configureGormSupport = {
        /* Gorm backed beans */
        springConfig.addAlias 'clientDetailsService', 'gormClientDetailsService'
        springConfig.addAlias 'tokenStore', 'gormTokenStoreService'
        springConfig.addAlias 'authorizationCodeServices', 'gormAuthorizationCodeService'
        springConfig.addAlias 'approvalStore', 'gormApprovalStoreService'

        /* Helper classes for Gorm support */
        oauth2AuthenticationSerializer(DefaultOAuth2AuthenticationSerializer)
        authenticationKeyGenerator(DefaultAuthenticationKeyGenerator)
    }

    private configureTokenServices = { conf ->
        tokenServices(DefaultTokenServices) {
            tokenStore = ref("tokenStore")
            clientDetailsService = ref("clientDetailsService")
            accessTokenValiditySeconds = conf.oauthProvider.tokenServices.accessTokenValiditySeconds
            refreshTokenValiditySeconds = conf.oauthProvider.tokenServices.refreshTokenValiditySeconds
            reuseRefreshToken = conf.oauthProvider.tokenServices.reuseRefreshToken
            supportRefreshToken = conf.oauthProvider.tokenServices.supportRefreshToken
        }
    }

    private configureOAuth2RequestSupport = { conf ->
        /* Should every request be required to include the scope of the access token */
        boolean requireScope = conf.oauthProvider.authorization.requireScope as boolean
        oauth2RequestFactory(GrailsOAuth2RequestFactory, ref('clientDetailsService'), requireScope)

        oauth2RequestValidator(GrailsOAuth2RequestValidator)
    }

    private configureTokenGranters = { conf ->
        def grantTypes = conf.oauthProvider.grantTypes

        /* Must enforce restrictions on which grants, e.g. implicit, are available to each each endpoint */
        def authorizationEndpointTokenGrantersBeanNames = []
        def tokenEndpointTokenGrantersBeanNames = []

        /* authorization-code */
        if(grantTypes.authorizationCode) {
            authorizationCodeTokenGranter(AuthorizationCodeTokenGranter,
                    ref('tokenServices'), ref('authorizationCodeServices'), ref('clientDetailsService'), ref('oauth2RequestFactory'))

            authorizationEndpointTokenGrantersBeanNames << 'authorizationCodeTokenGranter'
            tokenEndpointTokenGrantersBeanNames << 'authorizationCodeTokenGranter'
        }

        /* refresh-token */
        if(grantTypes.refreshToken) {
            refreshTokenGranter(RefreshTokenGranter, ref('tokenServices'), ref('clientDetailsService'), ref('oauth2RequestFactory'))
            tokenEndpointTokenGrantersBeanNames << 'refreshTokenGranter'
        }

        /* implicit */
        if(grantTypes.implicit) {
            implicitGranter(ImplicitTokenGranter, ref('tokenServices'), ref('clientDetailsService'), ref('oauth2RequestFactory'))
            authorizationEndpointTokenGrantersBeanNames << 'implicitGranter'
        }

        /* client-credentials */
        if(grantTypes.clientCredentials) {
            clientCredentialsGranter(ClientCredentialsTokenGranter,
                    ref('tokenServices'), ref('clientDetailsService'), ref('oauth2RequestFactory'))

            tokenEndpointTokenGrantersBeanNames << 'clientCredentialsGranter'
        }

        /* password; authenticationManager provided by Spring Security Core plugin */
        if(grantTypes.password) {
            resourceOwnerPasswordGranter(ResourceOwnerPasswordTokenGranter,
                    ref('authenticationManager'), ref('tokenServices'), ref('clientDetailsService'), ref('oauth2RequestFactory'))

            tokenEndpointTokenGrantersBeanNames << 'resourceOwnerPasswordGranter'
        }

        util.list(id: 'authorizationEndpointTokenGranters') {
            authorizationEndpointTokenGrantersBeanNames.each {
                ref(bean: it)
            }
        }

        util.list(id: 'tokenEndpointTokenGranters') {
            tokenEndpointTokenGrantersBeanNames.each {
                ref(bean: it)
            }
        }

        oauth2AuthorizationEndpointTokenGranter(CompositeTokenGranter, ref('authorizationEndpointTokenGranters'))
        oauth2TokenEndpointTokenGranter(CompositeTokenGranter, ref('tokenEndpointTokenGranters'))
    }

    private configureRedirectResolver = { conf ->
        if(conf.oauthProvider.authorization.requireRegisteredRedirectUri) {
            /* Require clients to have registered redirect URIs */
            redirectResolver(RequiredRedirectResolver)
        }
        else {
            /* This resolver will use the requested redirect URI if client does not have one registered */
            redirectResolver(DefaultRedirectResolver)
        }
    }

    private configureExceptionResolvers = {
        oauth2ExceptionRenderer(DefaultOAuth2ExceptionRenderer) {
            messageConverters = availableMessageConverters
        }

        oauth2TokenEndpointExceptionResolver(OAuth2TokenEndpointExceptionResolver) {
            order = 0
            tokenEndpoint = ref('oauth2TokenEndpoint')
            exceptionRenderer = ref('oauth2ExceptionRenderer')
        }

        oauth2AuthorizationEndpointExceptionResolver(OAuth2AuthorizationEndpointExceptionResolver) {
            order = 0
            authorizationEndpoint = ref('oauth2AuthorizationEndpoint')
        }
    }

    private configureUserApprovalHandler = { conf ->
        /* The request parameter sent from the userApprovalPage, indicating approval was given or denied */
        String approvalParameterName = conf.oauthProvider.userApprovalParameter

        /* Explicit approval required every time */
        defaultUserApprovalHandler(DefaultUserApprovalHandler) {
            approvalParameter = approvalParameterName
        }

        /* Approval based on existing access tokens */
        tokenStoreUserApprovalHandler(TokenStoreUserApprovalHandler) {
            tokenStore = ref('tokenStore')
            clientDetailsService = ref('clientDetailsService')
            approvalParameter = approvalParameterName
            requestFactory = ref('oauth2RequestFactory')
        }

        /* Approval based on remembered approvals */
        approvalStoreUserApprovalHandler(ApprovalStoreUserApprovalHandler) {
            clientDetailsService = ref('clientDetailsService')
            approvalStore = ref('approvalStore')
            requestFactory = ref('oauth2RequestFactory')
            approvalExpiryInSeconds = conf.oauthProvider.approval.approvalValiditySeconds
            scopePrefix = conf.oauthProvider.approval.scopePrefix
        }

        /* The method of authorization auto approval to use */
        UserApprovalSupport support = conf.oauthProvider.approval.auto

        if(support == EXPLICIT) {
            springConfig.addAlias 'userApprovalHandler', 'defaultUserApprovalHandler'
        }
        else if(support == TOKEN_STORE) {
            springConfig.addAlias 'userApprovalHandler', 'tokenStoreUserApprovalHandler'
        }
        else if(support == APPROVAL_STORE) {
            springConfig.addAlias 'userApprovalHandler', 'approvalStoreUserApprovalHandler'
        }
    }

    private configureEndpoints = { conf ->
        /* Register authorization endpoint */
        oauth2AuthorizationEndpoint(WrappedAuthorizationEndpoint) {
            tokenGranter = ref('oauth2AuthorizationEndpointTokenGranter')
            authorizationCodeServices = ref('authorizationCodeServices')
            clientDetailsService = ref('clientDetailsService')
            redirectResolver = ref('redirectResolver')
            userApprovalHandler = ref('userApprovalHandler')
            OAuth2RequestFactory = ref('oauth2RequestFactory')
            OAuth2RequestValidator = ref('oauth2RequestValidator')

            // The URL where the user approves the grant
            userApprovalPage = conf.oauthProvider.userApprovalEndpointUrl

            // The URL the user is directed to in case of an error
            errorPage = conf.oauthProvider.errorEndpointUrl
        }

        /* Register token endpoint */
        oauth2TokenEndpoint(WrappedTokenEndpoint) {
            clientDetailsService = ref('clientDetailsService')
            tokenGranter = ref('oauth2TokenEndpointTokenGranter')
            OAuth2RequestFactory = ref('oauth2RequestFactory')
            OAuth2RequestValidator = ref('oauth2RequestValidator')
        }

        /* Register handler mapping for token and authorization endpoints */
        oauth2HandlerMapping(FrameworkEndpointHandlerMapping) {
            mappings = [
                    "/oauth/token": conf.oauthProvider.tokenEndpointUrl,
                    "/oauth/authorize": conf.oauthProvider.authorizationEndpointUrl
            ]
        }

        /* Register jackson handler for token responses */
        annotationHandlerAdapter(RequestMappingHandlerAdapter){
            messageConverters = availableMessageConverters
        }
    }

    private configureAuthenticationEntryPoints = { conf ->
        // Configure multiple authentication entry points
        // http://jdevdiary.blogspot.com/2013/03/grails-spring-security-and-multiple.html
        oauth2RequestMatcher(AntPathRequestMatcher, conf.oauthProvider.tokenEndpointUrl + '**')
        oauth2AuthenticationEntryPoint(OAuth2AuthenticationEntryPoint) {
            realmName = conf.oauthProvider.realmName
        }

        util.map(id: 'authenticationEntryPointMap') {
            entry('key-ref': 'oauth2RequestMatcher') {
                ref(bean: 'oauth2AuthenticationEntryPoint')
            }
        }

        // Retrieve the bean definition defined by the Core plugin
        def defaultAuthenticationEntryPoint = getBeanDefinition('authenticationEntryPoint')

        authenticationEntryPoint(DelegatingAuthenticationEntryPoint, ref('authenticationEntryPointMap')) {
            defaultEntryPoint = defaultAuthenticationEntryPoint
        }
    }

    private configureClientAuthentication = { conf ->
        /* Allow client log-ins */
        clientDetailsUserService(ClientDetailsUserDetailsService, ref('clientDetailsService'))

        /* Use the password encoder configured for the core plugin for encoding client secrets */
        clientCredentialsAuthenticationProvider(DaoAuthenticationProvider) {
            userDetailsService = ref('clientDetailsUserService')
            passwordEncoder = ref('passwordEncoder')
            saltSource = ref('saltSource')
        }

        clientCredentialsTokenEndpointFilter(ClientCredentialsTokenEndpointFilter, conf.oauthProvider.tokenEndpointUrl) {
            authenticationManager = ref('authenticationManager')
            authenticationEntryPoint = ref('oauth2AuthenticationEntryPoint')
        }

        SpringSecurityUtils.registerFilter 'clientCredentialsTokenEndpointFilter',
                conf.oauthProvider.clientFilterStartPosition + 1
    }

    private configureResourceProtection = { conf ->

        // Override expression handler provided by Spring Security core plugin
        webExpressionHandler(OAuth2WebSecurityExpressionHandler) {
            roleHierarchy = ref('roleHierarchy')
            expressionParser = ref('voterExpressionParser')
            permissionEvaluator = ref('permissionEvaluator')
        }

        oauth2AuthenticationManager(OAuth2AuthenticationManager) {
            tokenServices = ref('tokenServices')
        }

        oauth2ProviderFilter(OAuth2AuthenticationProcessingFilter) {
            authenticationEntryPoint = ref('oauth2AuthenticationEntryPoint')
            authenticationManager = ref('oauth2AuthenticationManager')
        }

        SpringSecurityUtils.registerFilter 'oauth2ProviderFilter',
                conf.oauthProvider.filterStartPosition + 1
    }

    private configureStatelessFilters = { conf ->
        statelessSecurityContextPersistenceFilter(StatelessSecurityContextPersistenceFilter)

        // Should the stateless filter be registered in the filter chain
        boolean registerStatelessFilter = conf.oauthProvider.registerStatelessFilter as boolean

        if(registerStatelessFilter) {
            // We add the stateless filter to the chain by default and require the plugin consumer to remove
            // either the session based or stateless security context filter from the filter chain where appropriate
            SpringSecurityUtils.registerFilter 'statelessSecurityContextPersistenceFilter',
                    conf.oauthProvider.statelessFilterStartPosition + 1
        }

        oauth2RequestCache(NullRequestCache)

        oauth2ExceptionTranslationFilter(ExceptionTranslationFilter, ref('authenticationEntryPoint'), ref('oauth2RequestCache')) {
            accessDeniedHandler = ref('accessDeniedHandler')
            authenticationTrustResolver = ref('authenticationTrustResolver')
            throwableAnalyzer = ref('throwableAnalyzer')
        }

        // Should the custom exception translation filter be registered in the filter chain
        boolean registerExceptionTranslationFilter = conf.oauthProvider.registerExceptionTranslationFilter as boolean

        if(registerExceptionTranslationFilter) {
            // Similar to the stateless security context filter, this is registered in the filter chain,
            // allowing the plugin consumer to remove this filter or the Core plugin provided exceptionTranslationFilter
            // where necessary to meet their needs
            SpringSecurityUtils.registerFilter 'oauth2ExceptionTranslationFilter',
                    conf.oauthProvider.exceptionTranslationFilterStartPosition + 1
        }
    }

    def onConfigChange = { event ->
        loadSecurityConfig()
    }

    def doWithApplicationContext = { ctx ->
        def conf = loadSecurityConfig()
        if(!conf) {
            return
        }

        ctx.with {
            boolean handleRevocationAsExpiry = conf.oauthProvider.approval.handleRevocationAsExpiry as boolean
            gormApprovalStoreService.handleRevocationAsExpiry = handleRevocationAsExpiry
        }
    }

    private static ConfigObject loadSecurityConfig() {
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.active) {
            return null
        }

        SpringSecurityUtils.loadSecondaryConfig 'DefaultOAuth2ProviderSecurityConfig'
        conf = SpringSecurityUtils.securityConfig

        if (!conf.oauthProvider.active) {
            return null
        }
        return conf
    }
}
