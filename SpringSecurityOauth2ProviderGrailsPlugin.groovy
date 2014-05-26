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
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.oauthprovider.AuthorizationRequestHolderSerializer
import grails.plugin.springsecurity.oauthprovider.OAuth2AuthenticationSerializer
import grails.plugin.springsecurity.oauthprovider.endpoint.RequiredRedirectResolver
import grails.plugin.springsecurity.oauthprovider.endpoint.WrappedAuthorizationEndpoint
import grails.plugin.springsecurity.oauthprovider.endpoint.WrappedTokenEndpoint
import grails.plugin.springsecurity.oauthprovider.provider.GrailsAuthorizationRequestManager
import grails.plugin.springsecurity.oauthprovider.servlet.OAuth2AuthorizationEndpointExceptionResolver
import grails.plugin.springsecurity.oauthprovider.servlet.OAuth2TokenEndpointExceptionResolver
import grails.plugin.springsecurity.oauthprovider.token.StrictTokenGranter
import grails.plugin.springsecurity.web.authentication.AjaxAwareAuthenticationEntryPoint
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.context.ApplicationContext
import org.springframework.http.converter.ByteArrayHttpMessageConverter
import org.springframework.http.converter.FormHttpMessageConverter
import org.springframework.http.converter.StringHttpMessageConverter
import org.springframework.http.converter.json.MappingJacksonHttpMessageConverter
import org.springframework.http.converter.xml.SourceHttpMessageConverter
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.oauth2.provider.CompositeTokenGranter
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequestManager
import org.springframework.security.oauth2.provider.approval.TokenServicesUserApprovalHandler
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
import org.springframework.security.oauth2.provider.token.DefaultTokenServices
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint
import org.springframework.security.web.context.NullSecurityContextRepository
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.util.AntPathRequestMatcher
import org.springframework.security.web.util.RequestMatcher
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter

import javax.servlet.Filter

class SpringSecurityOauth2ProviderGrailsPlugin {
	static final Logger log = LoggerFactory.getLogger(this)

	def version = "1.0.5-SNAPSHOT"
	String grailsVersion = '2.0 > *'

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
		'grails-app/views/secured/**',
        'grails-app/views/redirect/**',
		'grails-app/views/index.gsp',
		'grails-app/views/error.gsp',
        'scripts/CreateOauth2TestApps.groovy'
	]

	def loadAfter = ["springSecurityCore"]

	def license = "APACHE"
	def organization = [ name:"Adaptive Computing", url:"http://adaptivecomputing.com" ]
	def issueManagement = [ system:"GitHub", url:"http://github.com/adaptivecomputing/grails-spring-security-oauth2-provider/issues" ]
	def scm = [ url:"http://github.com/adaptivecomputing/grails-spring-security-oauth2-provider" ]

	String author = 'Brian Saville'
	String authorEmail = 'bsaville@adaptivecomputing.com'
	String title = 'OAuth2 Provider support for the Spring Security plugin.'
	String description = '''\
OAuth2 Provider support for the Spring Security plugin.
'''

	String documentation = 'http://grails.org/plugin/spring-security-oauth2-provider'

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

        /* Register token granters */
        configureTokenGranters.delegate = delegate
        configureTokenGranters(conf)

        /* Register redirect resolver */
        configureRedirectResolver.delegate = delegate
        configureRedirectResolver(conf)

        /* Register authorization request manager */
        configureAuthorizationRequestManager.delegate = delegate
        configureAuthorizationRequestManager(conf)

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

        /* Prepare for token endpoint filter chain voodoo */
        configureTokenEndpointFilterChain.delegate = delegate
        configureTokenEndpointFilterChain()

		println "... done configuring Spring Security OAuth2 provider"
	}

    private configureGormSupport = {
        /* Gorm backed beans */
        springConfig.addAlias 'clientDetailsService', 'gormClientDetailsService'
        springConfig.addAlias 'tokenStore', 'gormTokenStoreService'
        springConfig.addAlias 'authorizationCodeServices', 'gormAuthorizationCodeService'

        /* Helper classes for Gorm support */
        oauth2AuthenticationSerializer(OAuth2AuthenticationSerializer)
        authorizationRequestHolderSerializer(AuthorizationRequestHolderSerializer)
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

    private configureTokenGranters = { conf ->
        def grantTypes = conf.oauthProvider.grantTypes

        /* Must enforce restrictions on which grants, e.g. implicit, are available to each each endpoint */
        def authorizationEndpointTokenGrantersBeanNames = []
        def tokenEndpointTokenGrantersBeanNames = []

        /* authorization-code */
        if(grantTypes.authorizationCode) {
            authorizationCodeTokenGranter(AuthorizationCodeTokenGranter,
                    ref('tokenServices'), ref('authorizationCodeServices'), ref('clientDetailsService'))

            authorizationEndpointTokenGrantersBeanNames << 'authorizationCodeTokenGranter'
            tokenEndpointTokenGrantersBeanNames << 'authorizationCodeTokenGranter'
        }

        /* refresh-token */
        if(grantTypes.refreshToken) {
            refreshTokenGranter(RefreshTokenGranter, ref('tokenServices'), ref('clientDetailsService'))
            tokenEndpointTokenGrantersBeanNames << 'refreshTokenGranter'
        }

        /* implicit */
        if(grantTypes.implicit) {
            implicitGranter(ImplicitTokenGranter, ref('tokenServices'), ref('clientDetailsService'))
            authorizationEndpointTokenGrantersBeanNames << 'implicitGranter'
        }

        /* client-credentials */
        if(grantTypes.clientCredentials) {
            clientCredentialsGranter(ClientCredentialsTokenGranter,
                    ref('tokenServices'), ref('clientDetailsService'))

            tokenEndpointTokenGrantersBeanNames << 'clientCredentialsGranter'
        }

        /* password */
        if(grantTypes.password) {
            resourceOwnerPasswordGranter(ResourceOwnerPasswordTokenGranter,
                    ref('authenticationManager'), ref('tokenServices'), ref('clientDetailsService'))

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

    private configureAuthorizationRequestManager = { conf ->
        /* Should every request be required to include the scope of the access token */
        boolean requireScope = conf.oauthProvider.authorization.requireScope as boolean
        authorizationRequestManager(GrailsAuthorizationRequestManager, ref('clientDetailsService'), requireScope)
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

    private configureEndpoints = { conf ->

        userApprovalHandler(TokenServicesUserApprovalHandler) {
            approvalParameter = conf.oauthProvider.userApprovalParameter
            tokenServices = ref("tokenServices")
        }

        /* Register authorization endpoint */
        oauth2AuthorizationEndpoint(WrappedAuthorizationEndpoint) {
            tokenGranter = ref('oauth2AuthorizationEndpointTokenGranter')
            authorizationRequestManager = ref('authorizationRequestManager')
            authorizationCodeServices = ref('authorizationCodeServices')
            clientDetailsService = ref('clientDetailsService')
            redirectResolver = ref('redirectResolver')
            userApprovalHandler = ref('userApprovalHandler')
            userApprovalPage = conf.oauthProvider.userApprovalEndpointUrl
            errorPage = conf.oauthProvider.errorEndpointUrl
        }

        /* Register token endpoint */
        oauth2TokenEndpoint(WrappedTokenEndpoint) {
            clientDetailsService = ref('clientDetailsService')
            tokenGranter = ref('oauth2TokenEndpointTokenGranter')
            authorizationRequestManager = ref('authorizationRequestManager')
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
        oauth2AuthenticationEntryPoint(OAuth2AuthenticationEntryPoint)

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

    private configureTokenEndpointFilterChain = {
        // Register the token endpoint as stateless
        // This is added to the filter chain
        nullContextRepository(NullSecurityContextRepository)
        statelessSecurityContextPersistenceFilter(SecurityContextPersistenceFilter, ref('nullContextRepository'))
    }

    def doWithApplicationContext = { ctx ->
        def conf = loadSecurityConfig()
        if(!conf) {
            return
        }

        if(conf.oauthProvider.tokenEndpointFilterChain.disabled) {
            log.debug("Skipping token endpoint filter chain configuration")
            return
        }

        setupTokenEndpointFilterChain.delegate = delegate
        setupTokenEndpointFilterChain(conf, ctx)
    }

    private setupTokenEndpointFilterChain = { conf, ctx ->
        def springSecurityFilterChain = ctx.springSecurityFilterChain
        def originalFilterChainMap = springSecurityFilterChain.filterChainMap

        def tokenEndpointUrl =  conf.oauthProvider.tokenEndpointUrl
        def statelessUrlPattern = conf.oauthProvider.tokenEndpointFilterChain.baseUrlPattern

        // Inherit the filter chain specified by another end point
        def allFilters = findFilterChainForUrl(statelessUrlPattern, originalFilterChainMap).value as List
        if(allFilters == null) {
            log.error("Could not find base filter chain for pattern [${statelessUrlPattern}] to use for token endpoint [${tokenEndpointUrl}]")
            return
        }

        // Locate the securityContextPersistenceFilter bean to replace
        def scpfIdx = allFilters.findIndexOf { it instanceof SecurityContextPersistenceFilter }
        def scpfBean = ctx.getBean('securityContextPersistenceFilter')

        // Skip if the securityContextPersistenceFilter is not present
        def filterPresent = (scpfIdx != -1) && allFilters[scpfIdx].is(scpfBean)
        if(!filterPresent) {
            log.error("Could not find securityContextPersistenceFilter in filter chain associated with [${statelessUrlPattern}]")
            return
        }

        // Replace default securityContextPersistenceFilter bean with one that is stateless
        def tokenEndpointFilters = replaceSecurityContextPersistenceFilterWithStateless(allFilters, scpfIdx, ctx)

        // Rebuild the filterChainMap with the the token endpoint filter at the beginning
        def filterChainMap = injectFilterChain(tokenEndpointUrl, tokenEndpointFilters, originalFilterChainMap)
        springSecurityFilterChain.filterChainMap = filterChainMap
    }

    private Map injectFilterChain(String url, List filters, Map oldFilterChainMap) {
        Map<RequestMatcher, List<Filter>> filterChainMap = [:]
        filterChainMap[new AntPathRequestMatcher(url)] = filters
        filterChainMap << oldFilterChainMap
        return filterChainMap
    }

    private List replaceSecurityContextPersistenceFilterWithStateless(List allFilters, int scpfIdx, ApplicationContext ctx) {
        def tokenEndpointFilters = []
        allFilters.eachWithIndex { filter, idx ->
            if (idx == scpfIdx) {
                def statelessFilter = ctx.getBean('statelessSecurityContextPersistenceFilter')
                tokenEndpointFilters << statelessFilter
            } else {
                tokenEndpointFilters << filter
            }

        }
        return tokenEndpointFilters
    }

    private def findFilterChainForUrl(String url, Map filterChainMap) {
        filterChainMap.find { AntPathRequestMatcher urlPattern, filters ->
            urlPattern.pattern == url
        }
    }

    def onConfigChange = { event ->
        loadSecurityConfig()
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
