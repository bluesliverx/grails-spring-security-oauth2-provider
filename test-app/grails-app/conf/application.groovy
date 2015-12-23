// Added by the Spring Security Core plugin:
grails.plugin.springsecurity.userLookup.userDomainClassName = 'test.oauth2.User'
grails.plugin.springsecurity.userLookup.authorityJoinClassName = 'test.oauth2.UserRole'
grails.plugin.springsecurity.authority.className = 'test.oauth2.Role'

grails.plugin.springsecurity.controllerAnnotations.staticRules = [
        [pattern: '/oauth/authorize',           access: "isFullyAuthenticated() and (request.getMethod().equals('GET') or request.getMethod().equals('POST'))"],
        [pattern: '/oauth/token',               access: "isFullyAuthenticated() and request.getMethod().equals('POST')"],
        [pattern: '/',                          access: 'permitAll'],
        [pattern: '/index',                     access: 'permitAll'],
        [pattern: '/index.gsp',                 access: 'permitAll'],
        [pattern: '/**/js/**',                  access: 'permitAll'],
        [pattern: '/**/css/**',                 access: 'permitAll'],
        [pattern: '/**/images/**',              access: 'permitAll'],
        [pattern: '/**/favicon.ico',            access: 'permitAll'],
        [pattern: '/assets/**',                 access: 'permitAll']
]

grails.plugin.springsecurity.filterChain.chainMap = [
        [pattern: '/oauth/token',               filters: 'JOINED_FILTERS,-oauth2ProviderFilter,-securityContextPersistenceFilter,-logoutFilter,-authenticationProcessingFilter,-rememberMeAuthenticationFilter,-exceptionTranslationFilter'],
        [pattern: '/securedOAuth2Resources/**', filters: 'JOINED_FILTERS,-securityContextPersistenceFilter,-logoutFilter,-authenticationProcessingFilter,-rememberMeAuthenticationFilter,-oauth2BasicAuthenticationFilter,-exceptionTranslationFilter'],
        [pattern: '/**',                        filters: 'JOINED_FILTERS,-statelessSecurityContextPersistenceFilter,-oauth2ProviderFilter,-clientCredentialsTokenEndpointFilter,-oauth2BasicAuthenticationFilter,-oauth2ExceptionTranslationFilter']
]

// Added by the Spring Security OAuth2 Provider plugin:
grails.plugin.springsecurity.oauthProvider.clientLookup.className = 'test.oauth2.Client'
grails.plugin.springsecurity.oauthProvider.authorizationCodeLookup.className = 'test.oauth2.AuthorizationCode'
grails.plugin.springsecurity.oauthProvider.accessTokenLookup.className = 'test.oauth2.AccessToken'
grails.plugin.springsecurity.oauthProvider.refreshTokenLookup.className = 'test.oauth2.RefreshToken'
grails.plugin.springsecurity.oauthProvider.approvalLookup.className = 'test.oauth2.UserApproval'
