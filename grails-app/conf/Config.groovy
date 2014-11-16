
log4j = {
    debug  'grails.plugin.springsecurity.oauthprovider',
            'grails.plugin.springsecurity',
            'org.springframework.security',
            'test.oauth2'

    error  'org.codehaus.groovy.grails.web.servlet',        // controllers
            'org.codehaus.groovy.grails.web.pages',          // GSP
            'org.codehaus.groovy.grails.web.sitemesh',       // layouts
            'org.codehaus.groovy.grails.web.mapping.filter', // URL mapping
            'org.codehaus.groovy.grails.web.mapping',        // URL mapping
            'org.codehaus.groovy.grails.commons',            // core / classloading
            'org.codehaus.groovy.grails.plugins',            // plugins
            'org.codehaus.groovy.grails.orm.hibernate',      // hibernate integration
            'org.springframework',
            'org.hibernate',
            'net.sf.ehcache.hibernate'
}

// Added by the Spring Security Core plugin:
grails.plugin.springsecurity.userLookup.userDomainClassName = 'test.oauth2.User'
grails.plugin.springsecurity.userLookup.authorityJoinClassName = 'test.oauth2.UserRole'
grails.plugin.springsecurity.authority.className = 'test.oauth2.Role'
grails.plugin.springsecurity.controllerAnnotations.staticRules = [
    '/oauth/authorize.dispatch':      ["isFullyAuthenticated() and (request.getMethod().equals('GET') or request.getMethod().equals('POST'))"],
    '/oauth/token.dispatch':          ["isFullyAuthenticated() and request.getMethod().equals('POST')"],
	'/':                              ['permitAll'],
	'/index':                         ['permitAll'],
	'/index.gsp':                     ['permitAll'],
	'/**/js/**':                      ['permitAll'],
	'/**/css/**':                     ['permitAll'],
	'/**/images/**':                  ['permitAll'],
	'/**/favicon.ico':                ['permitAll']
]

grails.plugin.springsecurity.providerNames = [
        'clientCredentialsAuthenticationProvider',
        'daoAuthenticationProvider',
        'anonymousAuthenticationProvider',
        'rememberMeAuthenticationProvider'
]

grails.plugin.springsecurity.filterChain.chainMap = [
        '/oauth/token': 'JOINED_FILTERS,-oauth2ProviderFilter,-securityContextPersistenceFilter,-logoutFilter,-rememberMeAuthenticationFilter',
        '/securedOAuth2Resources/**': 'JOINED_FILTERS,-securityContextPersistenceFilter,-logoutFilter,-rememberMeAuthenticationFilter',
        '/**': 'JOINED_FILTERS,-statelessSecurityContextPersistenceFilter,-oauth2ProviderFilter,-clientCredentialsTokenEndpointFilter'
]

// Added by the Spring Security OAuth2 Provider plugin:
grails.plugin.springsecurity.oauthProvider.clientLookup.className = 'test.oauth2.Client'
grails.plugin.springsecurity.oauthProvider.authorizationCodeLookup.className = 'test.oauth2.AuthorizationCode'
grails.plugin.springsecurity.oauthProvider.accessTokenLookup.className = 'test.oauth2.AccessToken'
grails.plugin.springsecurity.oauthProvider.refreshTokenLookup.className = 'test.oauth2.RefreshToken'
grails.plugin.springsecurity.oauthProvider.approvalLookup.className = 'test.oauth2.UserApproval'

// Documentation properties
grails.doc.license = 'Apache License 2.0'
grails.doc.title = 'Spring Security OAuth2 Plugin'

// GSP settings
grails {
    views {
        gsp {
            encoding = 'UTF-8'
            htmlcodec = 'xml' // use xml escaping instead of HTML4 escaping
            codecs {
                expression = 'html' // escapes values inside null
                scriptlet = 'none' // escapes output from scriptlets in GSPs
                taglib = 'none' // escapes output from taglibs
                staticparts = 'none' // escapes output from static template parts
            }
        }
        // escapes all not-encoded output at final stage of outputting
        filteringCodecForContentType {
            //'text/html' = 'html'
        }
    }
}