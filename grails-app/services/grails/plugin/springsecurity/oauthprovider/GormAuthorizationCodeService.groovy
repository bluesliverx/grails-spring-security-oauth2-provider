package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.SpringSecurityUtils
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.code.RandomValueAuthorizationCodeServices

class GormAuthorizationCodeService extends RandomValueAuthorizationCodeServices {

    OAuth2AuthenticationSerializer oauth2AuthenticationSerializer
    GrailsApplication grailsApplication

    @Override
    protected void store(String code, OAuth2Authentication authentication) {
        def (className, codePropertyName, authenticationPropertyName) = getAuthorizationCodeConfiguration()
        def ctorArgs = [
                (codePropertyName): code,
                (authenticationPropertyName): oauth2AuthenticationSerializer.serialize(authentication)
        ]

        Class AuthorizationCode = getAuthorizationCodeClass(className)
        AuthorizationCode.newInstance(ctorArgs).save()
    }

    @Override
    protected OAuth2Authentication remove(String code) {
        def (className, codePropertyName, authenticationPropertyName) = getAuthorizationCodeConfiguration()

        Class AuthorizationCode = getAuthorizationCodeClass(className)
        def gormAuthorizationCode = AuthorizationCode.findWhere((codePropertyName): code)

        OAuth2Authentication authentication = null

        try {
            def serializedAuthentication = gormAuthorizationCode?."$authenticationPropertyName"
            authentication = oauth2AuthenticationSerializer.deserialize(serializedAuthentication)
        }
        catch(IllegalArgumentException e) {
            log.warn("Failed to deserialize authentication for code")
            authentication = null
        }
        finally {
            gormAuthorizationCode?.delete()
        }

        return authentication
    }

    private def getAuthorizationCodeConfiguration() {
        def authorizationCodeLookup = SpringSecurityUtils.securityConfig.oauthProvider.authorizationCodeLookup

        def className = authorizationCodeLookup.className
        def codePropertyName = authorizationCodeLookup.codePropertyName
        def authenticationPropertyName = authorizationCodeLookup.authenticationPropertyName

        return [className, codePropertyName, authenticationPropertyName]
    }

    private Class getAuthorizationCodeClass(String authorizationCodeClassName) {
        def authorizationCodeClass = authorizationCodeClassName ? grailsApplication.getDomainClass(authorizationCodeClassName) : null
        if(!authorizationCodeClass) {
            throw new IllegalArgumentException("The specified authorization code domain class '$authorizationCodeClassName' is not a domain class")
        }
        return authorizationCodeClass.clazz
    }
}
