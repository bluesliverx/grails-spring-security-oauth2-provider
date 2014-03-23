package grails.plugin.springsecurity.oauthprovider

import grails.plugin.springsecurity.SpringSecurityUtils
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder
import org.springframework.security.oauth2.provider.code.RandomValueAuthorizationCodeServices

class GormAuthorizationCodeService extends RandomValueAuthorizationCodeServices {

    AuthorizationRequestHolderSerializer authorizationRequestHolderSerializer
    GrailsApplication grailsApplication

    @Override
    protected void store(String code, AuthorizationRequestHolder authentication) {
        def (className, codePropertyName, authenticationPropertyName) = getAuthorizationCodeConfiguration()
        def ctorArgs = [
                (codePropertyName): code,
                (authenticationPropertyName): authorizationRequestHolderSerializer.serialize(authentication)
        ]

        Class AuthorizationCode = getAuthorizationCodeClass(className)
        AuthorizationCode.newInstance(ctorArgs).save()
    }

    @Override
    protected AuthorizationRequestHolder remove(String code) {
        def (className, codePropertyName, authenticationPropertyName) = getAuthorizationCodeConfiguration()

        Class AuthorizationCode = getAuthorizationCodeClass(className)
        def gormAuthorizationCode = AuthorizationCode.findWhere((codePropertyName): code)

        AuthorizationRequestHolder authentication = null

        try {
            def serializedAuthentication = gormAuthorizationCode?."$authenticationPropertyName"
            authentication = authorizationRequestHolderSerializer.deserialize(serializedAuthentication)
        }
        catch(IllegalArgumentException e) {
            log.warn("Failed to deserialize authentication for code [$code]")
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
        def authorizationCodeClass = grailsApplication.getDomainClass(authorizationCodeClassName)
        if(!authorizationCodeClass) {
            throw new IllegalArgumentException("The specified authorization code domain class '$authorizationCodeClassName' is not a domain class")
        }
        return authorizationCodeClass.clazz
    }
}
