package grails.plugin.springsecurity.oauthprovider

import groovy.util.logging.Slf4j
import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder
import org.springframework.security.oauth2.provider.code.RandomValueAuthorizationCodeServices
import org.springframework.transaction.annotation.Transactional

@Slf4j
@Transactional
class GormAuthorizationCodeServices extends RandomValueAuthorizationCodeServices {

    AuthorizationRequestHolderSerializer authorizationRequestHolderSerializer

    @Override
    protected void store(String code, AuthorizationRequestHolder authentication) {
        new GormOAuth2AuthorizationCode(
                code: code,
                authentication: authorizationRequestHolderSerializer.serialize(authentication)
        ).save()
    }

    @Override
    protected AuthorizationRequestHolder remove(String code) {
        AuthorizationRequestHolder authentication = null
        def gormAuthorizationCode = GormOAuth2AuthorizationCode.findByCode(code)

        try {
            def serializedAuthentication = gormAuthorizationCode?.authentication
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
}
