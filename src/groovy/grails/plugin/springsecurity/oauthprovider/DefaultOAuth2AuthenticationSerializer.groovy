package grails.plugin.springsecurity.oauthprovider

import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.common.util.SerializationUtils

class DefaultOAuth2AuthenticationSerializer implements OAuth2AuthenticationSerializer {

    Object serialize(OAuth2Authentication authentication) {
        return SerializationUtils.serialize(authentication)
    }

    OAuth2Authentication deserialize(Object authentication) {
        if (authentication == null) {
            return null
        }
        new ByteArrayInputStream(authentication).withObjectInputStream(getClass().classLoader) { ois ->
            return ois.readObject() as OAuth2Authentication
        }
    }
}
